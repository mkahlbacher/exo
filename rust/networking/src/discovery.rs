use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use bytemuck::{Pod, Zeroable};
use log::{debug, trace, warn};
use netwatcher::WatchHandle;
use parking_lot::Mutex;
use socket2::SockRef;
use tokio::{
    net::UdpSocket,
    time::{Interval, interval},
};
use zenoh::config::ZenohId;

// IPv4 "Local Scope" administratively-scoped multicast address (RFC 2365, 239.255.0.0/16).
// Chosen so exo doesn't collide with well-known multicast users (SSDP, mDNS, etc).
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 222, 137);
const MAGIC: [u8; 3] = *b"EXO";

pub struct Discovery {
    sock: Arc<UdpSocket>,
    /// interface index -> local ipv4 address(es) on that interface we've joined the
    /// multicast group with. Also used to pick the outgoing interface (IP_MULTICAST_IF)
    /// when announcing, since (unlike ipv6) an ipv4 destination address carries no scope.
    ifaces: Arc<Mutex<HashMap<u32, Vec<Ipv4Addr>>>>,
    namespace: [u8; 8],
    last_nonce: Mutex<[u8; 8]>,
    /// the port of the service we are doing discovery for - transmitted to peers
    listen_port: u16,
    zid: ZenohId,
    /// fixed multicast destination (GROUP:discovery_port) we announce to
    dest: SocketAddrV4,
    tick: Interval,
    _sync: Mutex<WatchHandle>,
}

#[derive(Debug, Clone, Copy)]
pub struct Discovered {
    pub zid: ZenohId,
    pub addr: SocketAddrV4,
}

impl Discovery {
    pub async fn new(
        zid: ZenohId,
        namespace: [u8; 8],
        listen_port: u16,
        discovery_port: u16,
    ) -> io::Result<Self> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        sock.set_reuse_address(true)?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
        sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, discovery_port).into())?;
        sock.set_nonblocking(true)?;
        sock.set_multicast_loop_v4(true)?;
        let sock = Arc::new(UdpSocket::from_std(sock.into())?);
        let ifaces: Arc<Mutex<HashMap<u32, Vec<Ipv4Addr>>>> = Default::default();
        let _sync = Mutex::new(
            netwatcher::watch_interfaces_with_callback({
                let sock = sock.clone();
                let ifaces = ifaces.clone();
                move |update| {
                    for (iface_idx, iface) in update.interfaces.iter() {
                        let addrs: Vec<Ipv4Addr> = iface
                            .ipv4_ips()
                            .filter(|addr| !addr.is_loopback() && !addr.is_unspecified())
                            .copied()
                            .collect();
                        if addrs.is_empty() {
                            continue;
                        }

                        let mut joined = Vec::new();
                        for addr in addrs {
                            match sock.join_multicast_v4(GROUP, addr) {
                                Ok(()) => joined.push(addr),
                                Err(e) if e.kind() != io::ErrorKind::AddrInUse => {
                                    // skip AddrInUse - just means we've already joined the mv4
                                    warn!(
                                        "failed to join multicast v4 for interface {} ({addr}): {e}",
                                        iface.name
                                    )
                                }
                                _ => {}
                            }
                        }
                        if !joined.is_empty() {
                            ifaces.lock().insert(*iface_idx, joined);
                        }
                    }
                    for iface_idx in update.diff.removed {
                        let Some(addrs) = ifaces.lock().remove(&iface_idx) else {
                            continue;
                        };
                        for addr in addrs {
                            if let Err(e) = sock.leave_multicast_v4(GROUP, addr) {
                                if let Some(iface) = update.interfaces.get(&iface_idx) {
                                    warn!(
                                        "failed to leave multicast v4 for interface {} ({addr}): {e}",
                                        iface.name
                                    )
                                }
                            }
                        }
                    }
                }
            })
            // todo: better error handling here
            .expect("failed to bind discovery watcher"),
        );
        Ok(Self {
            sock,
            namespace,
            ifaces,
            last_nonce: Mutex::new(rand::random()),
            listen_port,
            zid,
            dest: SocketAddrV4::new(GROUP, discovery_port),
            tick: interval(Duration::from_secs(1)),
            _sync,
        })
    }

    pub async fn next(&mut self) -> io::Result<Discovered> {
        let mut buf = [0u8; Hello::buf_size() + WhatsUp::buf_size() + 1];
        loop {
            tokio::select! {
                _ = self.tick.tick() => {
                    self.announce().await?;
                }
                res = self.sock.recv_from(&mut buf) => {
                    let Ok((bytes_read, addr)) = res else { continue; };
                    if let Some(discovered) = self.respond(bytes_read, addr, &buf).await? {
                        return Ok(discovered)
                    }
                }
            }
        }
    }

    async fn respond(
        &self,
        bytes_read: usize,
        addr: SocketAddr,
        buf: &[u8],
    ) -> io::Result<Option<Discovered>> {
        trace!(
            "raw recv: {bytes_read} bytes from {addr}: {:02x?}",
            &buf[..bytes_read]
        );
        if bytes_read < size_of::<Header>() {
            trace!("dropped: early EOF");
            return Ok(None);
        }
        let header: &Header = bytemuck::from_bytes(&buf[0..size_of::<Header>()]);
        if header.magic != MAGIC {
            trace!("dropped: wrong magic");
            return Ok(None);
        }
        let Ok(kind) = header.kind.try_into() else {
            trace!("dropped: unknown message kind {}", header.kind);
            return Ok(None);
        };
        match kind {
            Kind::Hello => {
                let total = Hello::buf_size();
                if bytes_read != total {
                    trace!("dropped: hello wrong size");
                    return Ok(None);
                }
                let hello: &Hello = bytemuck::from_bytes(&buf[size_of::<Header>()..total]);
                if hello.nonce == *self.last_nonce.lock() {
                    trace!("dropped: local hello nonce");
                    return Ok(None);
                }
                if hello.namespace != self.namespace {
                    trace!("dropped: different namespace");
                    return Ok(None);
                }

                // reply
                trace!("replying to Hello({:?})", hello.nonce);
                let reply = WhatsUp {
                    nonce: hello.nonce,
                    zid: self.zid.to_le_bytes(),
                    port_le: self.listen_port.to_le_bytes(),
                }
                .alloc();

                for i in 1..6 {
                    if self
                        .sock
                        .send_to(&reply, addr)
                        .await
                        .inspect_err(|e| debug!("send to {addr} failed: {e}"))
                        .is_ok_and(|sent| sent == WhatsUp::buf_size())
                    {
                        trace!(
                            "sent {} bytes to {addr} after {} attempt(s)",
                            WhatsUp::buf_size(),
                            i
                        );
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                Ok(None)
            }
            Kind::WhatsUp => {
                let total = WhatsUp::buf_size();
                if bytes_read != total {
                    trace!("dropped: whatsup wrong size");
                    return Ok(None);
                }
                let whats_up: &WhatsUp = bytemuck::from_bytes(&buf[size_of::<Header>()..total]);
                if whats_up.nonce != *self.last_nonce.lock() {
                    trace!("dropped: stale nonce");
                    return Ok(None);
                }
                let SocketAddr::V4(v4) = addr else {
                    trace!("dropped: v6 addr used");
                    return Ok(None);
                };
                let Ok(zid) = ZenohId::try_from(&whats_up.zid[..]) else {
                    trace!("dropped: zenoh conversion failed");
                    return Ok(None);
                };
                if zid == self.zid {
                    trace!("dropped: self zenoh id");
                    return Ok(None);
                }
                // discovery success!
                // the incoming port is our listen port;
                // overwrite it with the whats_up port corresponding to the remote zenoh service
                let addr = {
                    let mut x = v4;
                    x.set_port(u16::from_le_bytes(whats_up.port_le));
                    x
                };
                Ok(Some(Discovered { addr, zid }))
            }
        }
    }

    async fn announce(&self) -> io::Result<()> {
        let nonce = rand::random();
        *self.last_nonce.lock() = nonce;
        let buf = Hello {
            nonce,
            namespace: self.namespace,
        }
        .alloc();

        let ifaces = self.ifaces.lock().clone();
        debug!("announcing Hello({nonce:?}) to {} interface(s)", ifaces.len());
        for (iface_idx, addrs) in ifaces {
            // ipv4 multicast sends have no per-destination scope (unlike ipv6), so the
            // outgoing interface is instead selected on the socket itself via IP_MULTICAST_IF,
            // using one of the local addresses we successfully joined the group with on it.
            let Some(&local_addr) = addrs.first() else {
                continue;
            };
            if let Err(e) = SockRef::from(&*self.sock).set_multicast_if_v4(&local_addr) {
                debug!(
                    "failed to set outgoing multicast interface to {local_addr} (idx {iface_idx}): {e}"
                );
                continue;
            }
            match self.sock.send_to(&buf, self.dest).await {
                Ok(bytes) => trace!("sent {bytes} to {} via {local_addr}", self.dest),
                Err(e) if e.kind() == io::ErrorKind::HostUnreachable => {
                    debug!("disabling discovery interface {iface_idx} ({local_addr}): {e}");
                    self.ifaces.lock().remove(&iface_idx);
                }
                Err(e) => debug!("failed to reach {} via {local_addr}: {e}", self.dest),
            }
        }
        Ok(())
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
// packet & version
pub enum Kind {
    Hello = 0,
    WhatsUp = 1,
}

pub struct UnknownKind;
impl TryFrom<u8> for Kind {
    type Error = UnknownKind;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Hello),
            1 => Ok(Self::WhatsUp),
            _ => Err(UnknownKind),
        }
    }
}

pub trait Message: Pod {
    const KIND: Kind;
}
// should be part of the Message trait, but const in traits isnt stabilized. this lets alloc :: Self -> [u8; Self::buf_size()]
macro_rules! impl_alloc {
    ($a:ident) => {
        impl $a {
            const fn buf_size() -> usize {
                size_of::<Header>() + size_of::<Self>()
            }
            pub fn alloc(self) -> [u8; Self::buf_size()] {
                let mut buf = [0u8; Self::buf_size()];
                buf[0..size_of::<Header>()].copy_from_slice(bytemuck::bytes_of(&Header {
                    magic: MAGIC,
                    kind: Self::KIND as u8,
                }));
                buf[size_of::<Header>()..Self::buf_size()]
                    .copy_from_slice(bytemuck::bytes_of(&self));
                buf
            }
        }
    };
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Header {
    magic: [u8; 3],
    kind: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Hello {
    pub nonce: [u8; 8],
    pub namespace: [u8; 8],
}
impl Message for Hello {
    const KIND: Kind = Kind::Hello;
}
impl_alloc!(Hello);

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct WhatsUp {
    pub nonce: [u8; 8],
    pub zid: [u8; 16],
    pub port_le: [u8; 2],
}
impl Message for WhatsUp {
    const KIND: Kind = Kind::WhatsUp;
}
impl_alloc!(WhatsUp);
