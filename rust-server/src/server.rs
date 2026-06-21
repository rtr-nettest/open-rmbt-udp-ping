use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use log::{debug, error, info};
use socket2::{Domain, Protocol, Socket, Type};

use crate::config::Config;
use crate::events::EventSink;
use crate::packet::{self, SecretEntry};

/// Receive buffer per worker thread — large enough for one RP01 packet.
const BUFFER_SIZE: usize = 1024;

/// Maximum epoll events dequeued per epoll_wait call (Linux only).
#[cfg(target_os = "linux")]
const EPOLL_BATCH: usize = 16;

/// A bound UDP server: one socket per configured address, ready to spawn workers.
pub struct Server {
    config: Config,
    sockets: Vec<Arc<UdpSocket>>,
    /// Optional structured-event logger; `None` when `--syslog` is not set.
    sink: Option<Arc<EventSink>>,
}

impl Server {
    /// Binds one UDP socket for every address in `config.bind_addrs`, or a single
    /// dual-stack wildcard socket when no addresses are specified.
    /// Panics immediately on any bind failure so the server never starts partially bound.
    pub fn bind(config: Config, sink: Option<Arc<EventSink>>) -> io::Result<Self> {
        let sockets: Vec<Arc<UdpSocket>> = if config.bind_addrs.is_empty() {
            info!("Listening on all interfaces, port {}", config.port);
            vec![Arc::new(setup_socket(None, config.port)?)]
        } else {
            config
                .bind_addrs
                .iter()
                .map(|&addr| {
                    info!("Listening on {addr}, port {}", config.port);
                    setup_socket(Some(addr), config.port)
                        .map(Arc::new)
                        .unwrap_or_else(|e| {
                            if let Some(sink) = &sink {
                                sink.error("bind", &e);
                            }
                            panic!("Failed to bind to {addr}: {e}");
                        })
                })
                .collect()
        };

        Ok(Server { config, sockets, sink })
    }

    /// Starts the epoll dispatch loop (Linux).
    ///
    /// Design: one shared epoll fd; all bound sockets registered with EPOLLIN|EPOLLEXCLUSIVE.
    /// `num_threads` worker threads each call epoll_wait() on the shared fd, then drain
    /// whichever socket(s) became ready. EPOLLEXCLUSIVE prevents thundering herd: only one
    /// thread is woken per readiness event. Total thread count is independent of socket count.
    #[cfg(target_os = "linux")]
    pub fn run(self) {
        use std::os::fd::AsRawFd;

        let num_threads = self.config.num_worker_threads();
        if let Some(sink) = &self.sink {
            sink.startup(self.config.port, &self.config.bind_addrs, self.sockets.len(), self.config.secrets.len());
        }
        let secrets = self.config.secrets;
        let sink = self.sink;
        info!("{} socket(s), {num_threads} worker thread(s) total", self.sockets.len());

        for s in &self.sockets {
            s.set_nonblocking(true).expect("set_nonblocking failed");
        }

        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            panic!("epoll_create1: {}", io::Error::last_os_error());
        }

        let sockets = Arc::new(self.sockets);
        for (i, socket) in sockets.iter().enumerate() {
            let mut ev = libc::epoll_event {
                events: (libc::EPOLLIN | libc::EPOLLEXCLUSIVE) as u32,
                u64: i as u64,
            };
            if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, socket.as_raw_fd(), &mut ev) } < 0 {
                panic!("epoll_ctl add socket {i}: {}", io::Error::last_os_error());
            }
        }

        let handles: Vec<JoinHandle<()>> = (0..num_threads)
            .map(|idx| {
                let sockets = sockets.clone();
                let secrets = secrets.clone();
                let sink = sink.clone();
                thread::spawn(move || {
                    debug!("Worker {idx} started");
                    worker_loop_epoll(epoll_fd, sockets, secrets, sink);
                })
            })
            .collect();

        for handle in handles {
            handle.join().ok();
        }
    }

    /// Starts a thread-per-socket blocking dispatch loop (non-Linux fallback).
    ///
    /// One thread is spawned per bound socket. Each thread blocks on recv_from and
    /// processes packets synchronously. The `num_threads` config is not used here
    /// since the thread count is determined by the number of bound sockets.
    #[cfg(not(target_os = "linux"))]
    pub fn run(self) {
        if let Some(sink) = &self.sink {
            sink.startup(self.config.port, &self.config.bind_addrs, self.sockets.len(), self.config.secrets.len());
        }
        let secrets = self.config.secrets;
        let sink = self.sink;
        info!("{} socket(s), one blocking thread per socket", self.sockets.len());

        let handles: Vec<JoinHandle<()>> = self.sockets
            .into_iter()
            .enumerate()
            .map(|(idx, socket)| {
                let secrets = secrets.clone();
                let sink = sink.clone();
                thread::spawn(move || {
                    debug!("Worker {idx} started (blocking)");
                    worker_loop_blocking(socket, secrets, sink);
                })
            })
            .collect();

        for handle in handles {
            handle.join().ok();
        }
    }
}

/// Runs forever: waits for ready sockets via epoll and drains each one completely (Linux).
///
/// Non-blocking recv_from is called in a loop until EAGAIN/WouldBlock to ensure all
/// queued packets are processed before returning to epoll_wait.
#[cfg(target_os = "linux")]
fn worker_loop_epoll(
    epoll_fd: i32,
    sockets: Arc<Vec<Arc<UdpSocket>>>,
    secrets: Arc<Vec<SecretEntry>>,
    sink: Option<Arc<EventSink>>,
) {
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; EPOLL_BATCH];

    loop {
        let n = unsafe {
            libc::epoll_wait(epoll_fd, events.as_mut_ptr(), EPOLL_BATCH as i32, -1)
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            error!("epoll_wait: {e}");
            continue;
        }

        for ev in &events[..n as usize] {
            let socket = &sockets[ev.u64 as usize];
            // Drain all queued packets from this socket before returning to epoll_wait.
            loop {
                match socket.recv_from(&mut buffer) {
                    Ok((len, src_addr)) => {
                        debug!("Received (len={len}): {}", hex::encode(&buffer[..len]));
                        let processed = packet::process_packet(&buffer[..len], src_addr, &secrets);
                        if let Some(sink) = &sink {
                            sink.log_outcome(src_addr.ip(), &processed.outcome);
                        }
                        if let Some(response) = processed.response {
                            debug!("Sending response: {}", hex::encode(response));
                            if let Err(e) = socket.send_to(&response, src_addr) {
                                error!("send_to: {e}");
                                if let Some(sink) = &sink {
                                    sink.error("send_to", &e);
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        error!("recv_from: {e}");
                        if let Some(sink) = &sink {
                            sink.error("recv_from", &e);
                        }
                        break;
                    }
                }
            }
        }
    }
}

/// Runs forever: blocks on recv_from and processes packets one at a time (non-Linux fallback).
#[cfg(not(target_os = "linux"))]
fn worker_loop_blocking(
    socket: Arc<UdpSocket>,
    secrets: Arc<Vec<SecretEntry>>,
    sink: Option<Arc<EventSink>>,
) {
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                debug!("Received (len={len}): {}", hex::encode(&buffer[..len]));
                let processed = packet::process_packet(&buffer[..len], src_addr, &secrets);
                if let Some(sink) = &sink {
                    sink.log_outcome(src_addr.ip(), &processed.outcome);
                }
                if let Some(response) = processed.response {
                    debug!("Sending response: {}", hex::encode(response));
                    if let Err(e) = socket.send_to(&response, src_addr) {
                        error!("send_to: {e}");
                        if let Some(sink) = &sink {
                            sink.error("send_to", &e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("recv_from: {e}");
                if let Some(sink) = &sink {
                    sink.error("recv_from", &e);
                }
            }
        }
    }
}

/// Creates and binds a UDP socket.
///
/// | `bind_addr`         | Socket family | Notes                                   |
/// |---------------------|---------------|-----------------------------------------|
/// | `None` (wildcard)   | IPv6          | `IPV6_V6ONLY=false` → accepts IPv4 too  |
/// | `Some(IPv4 address)`| IPv4          | dedicated IPv4 socket                   |
/// | `Some(IPv6 address)`| IPv6          | dedicated IPv6 socket, v6-only          |
fn setup_socket(bind_addr: Option<IpAddr>, port: u16) -> io::Result<UdpSocket> {
    match bind_addr {
        None => {
            // Dual-stack wildcard: one socket handles both IPv4 and IPv6 clients.
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_reuse_address(true)?;
            socket.set_only_v6(false)?; // accept IPv4-mapped addresses (::ffff:x.x.x.x)
            socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
            Ok(socket.into())
        }
        Some(ip) => {
            // Specific address: choose the right socket family automatically.
            let domain = if ip.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_reuse_address(true)?;
            socket.bind(&SocketAddr::new(ip, port).into())?;
            Ok(socket.into())
        }
    }
}
