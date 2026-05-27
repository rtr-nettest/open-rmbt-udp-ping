use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use log::{debug, error, info};
use socket2::{Domain, Protocol, Socket, Type};

use crate::config::Config;
use crate::packet;

/// Size of the receive buffer per worker thread. Must be at least 24 bytes (one RP01 packet).
const BUFFER_SIZE: usize = 1024;

/// A bound UDP server: one socket per configured address, ready to spawn workers.
pub struct Server {
    config: Config,
    /// Each element is shared among the worker threads assigned to that socket.
    sockets: Vec<Arc<UdpSocket>>,
}

impl Server {
    /// Binds one UDP socket for every address in `config.bind_addrs`, or a single
    /// dual-stack wildcard socket when no addresses are specified.
    pub fn bind(config: Config) -> io::Result<Self> {
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
                        .unwrap_or_else(|e| panic!("Failed to bind to {addr}: {e}"))
                })
                .collect()
        };

        Ok(Server { config, sockets })
    }

    /// Spawns worker threads and blocks until they all exit.
    /// Under normal operation the threads loop forever, so this never returns.
    pub fn run(self) {
        let threads_per_socket = self.config.threads_per_socket();
        info!("{} socket(s), {threads_per_socket} thread(s) each", self.sockets.len());

        let handles: Vec<JoinHandle<()>> = self
            .sockets
            .iter()
            .flat_map(|socket| {
                // Each socket gets its own slice of threads; clone the Arc once per socket.
                let socket = socket.clone();
                let seed = self.config.seed.clone();
                (0..threads_per_socket).map(move |idx| {
                    let socket = socket.clone();
                    let seed = seed.clone();
                    thread::spawn(move || {
                        debug!("Worker {idx} started on {}", socket.local_addr().unwrap());
                        worker_loop(socket, seed);
                    })
                })
            })
            .collect();

        for handle in handles {
            handle.join().ok();
        }
    }
}

/// Runs forever: receives UDP packets and writes a response for each valid one.
///
/// Because each socket is bound to a specific local address, `send_to` automatically
/// uses that address as the source IP — so replies always come from the same IP the
/// client originally addressed.
fn worker_loop(socket: Arc<UdpSocket>, seed: Option<Vec<u8>>) {
    let seed = seed.as_deref();
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let (len, src_addr) = match socket.recv_from(&mut buffer) {
            Ok(r) => r,
            Err(e) => {
                error!("recv_from: {e}");
                continue;
            }
        };

        debug!("Received (len={len}): {}", hex::encode(&buffer[..len]));

        if let Some(response) = packet::process_packet(&buffer[..len], src_addr, seed) {
            debug!("Sending response: {}", hex::encode(response));
            if let Err(e) = socket.send_to(&response, src_addr) {
                error!("send_to: {e}");
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
