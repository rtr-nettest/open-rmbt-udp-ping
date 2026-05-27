use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::thread;

use clap::{Arg, ArgAction, Command};

use crate::logger::DEBUG_ENABLED;

/// Validated, parsed command-line configuration.
pub struct Config {
    /// UDP port to listen on.
    pub port: u16,
    /// Optional HMAC-SHA256 shared secret. When absent, packets are not authenticated.
    pub seed: Option<Vec<u8>>,
    /// Total number of worker threads to spread across all bound sockets.
    pub num_threads: usize,
    /// Addresses to bind to. Empty means bind to all interfaces (dual-stack wildcard).
    pub bind_addrs: Vec<IpAddr>,
}

impl Config {
    /// Parses and validates command-line arguments, populating this struct.
    /// Also stores the initial debug-logging state in `DEBUG_ENABLED`.
    pub fn from_args() -> Self {
        let matches = Command::new("UDP Ping Server")
            .version("1.1.0")
            .arg(
                Arg::new("seed")
                    .short('s')
                    .long("seed")
                    .value_name("SEED")
                    .help("HMAC-SHA256 shared secret; omit to accept all packets without authentication"),
            )
            .arg(
                Arg::new("bind")
                    .short('b')
                    .long("bind")
                    .value_name("ADDR")
                    .action(ArgAction::Append)
                    .help("IP address to listen on; may be repeated (default: all interfaces)"),
            )
            .arg(
                Arg::new("threads")
                    .short('t')
                    .long("threads")
                    .value_name("N")
                    .help("Total worker threads, spread across bound addresses (default: logical CPU count)"),
            )
            .arg(
                Arg::new("debug")
                    .short('d')
                    .long("debug")
                    .action(ArgAction::SetTrue)
                    .help("Enable debug logging at startup (also toggled at runtime via SIGUSR1 on Unix)"),
            )
            .arg(
                Arg::new("port")
                    .short('p')
                    .long("port")
                    .value_name("PORT")
                    .help("UDP port to listen on (default: 444)"),
            )
            .get_matches();

        // Apply the debug flag immediately so subsequent log::debug! calls are visible.
        DEBUG_ENABLED.store(matches.get_flag("debug"), Ordering::Relaxed);

        let seed = matches
            .get_one::<String>("seed")
            .map(|s| s.as_bytes().to_vec());

        let port = matches
            .get_one::<String>("port")
            .map(|s| s.parse::<u16>().expect("Invalid port number"))
            .unwrap_or(444);

        let num_threads = matches
            .get_one::<String>("threads")
            .map(|s| s.parse::<usize>().expect("Invalid thread count"))
            .unwrap_or_else(|| thread::available_parallelism().map(|n| n.get()).unwrap_or(1));

        let bind_addrs = matches
            .get_many::<String>("bind")
            .map(|vals| {
                vals.map(|s| {
                    s.parse::<IpAddr>().unwrap_or_else(|_| {
                        eprintln!("Invalid IP address: {s}");
                        std::process::exit(1);
                    })
                })
                .collect()
            })
            .unwrap_or_default();

        Config { port, seed, num_threads, bind_addrs }
    }

    /// How many worker threads each socket should receive.
    /// The total thread budget is divided evenly; each socket gets at least one thread.
    pub fn threads_per_socket(&self, num_sockets: usize) -> usize {
        (self.num_threads / num_sockets).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(num_threads: usize) -> Config {
        Config { port: 444, seed: None, num_threads, bind_addrs: vec![] }
    }

    #[test]
    fn threads_distributed_evenly() {
        assert_eq!(make_config(8).threads_per_socket(4), 2);
    }

    #[test]
    fn threads_minimum_one_per_socket() {
        // More sockets than threads → every socket still gets at least 1 thread.
        assert_eq!(make_config(2).threads_per_socket(8), 1);
    }

    #[test]
    fn threads_single_socket_gets_all() {
        assert_eq!(make_config(6).threads_per_socket(1), 6);
    }
}
