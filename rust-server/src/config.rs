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
    /// Number of worker threads shared across all sockets (used by the Linux epoll backend).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
                    .conflicts_with("seed-file")
                    .help("HMAC-SHA256 shared secret (visible in process list — prefer --seed-file)"),
            )
            .arg(
                Arg::new("seed-file")
                    .short('f')
                    .long("seed-file")
                    .value_name("PATH")
                    .conflicts_with("seed")
                    .help("File containing the HMAC-SHA256 shared secret (one line, whitespace trimmed)"),
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
                    .help("Total worker threads shared across all sockets (default: logical CPU count)"),
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

        let seed = if let Some(path) = matches.get_one::<String>("seed-file") {
            Some(read_seed_file(path))
        } else {
            matches.get_one::<String>("seed").map(|s| s.as_bytes().to_vec())
        };

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

    /// Total number of worker threads shared across all sockets (used by the Linux epoll backend).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn num_worker_threads(&self) -> usize {
        self.num_threads
    }
}

/// Reads the shared secret from `path`, trims surrounding whitespace, and returns it as bytes.
/// Exits the process with an error message if the file cannot be read or is empty.
fn read_seed_file(path: &str) -> Vec<u8> {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Cannot read seed file '{path}': {e}");
        std::process::exit(1);
    });
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        eprintln!("Seed file '{path}' is empty");
        std::process::exit(1);
    }
    trimmed.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(num_threads: usize) -> Config {
        Config { port: 444, seed: None, num_threads, bind_addrs: vec![] }
    }

    #[test]
    fn num_worker_threads_reflects_config() {
        assert_eq!(make_config(8).num_worker_threads(), 8);
    }

    #[test]
    fn num_worker_threads_minimum_one() {
        assert_eq!(make_config(1).num_worker_threads(), 1);
    }

    // ── read_seed_file ────────────────────────────────────────────────────────

    fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn seed_file_plain_content() {
        let p = write_temp("udp_server_test_seed_plain.txt", "my-secret");
        assert_eq!(read_seed_file(p.to_str().unwrap()), b"my-secret");
    }

    #[test]
    fn seed_file_trims_surrounding_whitespace() {
        let p = write_temp("udp_server_test_seed_ws.txt", "  my-secret\n");
        assert_eq!(read_seed_file(p.to_str().unwrap()), b"my-secret");
    }

    #[test]
    fn seed_file_trims_windows_line_ending() {
        let p = write_temp("udp_server_test_seed_crlf.txt", "my-secret\r\n");
        assert_eq!(read_seed_file(p.to_str().unwrap()), b"my-secret");
    }
}
