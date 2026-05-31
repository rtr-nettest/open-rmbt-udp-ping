use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use clap::{Arg, ArgAction, Command};

use crate::logger::DEBUG_ENABLED;
use crate::packet::KeyEntry;

/// Validated, parsed command-line configuration.
pub struct Config {
    /// UDP port to listen on.
    pub port: u16,
    /// HMAC-SHA256 keys. Empty means no authentication (packets are not verified).
    pub keys: Arc<Vec<KeyEntry>>,
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
            .version("1.2.0")
            .arg(
                Arg::new("seed")
                    .short('s')
                    .long("seed")
                    .value_name("SEED")
                    .conflicts_with_all(["seed-file", "keys-file"])
                    .help("HMAC-SHA256 shared secret (visible in process list — prefer --seed-file)"),
            )
            .arg(
                Arg::new("seed-file")
                    .short('f')
                    .long("seed-file")
                    .value_name("PATH")
                    .conflicts_with_all(["seed", "keys-file"])
                    .help("File containing one HMAC-SHA256 shared secret (one line, whitespace trimmed)"),
            )
            .arg(
                Arg::new("keys-file")
                    .short('k')
                    .long("keys-file")
                    .value_name("PATH")
                    .conflicts_with_all(["seed", "seed-file"])
                    .help("File with multiple HMAC-SHA256 keys, one per line: '<key> <label>'"),
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

        let keys = if let Some(path) = matches.get_one::<String>("keys-file") {
            Arc::new(read_keys_file(path))
        } else if let Some(path) = matches.get_one::<String>("seed-file") {
            Arc::new(vec![KeyEntry {
                key: read_seed_file(path),
                label: "default".to_string(),
            }])
        } else if let Some(s) = matches.get_one::<String>("seed") {
            Arc::new(vec![KeyEntry {
                key: s.as_bytes().to_vec(),
                label: "default".to_string(),
            }])
        } else {
            Arc::new(vec![])
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

        Config { port, keys, num_threads, bind_addrs }
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

/// Reads a multi-key file where each line has the format `<key> <label>`.
/// Blank lines and lines starting with `#` are ignored.
/// Exits the process if the file cannot be read or contains no valid entries.
fn read_keys_file(path: &str) -> Vec<KeyEntry> {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Cannot read keys file '{path}': {e}");
        std::process::exit(1);
    });

    let entries: Vec<KeyEntry> = raw
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let (key_str, label) = match trimmed.split_once(|c: char| c.is_ascii_whitespace()) {
                Some((k, l)) => (k, l.trim().to_string()),
                None => (trimmed, format!("key-{}", i + 1)),
            };
            if key_str.is_empty() {
                eprintln!("Keys file '{path}': empty key on line {}", i + 1);
                std::process::exit(1);
            }
            Some(KeyEntry { key: key_str.as_bytes().to_vec(), label })
        })
        .collect();

    if entries.is_empty() {
        eprintln!("Keys file '{path}' contains no valid entries");
        std::process::exit(1);
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(num_threads: usize) -> Config {
        Config { port: 444, keys: Arc::new(vec![]), num_threads, bind_addrs: vec![] }
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

    // ── read_keys_file ────────────────────────────────────────────────────────

    #[test]
    fn keys_file_two_entries() {
        let p = write_temp("udp_server_test_keys.txt", "key1 label-one\nkey2 label-two\n");
        let entries = read_keys_file(p.to_str().unwrap());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, b"key1");
        assert_eq!(entries[0].label, "label-one");
        assert_eq!(entries[1].key, b"key2");
        assert_eq!(entries[1].label, "label-two");
    }

    #[test]
    fn keys_file_ignores_blank_lines_and_comments() {
        let p = write_temp(
            "udp_server_test_keys_comments.txt",
            "# comment\n\nkey1 lbl\n\n# another comment\nkey2 lbl2\n",
        );
        let entries = read_keys_file(p.to_str().unwrap());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, b"key1");
        assert_eq!(entries[1].key, b"key2");
    }

    #[test]
    fn keys_file_label_defaults_when_missing() {
        let p = write_temp("udp_server_test_keys_nolabel.txt", "only-key\n");
        let entries = read_keys_file(p.to_str().unwrap());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, b"only-key");
        // Label must be non-empty (exact value is implementation-defined).
        assert!(!entries[0].label.is_empty());
    }
}
