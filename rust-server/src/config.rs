use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use clap::{Arg, ArgAction, Command};

use crate::logger::DEBUG_ENABLED;
use crate::packet::SecretEntry;

/// Validated, parsed command-line configuration.
pub struct Config {
    /// UDP port to listen on.
    pub port: u16,
    /// HMAC-SHA256 shared secrets. Empty means no authentication (packets are not verified).
    pub secrets: Arc<Vec<SecretEntry>>,
    /// Number of worker threads shared across all sockets (used by the Linux epoll backend).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub num_threads: usize,
    /// Addresses to bind to. Empty means bind to all interfaces (dual-stack wildcard).
    pub bind_addrs: Vec<IpAddr>,
    /// Collector address for UDP syslog event logging. `None` disables event logging.
    pub syslog_target: Option<SocketAddr>,
}

impl Config {
    /// Parses and validates command-line arguments, populating this struct.
    /// Also stores the initial debug-logging state in `DEBUG_ENABLED`.
    pub fn from_args() -> Self {
        let matches = Command::new("UDP Ping Server")
            .version(env!("GIT_VERSION"))
            .arg(
                Arg::new("secret")
                    .short('s')
                    .long("secret")
                    .value_name("SECRET")
                    .help("HMAC-SHA256 shared secret (visible in process list — prefer --secret-file)"),
            )
            .arg(
                Arg::new("secret-file")
                    .short('f')
                    .long("secret-file")
                    .value_name("PATH")
                    .help("File with HMAC-SHA256 shared secrets, one per line: '<secret>[ <label>]'"),
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
            .arg(
                Arg::new("syslog")
                    .long("syslog")
                    .value_name("TARGET")
                    .help("Send structured RFC 5424 logs over UDP to TARGET (IP or IP:port; port default 514)"),
            )
            .get_matches();

        // Apply the debug flag immediately so subsequent log::debug! calls are visible.
        DEBUG_ENABLED.store(matches.get_flag("debug"), Ordering::Relaxed);

        // Collect secrets: the command-line secret (if any) first, then the file's secrets.
        // Unlabeled secrets receive the default label `secret_<n>` based on their 1-based
        // position in the combined list.
        let mut secrets: Vec<SecretEntry> = Vec::new();
        if let Some(s) = matches.get_one::<String>("secret") {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                eprintln!("Command-line secret is empty");
                std::process::exit(1);
            }
            secrets.push(SecretEntry {
                secret: trimmed.as_bytes().to_vec(),
                label: format!("secret_{}", secrets.len() + 1),
            });
        }
        if let Some(path) = matches.get_one::<String>("secret-file") {
            read_secret_file(path, &mut secrets);
        }
        let secrets = Arc::new(secrets);

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

        let syslog_target = matches
            .get_one::<String>("syslog")
            .map(|s| parse_syslog_target(s));

        Config { port, secrets, num_threads, bind_addrs, syslog_target }
    }

    /// Total number of worker threads shared across all sockets (used by the Linux epoll backend).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn num_worker_threads(&self) -> usize {
        self.num_threads
    }
}

/// Reads a secrets file and appends each secret to `secrets`.
///
/// Each non-empty line has the format `<secret>[ <label>]`: the secret is the first
/// whitespace-trimmed token, and an optional label follows. When a line has no label,
/// the secret receives the default label `secret_<n>` based on its 1-based position in
/// the combined `secrets` list (so the command-line secret, if present, is `secret_1`).
/// Blank lines and lines starting with `#` are ignored.
/// Exits the process if the file cannot be read or contains no secrets.
fn read_secret_file(path: &str, secrets: &mut Vec<SecretEntry>) {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Cannot read secret file '{path}': {e}");
        std::process::exit(1);
    });

    let mut added = 0;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (secret_str, label) = match trimmed.split_once(|c: char| c.is_ascii_whitespace()) {
            Some((s, l)) if !l.trim().is_empty() => (s, l.trim().to_string()),
            Some((s, _)) => (s, format!("secret_{}", secrets.len() + 1)),
            None => (trimmed, format!("secret_{}", secrets.len() + 1)),
        };
        secrets.push(SecretEntry { secret: secret_str.as_bytes().to_vec(), label });
        added += 1;
    }

    if added == 0 {
        eprintln!("Secret file '{path}' contains no secrets");
        std::process::exit(1);
    }
}

/// Parses a syslog target of the form `IP` or `IP:port`. The port is optional and
/// defaults to 514. IPv6 addresses must be bracketed when a port is given (`[::1]:514`).
/// Exits the process on an invalid target.
fn parse_syslog_target(s: &str) -> SocketAddr {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return addr;
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return SocketAddr::new(ip, 514);
    }
    eprintln!("Invalid --syslog target '{s}' (expected IP or IP:port)");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(num_threads: usize) -> Config {
        Config {
            port: 444,
            secrets: Arc::new(vec![]),
            num_threads,
            bind_addrs: vec![],
            syslog_target: None,
        }
    }

    #[test]
    fn num_worker_threads_reflects_config() {
        assert_eq!(make_config(8).num_worker_threads(), 8);
    }

    #[test]
    fn num_worker_threads_minimum_one() {
        assert_eq!(make_config(1).num_worker_threads(), 1);
    }

    // ── read_secret_file ──────────────────────────────────────────────────────

    fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    fn read(path: &std::path::Path) -> Vec<SecretEntry> {
        let mut secrets = Vec::new();
        read_secret_file(path.to_str().unwrap(), &mut secrets);
        secrets
    }

    #[test]
    fn single_secret_no_label() {
        let p = write_temp("udp_server_test_secret_single.txt", "my-secret\n");
        let s = read(&p);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].secret, b"my-secret");
        assert_eq!(s[0].label, "secret_1");
    }

    #[test]
    fn secret_trims_surrounding_whitespace() {
        let p = write_temp("udp_server_test_secret_ws.txt", "  my-secret  \r\n");
        let s = read(&p);
        assert_eq!(s[0].secret, b"my-secret");
    }

    #[test]
    fn labeled_and_unlabeled_lines() {
        let p = write_temp(
            "udp_server_test_secret_mixed.txt",
            "key1 label-one\nkey2\nkey3 label-three\n",
        );
        let s = read(&p);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].secret, b"key1");
        assert_eq!(s[0].label, "label-one");
        assert_eq!(s[1].secret, b"key2");
        assert_eq!(s[1].label, "secret_2"); // default label uses 1-based position
        assert_eq!(s[2].secret, b"key3");
        assert_eq!(s[2].label, "label-three");
    }

    #[test]
    fn ignores_blank_lines_and_comments() {
        let p = write_temp(
            "udp_server_test_secret_comments.txt",
            "# comment\n\nkey1 lbl\n\n# another comment\nkey2\n",
        );
        let s = read(&p);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].secret, b"key1");
        assert_eq!(s[0].label, "lbl");
        assert_eq!(s[1].secret, b"key2");
        assert_eq!(s[1].label, "secret_2");
    }

    // ── parse_syslog_target ───────────────────────────────────────────────────

    #[test]
    fn syslog_target_ip_only_defaults_port_514() {
        assert_eq!(parse_syslog_target("10.0.0.1"), "10.0.0.1:514".parse().unwrap());
    }

    #[test]
    fn syslog_target_ip_with_port() {
        assert_eq!(parse_syslog_target("10.0.0.1:5514"), "10.0.0.1:5514".parse().unwrap());
    }

    #[test]
    fn syslog_target_ipv6_bracketed_with_port() {
        assert_eq!(parse_syslog_target("[::1]:514"), "[::1]:514".parse().unwrap());
    }

    #[test]
    fn default_label_continues_after_existing_secrets() {
        // Simulate a command-line secret already in the list: file secrets continue the count.
        let p = write_temp("udp_server_test_secret_continue.txt", "file-key\n");
        let mut secrets = vec![SecretEntry {
            secret: b"cli-secret".to_vec(),
            label: "secret_1".to_string(),
        }];
        read_secret_file(p.to_str().unwrap(), &mut secrets);
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[1].secret, b"file-key");
        assert_eq!(secrets[1].label, "secret_2");
    }
}
