//! Structured event logging to a remote collector over UDP syslog (RFC 5424).
//!
//! When `--syslog <target>` is set, the server emits one UDP datagram per event in
//! RFC 5424 framing with a JSON object as the message body, e.g.:
//!
//! ```text
//! <134>1 2026-06-21T12:34:56.789Z host udp_server 4242 auth - {"event":"good_ping","src":"1.2.3.4","secret":"secret_1"}
//! ```
//!
//! This format ingests cleanly into ELK: Logstash parses the syslog envelope and the
//! `json` filter cracks the body into typed, queryable fields.
//!
//! Logging never blocks the packet hot path: sends are fire-and-forget (UDP, errors
//! ignored) and high-frequency events are rate-limited so a flood of bad packets — or
//! a busy server — cannot overwhelm the log pipeline:
//!   * "good" pings: the first per source IP per [`GOOD_PING_WINDOW`];
//!   * negative/error events: at most [`CLASS_RATE_PER_SEC`] per class per second.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::packet::Outcome;

const APP_NAME: &str = "udp_server";
/// Syslog facility `local0`.
const FACILITY: u32 = 16;

// RFC 5424 severities.
const SEV_ERR: u8 = 3;
const SEV_WARNING: u8 = 4;
const SEV_NOTICE: u8 = 5;
const SEV_INFO: u8 = 6;

/// A source IP gets at most one "good ping" event logged per this window.
const GOOD_PING_WINDOW: Duration = Duration::from_secs(60);
/// Per-class cap (per second) for negative and error events.
const CLASS_RATE_PER_SEC: u32 = 20;
/// Upper bound on tracked source IPs before stale entries are pruned.
const IP_MAP_MAX: usize = 16_384;

/// Sends structured events to a syslog collector over UDP.
pub struct EventSink {
    socket: UdpSocket,
    hostname: String,
    procid: u32,
    /// Fixed-window rate limiter per event class (auth_fail, ip_mismatch, error).
    class_windows: Mutex<HashMap<&'static str, ClassWindow>>,
    /// Last time a "good ping" was logged for each source IP.
    ip_last: Mutex<HashMap<IpAddr, Instant>>,
}

struct ClassWindow {
    start: Instant,
    count: u32,
}

impl EventSink {
    /// Connects a UDP socket to `target` so events can be sent with `send`.
    /// The local socket family matches the target (IPv4 or IPv6).
    pub fn new(target: SocketAddr) -> io::Result<Self> {
        let bind: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(target)?;
        Ok(Self {
            socket,
            hostname: hostname(),
            procid: std::process::id(),
            class_windows: Mutex::new(HashMap::new()),
            ip_last: Mutex::new(HashMap::new()),
        })
    }

    /// Emits a one-time startup event describing the running configuration.
    pub fn startup(&self, port: u16, bind_addrs: &[IpAddr], num_sockets: usize, num_secrets: usize) {
        self.emit(
            SEV_INFO,
            "lifecycle",
            Json::new()
                .str("event", "startup")
                .str("version", env!("GIT_VERSION"))
                .int("port", port as i64)
                .raw("bind", &ip_array(bind_addrs))
                .int("sockets", num_sockets as i64)
                .int("secrets", num_secrets as i64)
                .done(),
        );
    }

    /// Emits an error event (rate-limited so a repeating failure cannot flood the pipeline).
    pub fn error(&self, context: &str, err: &io::Error) {
        if self.class_allow("error") {
            self.emit(
                SEV_ERR,
                "error",
                Json::new()
                    .str("event", "error")
                    .str("context", context)
                    .str("message", &err.to_string())
                    .done(),
            );
        }
    }

    /// Emits a security event for a processed packet, applying the relevant rate limit.
    /// `src` is the packet's source IP. Invalid packets and the no-auth case are not logged.
    pub fn log_outcome(&self, src: IpAddr, outcome: &Outcome) {
        match *outcome {
            // Good pings are high volume: log only the first per IP per window.
            Outcome::Matched(secret) => {
                if self.good_ping_allow(src) {
                    self.emit(
                        SEV_INFO,
                        "auth",
                        Json::new()
                            .str("event", "good_ping")
                            .str("src", &src.to_string())
                            .str("secret", secret)
                            .done(),
                    );
                }
            }
            // Benign cause (client IP changed), but worth recording — rate-limited per class.
            Outcome::IpMismatch(secret) => {
                if self.class_allow("ip_mismatch") {
                    self.emit(
                        SEV_NOTICE,
                        "auth",
                        Json::new()
                            .str("event", "ip_mismatch")
                            .str("src", &src.to_string())
                            .str("secret", secret)
                            .done(),
                    );
                }
            }
            Outcome::NoMatch => {
                if self.class_allow("auth_fail") {
                    self.emit(
                        SEV_WARNING,
                        "auth",
                        Json::new()
                            .str("event", "auth_fail")
                            .str("src", &src.to_string())
                            .done(),
                    );
                }
            }
            Outcome::NoAuth | Outcome::Invalid => {}
        }
    }

    /// Builds the RFC 5424 frame and sends it. Fire-and-forget: send errors are ignored
    /// so logging never affects packet handling.
    fn emit(&self, severity: u8, msgid: &str, body: String) {
        let pri = FACILITY * 8 + severity as u32;
        let frame = format!(
            "<{pri}>1 {} {} {APP_NAME} {} {msgid} - {body}",
            rfc3339_now(),
            self.hostname,
            self.procid,
        );
        let _ = self.socket.send(frame.as_bytes());
    }

    /// Returns `true` if a "good ping" for `src` should be logged now (first in the window).
    fn good_ping_allow(&self, src: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.ip_last.lock().unwrap();
        if map.len() >= IP_MAP_MAX {
            map.retain(|_, &mut t| now.duration_since(t) < GOOD_PING_WINDOW);
        }
        match map.get(&src) {
            Some(&t) if now.duration_since(t) < GOOD_PING_WINDOW => false,
            _ => {
                map.insert(src, now);
                true
            }
        }
    }

    /// Fixed-window limiter: allows up to `CLASS_RATE_PER_SEC` events per class per second.
    fn class_allow(&self, class: &'static str) -> bool {
        let now = Instant::now();
        let mut map = self.class_windows.lock().unwrap();
        let w = map.entry(class).or_insert(ClassWindow { start: now, count: 0 });
        if now.duration_since(w.start) >= Duration::from_secs(1) {
            w.start = now;
            w.count = 0;
        }
        if w.count < CLASS_RATE_PER_SEC {
            w.count += 1;
            true
        } else {
            false
        }
    }
}

/// Best-effort hostname from the environment; `-` (RFC 5424 NILVALUE) when unknown.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

/// Current time as an RFC 3339 / ISO-8601 UTC timestamp with milliseconds.
fn rfc3339_now() -> String {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let tod = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60,
    )
}

/// Converts days since the Unix epoch to a `(year, month, day)` UTC date.
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Renders a JSON array of IP addresses; an empty list (bind to all interfaces) becomes `["*"]`.
fn ip_array(addrs: &[IpAddr]) -> String {
    if addrs.is_empty() {
        return "[\"*\"]".to_string();
    }
    let mut s = String::from("[");
    for (i, a) in addrs.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        json_escape(&a.to_string(), &mut s);
        s.push('"');
    }
    s.push(']');
    s
}

/// Appends `s` to `out` with JSON string escaping.
fn json_escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

/// A minimal JSON object builder for the small, server-controlled event payloads.
struct Json(String);

impl Json {
    fn new() -> Self {
        Self(String::from("{"))
    }

    fn sep(&mut self) {
        if !self.0.ends_with('{') {
            self.0.push(',');
        }
    }

    fn key(&mut self, k: &str) {
        self.0.push('"');
        json_escape(k, &mut self.0);
        self.0.push_str("\":");
    }

    fn str(mut self, k: &str, v: &str) -> Self {
        self.sep();
        self.key(k);
        self.0.push('"');
        json_escape(v, &mut self.0);
        self.0.push('"');
        self
    }

    fn int(mut self, k: &str, v: i64) -> Self {
        self.sep();
        self.key(k);
        self.0.push_str(&v.to_string());
        self
    }

    /// Inserts a pre-rendered JSON value (e.g. an array) verbatim.
    fn raw(mut self, k: &str, v: &str) -> Self {
        self.sep();
        self.key(k);
        self.0.push_str(v);
        self
    }

    fn done(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_epoch_is_formatted() {
        // 1970-01-01T00:00:00 is day 0.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // A known later date: 2026-06-21 is 20625 days after the epoch.
        assert_eq!(civil_from_days(20_625), (2026, 6, 21));
    }

    #[test]
    fn json_escapes_quotes_and_controls() {
        let mut s = String::new();
        json_escape("a\"b\\c\n", &mut s);
        assert_eq!(s, "a\\\"b\\\\c\\n");
    }

    #[test]
    fn json_builder_emits_object() {
        let body = Json::new().str("event", "x").int("n", 3).done();
        assert_eq!(body, r#"{"event":"x","n":3}"#);
    }

    #[test]
    fn ip_array_empty_is_wildcard() {
        assert_eq!(ip_array(&[]), "[\"*\"]");
        let one: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(ip_array(&[one]), "[\"10.0.0.1\"]");
    }
}
