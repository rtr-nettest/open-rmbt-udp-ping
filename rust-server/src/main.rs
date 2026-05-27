//! UDP Ping Server
//!
//! Listens on one or more IP addresses and responds to `RP01` ping packets.
//! Optional HMAC-SHA256 authentication verifies both the packet timestamp and
//! the source IP address to prevent spoofing and replay attacks.

mod config;
mod logger;
mod packet;
mod server;

use log::LevelFilter;

fn main() {
    // Install logger first so that messages from Config::from_args() are visible.
    log::set_boxed_logger(Box::new(logger::DynamicLogger)).unwrap();
    log::set_max_level(LevelFilter::Debug);

    let config = config::Config::from_args();

    // On Unix, SIGUSR1 toggles DEBUG_ENABLED at runtime without restarting the server.
    #[cfg(unix)]
    setup_signal_handler();

    server::Server::bind(config)
        .expect("Failed to bind server sockets")
        .run();
}

/// Spawns a background thread that listens for SIGUSR1 and flips `logger::DEBUG_ENABLED`.
#[cfg(unix)]
fn setup_signal_handler() {
    use logger::DEBUG_ENABLED;
    use signal_hook::consts::SIGUSR1;
    use signal_hook::iterator::Signals;
    use std::sync::atomic::Ordering;

    let mut signals = Signals::new([SIGUSR1]).expect("Failed to register SIGUSR1 handler");
    std::thread::spawn(move || {
        for _ in signals.forever() {
            let prev = DEBUG_ENABLED.fetch_xor(true, Ordering::Relaxed);
            eprintln!("Debug logging {}", if !prev { "enabled" } else { "disabled" });
        }
    });
}
