use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{Level, Log, Metadata, Record};

/// Toggled at runtime (SIGUSR1 on Unix) to turn debug output on/off without restarting.
pub static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

/// Writes `<unix-seconds> [LEVEL] message` to stderr.
/// Debug messages are suppressed unless `DEBUG_ENABLED` is set.
pub struct DynamicLogger;

impl Log for DynamicLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if metadata.level() == Level::Debug {
            DEBUG_ENABLED.load(Ordering::Relaxed)
        } else {
            metadata.level() <= Level::Info
        }
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            eprintln!("{} [{}] {}", now, record.level(), record.args());
        }
    }

    fn flush(&self) {}
}
