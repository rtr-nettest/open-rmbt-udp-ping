use std::time::Duration;

pub struct RttStats {
    rtts: Vec<f64>,
}

impl RttStats {
    pub fn new() -> Self {
        Self { rtts: Vec::new() }
    }

    pub fn add(&mut self, rtt_ms: f64) {
        self.rtts.push(rtt_ms);
    }

    pub fn received(&self) -> usize {
        self.rtts.len()
    }

    pub fn print_summary(&self, sent: u32, elapsed: Duration, host: &str) {
        let received = self.received();
        let loss = if sent > 0 {
            100.0 * (1.0 - received as f64 / sent as f64)
        } else {
            0.0
        };
        println!("\n--- {host} ping statistics ---");
        println!(
            "{sent} packets transmitted, {received} received, \
             {loss:.1}% packet loss, time {}ms",
            elapsed.as_millis()
        );
        if received > 0 {
            let min = self.rtts.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = self.rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let avg = self.rtts.iter().sum::<f64>() / received as f64;
            let mdev = (self.rtts.iter().map(|&x| (x - avg).powi(2)).sum::<f64>()
                / received as f64)
                .sqrt();
            println!("rtt min/avg/max/mdev = {min:.3}/{avg:.3}/{max:.3}/{mdev:.3} ms");
        }
    }
}
