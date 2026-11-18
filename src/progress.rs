use std::io::{self, Write};
use std::time::Instant;

/// A lightweight, zero-dependency terminal progress bar with transfer rate and ETA.
pub struct ProgressBar {
    total: u64,
    current: u64,
    bytes_processed: u64,
    start_time: Instant,
    last_draw: Instant,
    prefix: String,
    width: usize,
}

impl ProgressBar {
    pub fn new(total: u64, prefix: &str) -> Self {
        let now = Instant::now();
        Self {
            total,
            current: 0,
            bytes_processed: 0,
            start_time: now,
            last_draw: now,
            prefix: prefix.to_string(),
            width: 28,
        }
    }

    pub fn update(&mut self, current: u64, add_bytes: u64) {
        self.current = current;
        self.bytes_processed += add_bytes;
        if self.last_draw.elapsed().as_millis() > 30 || current == self.total {
            self.draw();
            self.last_draw = Instant::now();
        }
    }

    pub fn draw(&self) {
        let ratio = if self.total > 0 {
            (self.current as f64 / self.total as f64).clamp(0.0, 1.0)
        } else {
            1.0
        };

        let filled = (ratio * self.width as f64) as usize;
        let empty = self.width.saturating_sub(filled);

        let elapsed = self.start_time.elapsed().as_secs_f64();
        let speed_str = if elapsed > 0.05 && self.bytes_processed > 0 {
            let bps = self.bytes_processed as f64 / elapsed;
            format_speed(bps)
        } else {
            String::new()
        };

        let bar_filled = "━".repeat(filled);
        let bar_empty = "─".repeat(empty);

        print!(
            "\r\x1b[2K   {} \x1b[36m[{}{}]\x1b[0m {:>3.0}% ({}/{}) {}",
            self.prefix,
            bar_filled,
            bar_empty,
            ratio * 100.0,
            self.current,
            self.total,
            speed_str
        );
        let _ = io::stdout().flush();
    }

    pub fn finish(&self, msg: &str) {
        let elapsed = self.start_time.elapsed();
        let total_size = if self.bytes_processed > 0 {
            format!(" • {}", format_bytes(self.bytes_processed))
        } else {
            String::new()
        };
        println!(
            "\r\x1b[2K   {} \x1b[32m[Done in {:.2?}]{}\x1b[0m",
            msg,
            elapsed,
            total_size
        );
        let _ = io::stdout().flush();
    }
}

/// A lightweight animated step indicator for memory-hard operations.
pub struct StepIndicator {
    start_time: Instant,
}

impl StepIndicator {
    pub fn start(prefix: &str) -> Self {
        print!("   \x1b[33m⠋\x1b[0m {}", prefix);
        let _ = io::stdout().flush();
        Self {
            start_time: Instant::now(),
        }
    }

    pub fn done(&self, msg: &str) {
        let elapsed = self.start_time.elapsed();
        println!(
            "\r\x1b[2K   {} \x1b[32m[Done in {:.2?}]\x1b[0m",
            msg,
            elapsed
        );
        let _ = io::stdout().flush();
    }
}

fn format_speed(bps: f64) -> String {
    if bps >= 1024.0 * 1024.0 * 1024.0 {
        format!("• {:.1} GB/s", bps / (1024.0 * 1024.0 * 1024.0))
    } else if bps >= 1024.0 * 1024.0 {
        format!("• {:.1} MB/s", bps / (1024.0 * 1024.0))
    } else if bps >= 1024.0 {
        format!("• {:.1} KB/s", bps / 1024.0)
    } else {
        format!("• {:.0} B/s", bps)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
