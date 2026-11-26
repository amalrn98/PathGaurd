//! Time source.
//!
//! The protocol uses wall-clock seconds in exactly one place: hello freshness
//! and session expiry. Injecting the clock keeps tests and the simulator
//! deterministic and makes the time dependence explicit.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    /// Current time in whole seconds.
    fn unix_secs(&self) -> u64;
}

/// The operating system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }
}

/// A clock you advance by hand. Clones share the same time.
#[derive(Debug, Clone)]
pub struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    /// Start at `start` seconds.
    pub fn new(start: u64) -> Self {
        Self(Arc::new(AtomicU64::new(start)))
    }
    /// Move forward.
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
    /// Jump to an absolute time.
    pub fn set(&self, secs: u64) {
        self.0.store(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn unix_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_clones_share_time() {
        let a = ManualClock::new(100);
        let b = a.clone();
        a.advance(5);
        assert_eq!(b.unix_secs(), 105);
        b.set(7);
        assert_eq!(a.unix_secs(), 7);
    }

    #[test]
    fn system_clock_is_after_2024() {
        assert!(SystemClock.unix_secs() > 1_700_000_000);
    }
}
