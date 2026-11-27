//! Interception indicators and scoring.
//!
//! Findings are evidence, not verdicts. Hard cryptographic failures are
//! `Critical`. Timing and duplication are weak signals and carry small weights.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

/// How strong a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Weak signal (timing).
    Low,
    /// Plausibly benign alone (loss, duplication).
    Medium,
    /// Cryptographic failure or direct evidence of exposure.
    Critical,
}

impl Severity {
    /// Contribution to the suspicion score.
    pub fn weight(self) -> f64 {
        match self {
            Severity::Low => 0.25,
            Severity::Medium => 0.5,
            Severity::Critical => 100.0,
        }
    }
}

/// What was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// Handshake failed (wrong identity, bad signature, rejection).
    HandshakeFailure,
    /// Probe reply MAC did not verify.
    ReplyAuthFailure,
    /// Reply could not be parsed or answered a different probe.
    MalformedReply,
    /// Receiver rejected an authentic probe, so it was altered in transit.
    ProbeRejected,
    /// More than one reply to a single probe.
    DuplicateReply,
    /// No reply (loss, drop, timeout).
    NoReply,
    /// Round-trip time far above the path baseline.
    TimingAnomaly,
    /// A canary token was touched.
    CanaryTriggered,
    /// The canary source could not be reached, or its answer was not authentic.
    CanarySourceFailure,
}

/// One observation.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Kind.
    pub kind: FindingKind,
    /// Severity.
    pub severity: Severity,
    /// Path id, or `session` for session-level findings.
    pub path: String,
    /// Human-readable detail.
    pub detail: String,
}

impl Finding {
    /// Build a finding.
    pub fn new(kind: FindingKind, severity: Severity, path: &str, detail: impl Into<String>) -> Self {
        Self { kind, severity, path: path.to_string(), detail: detail.into() }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {:?} on {}: {}", self.severity, self.kind, self.path, self.detail)
    }
}

/// Sum of finding weights.
pub fn score<'a>(findings: impl IntoIterator<Item = &'a Finding>) -> f64 {
    findings.into_iter().fold(0.0, |acc, f| acc + f.severity.weight())
}

/// Collapse repeated findings of the same kind on the same path, keeping the
/// first occurrence and a count. Order of first appearance is preserved.
pub fn summarize<'a>(findings: impl IntoIterator<Item = &'a Finding>) -> Vec<(&'a Finding, usize)> {
    let mut out: Vec<(&Finding, usize)> = Vec::new();
    for f in findings {
        match out.iter_mut().find(|(g, _)| g.kind == f.kind && g.path == f.path) {
            Some((_, n)) => *n += 1,
            None => out.push((f, 1)),
        }
    }
    out
}

#[derive(Default)]
struct Welford {
    n: u32,
    mean: f64,
    m2: f64,
}

/// Per-path round-trip time baseline using Welford's online algorithm.
pub struct Detector {
    max_z: f64,
    min_samples: u32,
    base: HashMap<String, Welford>,
}

impl Detector {
    /// New detector flagging samples above `max_z` standard deviations.
    pub fn new(max_z: f64) -> Self {
        Self { max_z, min_samples: 2, base: HashMap::new() }
    }

    /// Record an RTT sample. Returns a `Low` finding when it is far above the
    /// baseline. The deviation has a floor (10% of the mean, at least 1 ms) so
    /// very stable links do not produce spurious alerts.
    pub fn observe_rtt(&mut self, path: &str, rtt: Duration) -> Option<Finding> {
        let x = rtt.as_secs_f64() * 1000.0;
        let w = self.base.entry(path.to_string()).or_default();
        let mut out = None;
        if w.n >= self.min_samples {
            let var = w.m2 / (w.n as f64 - 1.0);
            let sd = var.sqrt().max(0.1 * w.mean).max(1.0);
            let z = (x - w.mean) / sd;
            if z > self.max_z {
                out = Some(Finding::new(
                    FindingKind::TimingAnomaly,
                    Severity::Low,
                    path,
                    format!("rtt {x:.1} ms is {z:.1} deviations above baseline {:.1} ms", w.mean),
                ));
            }
        }
        w.n += 1;
        let d = x - w.mean;
        w.mean += d / w.n as f64;
        w.m2 += d * (x - w.mean);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_spike_not_jitter() {
        let mut d = Detector::new(4.0);
        let ms = |v: f64| Duration::from_secs_f64(v / 1000.0);
        assert!(d.observe_rtt("p", ms(20.0)).is_none());
        assert!(d.observe_rtt("p", ms(21.0)).is_none());
        assert!(d.observe_rtt("p", ms(19.5)).is_none());
        assert!(d.observe_rtt("p", ms(80.0)).is_some());
    }

    #[test]
    fn summarize_groups_repeats() {
        let f = vec![
            Finding::new(FindingKind::NoReply, Severity::Medium, "p", "a"),
            Finding::new(FindingKind::NoReply, Severity::Medium, "p", "b"),
            Finding::new(FindingKind::NoReply, Severity::Medium, "q", "c"),
        ];
        let s = summarize(&f);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].1, 2);
    }

    #[test]
    fn empty_score_is_positive_zero() {
        assert!(score(&[]).is_sign_positive());
    }

    #[test]
    fn score_sums_weights() {
        let f = vec![
            Finding::new(FindingKind::NoReply, Severity::Medium, "p", ""),
            Finding::new(FindingKind::TimingAnomaly, Severity::Low, "p", ""),
        ];
        assert!((score(&f) - 0.75).abs() < 1e-9);
    }
}
