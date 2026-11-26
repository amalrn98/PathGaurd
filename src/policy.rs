//! Security policy: which mechanisms run and what must hold before release.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Independently switchable mechanisms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mechanisms {
    /// Mechanism A: probes that detect tampering, duplication, odd timing.
    pub interception_detection: bool,
    /// Mechanism B: plaintext bait carrying canary tokens, watched via a honeypot.
    pub active_decoys: bool,
    /// Mechanism C: verify several paths and require measured path diversity.
    pub multipath: bool,
    /// Mechanism D: encrypted payload-shaped decoys.
    pub payload_like_decoys: bool,
    /// Mechanism E: canary tokens in probes; a trigger invalidates the session.
    pub canary: bool,
}

impl Default for Mechanisms {
    fn default() -> Self {
        Self {
            interception_detection: true,
            active_decoys: false,
            multipath: false,
            payload_like_decoys: false,
            canary: true,
        }
    }
}

/// Verification thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Verification {
    /// Probes sent on each verified path.
    pub probes_per_path: u32,
    /// Minimum number of fully verified paths (multipath only).
    pub min_verified_paths: u32,
    /// Minimum pairwise path diversity in [0, 1] when two or more paths are required.
    pub min_path_diversity: f64,
    /// Withhold when the summed finding weight reaches this value.
    pub max_suspicion_score: f64,
    /// Round-trip time z-score above which a timing finding is recorded.
    pub max_rtt_zscore: f64,
    /// Plaintext length of payload-like decoys.
    pub payload_like_len: u32,
    /// Let a failing secondary path be excluded instead of blocking release.
    pub tolerate_failed_secondary_paths: bool,
}

impl Default for Verification {
    fn default() -> Self {
        Self {
            probes_per_path: 3,
            min_verified_paths: 1,
            min_path_diversity: 0.5,
            max_suspicion_score: 1.0,
            max_rtt_zscore: 4.0,
            payload_like_len: 256,
            tolerate_failed_secondary_paths: false,
        }
    }
}

/// Failure handling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Failure {
    /// Fresh-handshake retries after a withheld attempt. Each retry uses new
    /// ephemeral keys and starts from the next path.
    pub max_retries: u32,
    /// Send an authenticated close so the receiver drops the session keys.
    pub close_session_on_failure: bool,
}

impl Default for Failure {
    fn default() -> Self {
        Self { max_retries: 2, close_session_on_failure: true }
    }
}

/// Complete policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Policy name, recorded in audit output.
    pub name: String,
    /// Mechanism switches.
    pub mechanisms: Mechanisms,
    /// Verification thresholds.
    pub verification: Verification,
    /// Failure handling.
    pub failure: Failure,
}

impl Default for Policy {
    fn default() -> Self {
        Self::balanced()
    }
}

impl Policy {
    /// Authenticated encryption only. No probing.
    pub fn baseline() -> Self {
        Self {
            name: "baseline".into(),
            mechanisms: Mechanisms {
                interception_detection: false,
                active_decoys: false,
                multipath: false,
                payload_like_decoys: false,
                canary: false,
            },
            ..Self::balanced()
        }
    }
    /// Interception detection plus canary tokens on the primary path.
    pub fn balanced() -> Self {
        Self {
            name: "balanced".into(),
            mechanisms: Mechanisms::default(),
            verification: Verification::default(),
            failure: Failure::default(),
        }
    }
    /// Everything on, two independent verified paths required.
    pub fn paranoid() -> Self {
        Self {
            name: "paranoid".into(),
            mechanisms: Mechanisms {
                interception_detection: true,
                active_decoys: true,
                multipath: true,
                payload_like_decoys: true,
                canary: true,
            },
            verification: Verification {
                probes_per_path: 4,
                min_verified_paths: 2,
                tolerate_failed_secondary_paths: true,
                ..Verification::default()
            },
            failure: Failure::default(),
        }
    }
    /// Look up a preset by name.
    pub fn preset(name: &str) -> Option<Self> {
        match name {
            "baseline" => Some(Self::baseline()),
            "balanced" => Some(Self::balanced()),
            "paranoid" => Some(Self::paranoid()),
            _ => None,
        }
    }
    /// Parse and validate a TOML policy.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let p: Policy = toml::from_str(s).map_err(|e| Error::Policy(e.to_string()))?;
        p.validate()?;
        Ok(p)
    }
    /// Serialize to TOML.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("policy is always serializable")
    }
    /// Reject nonsensical values.
    pub fn validate(&self) -> Result<()> {
        let v = &self.verification;
        let bad = |m: &str| Err(Error::Policy(m.to_string()));
        if !(1..=64).contains(&v.probes_per_path) {
            return bad("probes_per_path must be 1..=64");
        }
        if v.min_verified_paths == 0 || v.min_verified_paths > 16 {
            return bad("min_verified_paths must be 1..=16");
        }
        if !(0.0..=1.0).contains(&v.min_path_diversity) {
            return bad("min_path_diversity must be within 0..=1");
        }
        if !v.max_suspicion_score.is_finite() || v.max_suspicion_score < 0.0 {
            return bad("max_suspicion_score must be a non-negative number");
        }
        if !v.max_rtt_zscore.is_finite() || v.max_rtt_zscore <= 0.0 {
            return bad("max_rtt_zscore must be positive");
        }
        if !(16..=16384).contains(&v.payload_like_len) {
            return bad("payload_like_len must be 16..=16384");
        }
        if self.failure.max_retries > 10 {
            return bad("max_retries must be at most 10");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_validate_and_roundtrip() {
        for name in ["baseline", "balanced", "paranoid"] {
            let p = Policy::preset(name).unwrap();
            p.validate().unwrap();
            assert_eq!(Policy::from_toml_str(&p.to_toml()).unwrap(), p);
        }
    }

    #[test]
    fn partial_toml_uses_defaults() {
        let p = Policy::from_toml_str("[mechanisms]\nmultipath = true\n").unwrap();
        assert!(p.mechanisms.multipath);
        assert!(p.mechanisms.interception_detection);
    }

    #[test]
    fn rejects_unknown_and_invalid() {
        assert!(Policy::from_toml_str("[mechanisms]\nbogus = true\n").is_err());
        assert!(Policy::from_toml_str("[verification]\nprobes_per_path = 0\n").is_err());
        assert!(Policy::from_toml_str("[verification]\nmin_path_diversity = 2.0\n").is_err());
    }
}
