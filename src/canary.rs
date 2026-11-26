//! Canary tokens and the honeypot that watches them.
//!
//! A canary token is a unique, non-secret string. It is derived with a MAC
//! under a per-session key, so tokens are unguessable and tied to one session.
//! If a token shows up where it should not (here: a touch on the honeypot),
//! the sender treats the session as exposed. A trigger is an indicator of
//! exposure, not proof of interception.

use crate::crypto::mac;
use crate::util;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Prefix of every canary token.
pub const PREFIX: &str = "pg-canary-";
const HEX_LEN: usize = 24;

/// Issues canary tokens for one session.
pub struct CanaryIssuer {
    key: [u8; 32],
    counter: u64,
    issued: HashMap<String, String>,
}

impl CanaryIssuer {
    /// New issuer from the session canary key.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, counter: 0, issued: HashMap::new() }
    }
    /// Issue a token tagged with a label (for the audit log).
    pub fn issue(&mut self, label: &str) -> String {
        self.counter += 1;
        let tag = mac(&self.key, &[b"canary", &self.counter.to_be_bytes()]);
        let token = format!("{PREFIX}{}", util::hex(&tag[..HEX_LEN / 2]));
        self.issued.insert(token.clone(), label.to_string());
        token
    }
    /// Label of a token issued by this session, if any.
    pub fn label_of(&self, token: &str) -> Option<&str> {
        self.issued.get(token).map(String::as_str)
    }
}

impl Drop for CanaryIssuer {
    fn drop(&mut self) {
        self.key = [0; 32];
    }
}

/// Find canary-shaped tokens inside arbitrary bytes.
pub fn scan(data: &[u8]) -> Vec<String> {
    let p = PREFIX.as_bytes();
    let total = p.len() + HEX_LEN;
    let mut out = Vec::new();
    let mut i = 0;
    while i + total <= data.len() {
        if &data[i..i + p.len()] == p && data[i + p.len()..i + total].iter().all(u8::is_ascii_hexdigit) {
            out.push(String::from_utf8_lossy(&data[i..i + total]).into_owned());
            i += total;
        } else {
            i += 1;
        }
    }
    out
}

/// One recorded interaction with a canary token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneypotHit {
    /// Token that was touched.
    pub token: String,
    /// Description of where the touch came from.
    pub source: String,
}

/// Shared log of canary touches. In a deployment this would be backed by a
/// real listener (a bait URL, a fake credential endpoint). Cloning shares state.
#[derive(Clone, Default)]
pub struct Honeypot {
    hits: Arc<Mutex<Vec<HoneypotHit>>>,
}

impl Honeypot {
    /// New empty honeypot.
    pub fn new() -> Self {
        Self::default()
    }
    /// Record a touch.
    pub fn touch(&self, token: &str, source: &str) {
        if let Ok(mut h) = self.hits.lock() {
            h.push(HoneypotHit { token: token.to_string(), source: source.to_string() });
        }
    }
    /// Take all recorded hits.
    pub fn drain(&self) -> Vec<HoneypotHit> {
        self.hits.lock().map(|mut h| std::mem::take(&mut *h)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_scan_label() {
        let mut i = CanaryIssuer::new([5; 32]);
        let a = i.issue("bait");
        let b = i.issue("probe");
        assert_ne!(a, b);
        let text = format!("x {a} y {b} z");
        assert_eq!(scan(text.as_bytes()), vec![a.clone(), b]);
        assert_eq!(i.label_of(&a), Some("bait"));
        assert!(scan(b"pg-canary-nothex!!!!!!!!!!!!!!!!!").is_empty());
    }

    #[test]
    fn honeypot_shares_state() {
        let h = Honeypot::new();
        let h2 = h.clone();
        h2.touch("t", "attacker");
        assert_eq!(h.drain().len(), 1);
        assert!(h.drain().is_empty());
    }
}
