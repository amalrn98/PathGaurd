//! Canary tokens and the honeypot that watches them.
//!
//! A canary token is a unique, non-secret string. It is derived with a MAC
//! under a per-session key, so tokens are unguessable and tied to one session.
//! If a token shows up where it should not (here: a touch on the honeypot),
//! the sender treats the session as exposed. A trigger is an indicator of
//! exposure, not proof of interception.

use crate::crypto::mac;
use crate::util;
use std::collections::{HashMap, HashSet};
use std::fmt;
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
        let token = self.token_for(self.counter);
        self.issued.insert(token.clone(), label.to_string());
        token
    }
    /// The tokens the next `n` calls to [`CanaryIssuer::issue`] will return, without
    /// issuing them. Lets a sender register tokens with an external service
    /// **before** any bait carrying them leaves the machine.
    pub fn preview(&self, n: usize) -> Vec<String> {
        (1..=n as u64).map(|i| self.token_for(self.counter + i)).collect()
    }
    fn token_for(&self, counter: u64) -> String {
        let tag = mac(&self.key, &[b"canary", &counter.to_be_bytes()]);
        format!("{PREFIX}{}", util::hex(&tag[..HEX_LEN / 2]))
    }
    /// Label of a token issued by this session, if any.
    pub fn label_of(&self, token: &str) -> Option<&str> {
        self.issued.get(token).map(String::as_str)
    }
    /// All tokens issued so far, with their labels.
    pub fn issued(&self) -> &HashMap<String, String> {
        &self.issued
    }
}

/// Is `s` exactly one well-formed canary token?
pub fn is_valid_token(s: &str) -> bool {
    s.len() == PREFIX.len() + HEX_LEN
        && s.starts_with(PREFIX)
        && s[PREFIX.len()..].bytes().all(|b| b.is_ascii_hexdigit())
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

/// Why a canary source could not give a trustworthy answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryError {
    /// The source could not be reached or did not answer in time. The path can
    /// **not** be called clean on this basis.
    Unavailable(String),
    /// The answer failed authentication, was stale, or answered a different
    /// question. This is evidence of tampering, not just an outage.
    Untrusted(String),
}

impl fmt::Display for CanaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanaryError::Unavailable(m) => write!(f, "canary source unavailable: {m}"),
            CanaryError::Untrusted(m) => write!(f, "canary source answer not trusted: {m}"),
        }
    }
}

impl std::error::Error for CanaryError {}

/// Where canary touches are observed.
///
/// `Honeypot` is the in-process implementation used by the simulator. A real
/// deployment uses [`crate::canary_service::RemoteCanary`], which asks a
/// separately deployed listener over an authenticated channel.
pub trait CanarySource: Send + Sync {
    /// Tell the source which tokens are about to be used, so it can ignore
    /// everything else. The default does nothing.
    fn register(&self, _tokens: &[String]) -> Result<(), CanaryError> {
        Ok(())
    }
    /// Return hits for exactly these tokens. Hits for other tokens must be left
    /// alone, because they belong to other sessions.
    fn poll(&self, tokens: &HashSet<String>) -> Result<Vec<HoneypotHit>, CanaryError>;
}

/// Shared in-process log of canary touches. Cloning shares state.
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
    /// Remove and return the hits whose token is in `tokens`. All other hits stay,
    /// so concurrent sessions sharing one honeypot cannot consume each other's events.
    pub fn take_matching(&self, tokens: &HashSet<String>) -> Vec<HoneypotHit> {
        let Ok(mut all) = self.hits.lock() else {
            return Vec::new();
        };
        let (mine, rest): (Vec<_>, Vec<_>) =
            std::mem::take(&mut *all).into_iter().partition(|h| tokens.contains(&h.token));
        *all = rest;
        mine
    }
    /// Hits not yet claimed by any session.
    pub fn unclaimed(&self) -> usize {
        self.hits.lock().map(|h| h.len()).unwrap_or(0)
    }
}

impl CanarySource for Honeypot {
    fn poll(&self, tokens: &HashSet<String>) -> Result<Vec<HoneypotHit>, CanaryError> {
        Ok(self.take_matching(tokens))
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
        let want: HashSet<String> = ["t".to_string()].into();
        assert_eq!(h.take_matching(&want).len(), 1);
        assert!(h.take_matching(&want).is_empty());
    }

    #[test]
    fn take_matching_leaves_other_sessions_events() {
        let mut a = CanaryIssuer::new([1; 32]);
        let mut b = CanaryIssuer::new([2; 32]);
        let (ta, tb) = (a.issue("probe"), b.issue("probe"));
        let h = Honeypot::new();
        h.touch(&ta, "x");
        h.touch(&tb, "y");
        let mine: HashSet<String> = a.issued().keys().cloned().collect();
        let got = h.take_matching(&mine);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].token, ta);
        assert_eq!(h.unclaimed(), 1, "B's event must survive A's poll");
    }

    #[test]
    fn preview_matches_issue_and_token_validation() {
        let mut i = CanaryIssuer::new([3; 32]);
        let preview = i.preview(3);
        let issued: Vec<String> = (0..3).map(|_| i.issue("x")).collect();
        assert_eq!(preview, issued);
        assert!(preview.iter().all(|t| is_valid_token(t)));
        assert!(!is_valid_token("pg-canary-zz"));
        assert!(!is_valid_token(&format!("{}x", preview[0])));
    }
}
