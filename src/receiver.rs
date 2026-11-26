//! Receiver state machine.
//!
//! The receiver never panics on network input. Every malformed or
//! unauthenticated request yields a `Reject`.

use crate::clock::{Clock, SystemClock};
use crate::crypto::{
    self, derive_session_keys, mac, mac_verify, sha256, Ephemeral, Identity, PublicIdentity, SessionKeys,
};
use crate::error::{Error, Result};
use crate::handshake::{ack_input, hello_input, transcript};
use crate::message::{Message, ProbeId, ProbeKind, RejectCode, SessionId};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use zeroize::Zeroize;

const MAX_SEEN_PROBES: usize = 4096;

/// Resource and freshness limits of a receiver.
///
/// The defaults are the safe values. Every field can be **lowered** freely, but
/// `validate` rejects values above a hard ceiling, so configuration cannot
/// weaken the receiver beyond what the protocol allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverConfig {
    /// Accepted difference between a hello timestamp and the receiver clock.
    pub max_clock_skew_secs: u64,
    /// Absolute lifetime of a session. Expired sessions are reclaimed.
    pub session_ttl_secs: u64,
    /// Concurrent sessions across all senders.
    pub max_sessions: usize,
    /// Concurrent sessions per sender identity.
    pub max_sessions_per_sender: usize,
    /// Length of the handshake rate-limit window.
    pub handshake_window_secs: u64,
    /// Hellos processed per window. Further hellos get `Busy` until the window rolls.
    pub max_handshakes_per_window: u32,
    /// Accepted hellos remembered to stop replay inside the freshness window.
    pub replay_cache_capacity: usize,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            max_clock_skew_secs: 120,
            session_ttl_secs: 300,
            max_sessions: 1024,
            max_sessions_per_sender: 16,
            handshake_window_secs: 10,
            max_handshakes_per_window: 256,
            replay_cache_capacity: 16_384,
        }
    }
}

impl ReceiverConfig {
    /// Hard ceilings. A configuration above any of these is invalid.
    pub const SKEW_CEILING: u64 = 300;
    /// Hard ceiling for `session_ttl_secs`.
    pub const TTL_CEILING: u64 = 3_600;
    /// Hard ceiling for `max_sessions`.
    pub const SESSIONS_CEILING: usize = 65_536;
    /// Hard ceiling for `replay_cache_capacity`.
    pub const REPLAY_CEILING: usize = 1 << 20;

    /// Check every field against its floor (1) and ceiling.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::Policy(format!("receiver config: {m}")));
        if self.max_clock_skew_secs == 0 || self.max_clock_skew_secs > Self::SKEW_CEILING {
            return bad("max_clock_skew_secs must be 1..=300");
        }
        if self.session_ttl_secs == 0 || self.session_ttl_secs > Self::TTL_CEILING {
            return bad("session_ttl_secs must be 1..=3600");
        }
        if self.max_sessions == 0 || self.max_sessions > Self::SESSIONS_CEILING {
            return bad("max_sessions must be 1..=65536");
        }
        if self.max_sessions_per_sender == 0 || self.max_sessions_per_sender > self.max_sessions {
            return bad("max_sessions_per_sender must be 1..=max_sessions");
        }
        if self.handshake_window_secs == 0 || self.handshake_window_secs > 3_600 {
            return bad("handshake_window_secs must be 1..=3600");
        }
        if self.max_handshakes_per_window == 0 {
            return bad("max_handshakes_per_window must be at least 1");
        }
        if self.replay_cache_capacity == 0 || self.replay_cache_capacity > Self::REPLAY_CEILING {
            return bad("replay_cache_capacity must be 1..=1048576");
        }
        Ok(())
    }
}

struct RecvSession {
    created_at: u64,
    sender: [u8; 32],
    keys: SessionKeys,
    last_seq: u64,
    seen_probes: HashSet<ProbeId>,
}

/// AAD binding a payload to its session, receiver and sequence number.
pub fn payload_aad(session_id: &SessionId, recipient: &[u8; 32], seq: u64) -> Vec<u8> {
    let mut v = b"pathguard/v1/payload".to_vec();
    v.extend_from_slice(session_id);
    v.extend_from_slice(recipient);
    v.extend_from_slice(&seq.to_be_bytes());
    v
}

/// Who may open sessions with a receiver.
///
/// Authentication (a valid Ed25519 signature) proves which key signed the hello.
/// Authorization decides whether that key is allowed to send to this receiver.
/// They are separate checks, and a receiver is **deny-by-default**: until a
/// policy is configured, no sender is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SenderPolicy {
    /// Accept nobody. The default.
    #[default]
    DenyAll,
    /// Accept only these sender identities.
    AllowList(HashSet<[u8; 32]>),
    /// Accept any sender that proves possession of its key. Only appropriate for
    /// public services or tests, because it provides authentication without
    /// authorization.
    AllowAnyAuthenticated,
}

impl SenderPolicy {
    /// Is this sender identity authorized?
    pub fn permits(&self, sender: &[u8; 32]) -> bool {
        match self {
            SenderPolicy::DenyAll => false,
            SenderPolicy::AllowList(set) => set.contains(sender),
            SenderPolicy::AllowAnyAuthenticated => true,
        }
    }
}

/// Counters describing what the receiver has refused. Local only: nothing here
/// is sent over the network, so it does not give a remote attacker an oracle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiverStats {
    /// Hellos with a valid signature from an identity the policy does not permit.
    pub rejected_unauthorized: u64,
    /// Hellos outside the freshness window.
    pub rejected_stale: u64,
    /// Hellos replayed inside the freshness window.
    pub rejected_replayed_hello: u64,
    /// Hellos refused by the handshake rate limit.
    pub rejected_rate_limited: u64,
    /// Hellos refused because a session or replay-cache cap was reached.
    pub rejected_capacity: u64,
    /// Sessions reclaimed after their lifetime ended.
    pub sessions_expired: u64,
}

/// Receiver endpoint.
pub struct Receiver {
    identity: Identity,
    policy: SenderPolicy,
    config: ReceiverConfig,
    clock: Arc<dyn Clock>,
    stats: ReceiverStats,
    /// Digest of each accepted hello, with the time after which it is stale anyway.
    replay_cache: HashMap<[u8; 32], u64>,
    window_start: u64,
    window_count: u32,
    last_sweep: u64,
    sessions: HashMap<SessionId, RecvSession>,
    delivered: Vec<Vec<u8>>,
}

impl Receiver {
    /// New receiver. It is **deny-by-default**: configure who may send with
    /// [`Receiver::allow_sender`] or [`Receiver::set_sender_policy`].
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            policy: SenderPolicy::DenyAll,
            config: ReceiverConfig::default(),
            clock: Arc::new(SystemClock),
            stats: ReceiverStats::default(),
            replay_cache: HashMap::new(),
            window_start: 0,
            window_count: 0,
            last_sweep: 0,
            sessions: HashMap::new(),
            delivered: Vec::new(),
        }
    }
    /// Use a specific clock (tests and simulation).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
    /// Use explicit limits. Fails if any value is outside its allowed range.
    pub fn with_config(mut self, config: ReceiverConfig) -> Result<Self> {
        config.validate()?;
        self.config = config;
        Ok(self)
    }
    /// Active limits.
    pub fn config(&self) -> &ReceiverConfig {
        &self.config
    }
    /// Reclaim expired sessions and stale replay-cache entries now. Called
    /// automatically (at most once per second) on every request.
    pub fn maintain(&mut self) {
        let now = self.clock.unix_secs();
        self.sweep(now);
    }
    fn sweep(&mut self, now: u64) {
        if now == self.last_sweep {
            return;
        }
        self.last_sweep = now;
        let ttl = self.config.session_ttl_secs;
        let before = self.sessions.len();
        self.sessions.retain(|_, s| s.created_at.saturating_add(ttl) > now);
        self.stats.sessions_expired += (before - self.sessions.len()) as u64;
        self.replay_cache.retain(|_, expires| *expires > now);
    }
    /// Replace the authorization policy. Sessions of senders the new policy no
    /// longer permits are closed immediately.
    pub fn set_sender_policy(&mut self, policy: SenderPolicy) {
        self.policy = policy;
        let policy = &self.policy;
        self.sessions.retain(|_, s| policy.permits(&s.sender));
    }
    /// Permit one sender identity. If the current policy is not an allow-list
    /// (deny-all, or allow-any-authenticated), it becomes an allow-list
    /// containing just this identity, so calling this never widens access.
    pub fn allow_sender(&mut self, sender: PublicIdentity) {
        match &mut self.policy {
            SenderPolicy::AllowList(set) => {
                set.insert(sender.0);
            }
            other => *other = SenderPolicy::AllowList(HashSet::from([sender.0])),
        }
    }
    /// Remove a sender from the allow-list (key revocation or rotation) and
    /// close its live sessions. Returns false if the identity was not listed.
    pub fn revoke_sender(&mut self, sender: &PublicIdentity) -> bool {
        let removed = match &mut self.policy {
            SenderPolicy::AllowList(set) => set.remove(&sender.0),
            _ => false,
        };
        self.sessions.retain(|_, s| s.sender != sender.0);
        removed
    }
    /// Accept any sender that proves possession of its key. Explicit opt-out of
    /// authorization; see [`SenderPolicy::AllowAnyAuthenticated`].
    pub fn allow_any_authenticated_sender(&mut self) {
        self.policy = SenderPolicy::AllowAnyAuthenticated;
    }
    /// Current authorization policy.
    pub fn sender_policy(&self) -> &SenderPolicy {
        &self.policy
    }
    /// Accepted hellos currently remembered for replay protection.
    pub fn replay_cache_len(&self) -> usize {
        self.replay_cache.len()
    }
    /// Refusal counters.
    pub fn stats(&self) -> &ReceiverStats {
        &self.stats
    }
    /// Receiver public identity.
    pub fn public(&self) -> PublicIdentity {
        self.identity.public()
    }
    /// Take payloads delivered so far.
    pub fn take_delivered(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.delivered)
    }
    /// Number of live sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Handle one request and return the encoded response.
    pub fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        let now = self.clock.unix_secs();
        self.sweep(now);
        let reply = match Message::decode(request) {
            Ok(m) => match self.dispatch(m, now) {
                Ok(r) => r,
                Err(code) => Message::Reject { code },
            },
            Err(_) => Message::Reject { code: RejectCode::BadRequest },
        };
        reply.encode()
    }

    fn dispatch(&mut self, msg: Message, now: u64) -> std::result::Result<Message, RejectCode> {
        match msg {
            Message::Hello { session_id, timestamp, sender_eph, sender_id, recipient, sig } => {
                let me = self.identity.public().0;
                if recipient != me {
                    return Err(RejectCode::AuthFailed);
                }
                // Cheap checks first, so unauthenticated traffic costs little.
                // 1. Freshness: the timestamp is signed, so a captured hello is only
                //    replayable inside this window.
                if timestamp.abs_diff(now) > self.config.max_clock_skew_secs {
                    self.stats.rejected_stale += 1;
                    return Err(RejectCode::Stale);
                }
                // 2. Global handshake rate limit (fixed window). Unauthenticated
                //    traffic can use up the window; see the threat model.
                if now.saturating_sub(self.window_start) >= self.config.handshake_window_secs {
                    self.window_start = now;
                    self.window_count = 0;
                }
                if self.window_count >= self.config.max_handshakes_per_window {
                    self.stats.rejected_rate_limited += 1;
                    return Err(RejectCode::Busy);
                }
                self.window_count += 1;
                // 3. Replay: a hello that was already accepted stays rejected for as
                //    long as its timestamp is still fresh, even after its session closed.
                let hi = hello_input(&session_id, timestamp, &sender_eph, &sender_id, &recipient);
                let digest = sha256(&[&hi]);
                if self.sessions.contains_key(&session_id) || self.replay_cache.contains_key(&digest) {
                    self.stats.rejected_replayed_hello += 1;
                    return Err(RejectCode::Replay);
                }
                // 4. Capacity. Fail closed: refuse new sessions rather than evict
                //    live ones, so a flood cannot push out legitimate sessions.
                if self.sessions.len() >= self.config.max_sessions
                    || self.replay_cache.len() >= self.config.replay_cache_capacity
                {
                    self.stats.rejected_capacity += 1;
                    return Err(RejectCode::Busy);
                }
                // 5. Authentication, then authorization, before any key agreement.
                if !PublicIdentity(sender_id).verify(&hi, &sig) {
                    return Err(RejectCode::AuthFailed);
                }
                if !self.policy.permits(&sender_id) {
                    self.stats.rejected_unauthorized += 1;
                    return Err(RejectCode::AuthFailed);
                }
                if self.sessions.values().filter(|s| s.sender == sender_id).count()
                    >= self.config.max_sessions_per_sender
                {
                    self.stats.rejected_capacity += 1;
                    return Err(RejectCode::Busy);
                }
                let eph = Ephemeral::generate();
                let recv_eph = eph.public;
                let ai = ack_input(&sha256(&[&hi]), &session_id, &recv_eph, &me);
                let ack_sig = self.identity.sign(&ai);
                let mut shared = eph.agree(&sender_eph).map_err(|_| RejectCode::AuthFailed)?;
                let keys = derive_session_keys(&shared, &transcript(&hi, &ai));
                shared.zeroize();
                // Remember the hello until it would be rejected as stale anyway.
                self.replay_cache
                    .insert(digest, timestamp.saturating_add(self.config.max_clock_skew_secs).saturating_add(1));
                self.sessions.insert(
                    session_id,
                    RecvSession { created_at: now, sender: sender_id, keys, last_seq: 0, seen_probes: HashSet::new() },
                );
                Ok(Message::HelloAck { session_id, recv_eph, recv_id: me, sig: ack_sig })
            }
            Message::Probe { session_id, probe_id, kind, seq, body, mac: tag } => {
                let s = self.sessions.get_mut(&session_id).ok_or(RejectCode::UnknownSession)?;
                let parts: [&[u8]; 6] = [b"probe", &session_id, &probe_id, &[kind as u8], &seq.to_be_bytes(), &body];
                if !mac_verify(&s.keys.probe, &parts, &tag) {
                    return Err(RejectCode::AuthFailed);
                }
                if s.seen_probes.len() >= MAX_SEEN_PROBES || !s.seen_probes.insert(probe_id) {
                    return Err(RejectCode::Replay);
                }
                let content = if kind == ProbeKind::PayloadLike {
                    let nonce = decoy_nonce(&probe_id);
                    crypto::open(&s.keys.decoy, &nonce, &session_id, &body).map_err(|_| RejectCode::AuthFailed)?
                } else {
                    body
                };
                let reply = reply_mac(&s.keys.probe, &session_id, &probe_id, seq, &content);
                Ok(Message::ProbeReply { session_id, probe_id, seq, mac: reply })
            }
            Message::Payload { session_id, seq, ciphertext } => {
                let me = self.identity.public().0;
                let s = self.sessions.get_mut(&session_id).ok_or(RejectCode::UnknownSession)?;
                if seq == 0 || seq <= s.last_seq {
                    return Err(RejectCode::Replay);
                }
                let aad = payload_aad(&session_id, &me, seq);
                let plain = crypto::open(&s.keys.payload, &crypto::seq_nonce(seq), &aad, &ciphertext)
                    .map_err(|_| RejectCode::AuthFailed)?;
                s.last_seq = seq;
                let ack = ack_mac(&s.keys.probe, &session_id, seq, &ciphertext);
                self.delivered.push(plain);
                Ok(Message::PayloadAck { session_id, seq, mac: ack })
            }
            Message::Close { session_id, mac: tag } => {
                let s = self.sessions.get(&session_id).ok_or(RejectCode::UnknownSession)?;
                if !mac_verify(&s.keys.probe, &[b"close", &session_id], &tag) {
                    return Err(RejectCode::AuthFailed);
                }
                self.sessions.remove(&session_id);
                Ok(Message::Close { session_id, mac: [0; 32] })
            }
            _ => Err(RejectCode::BadRequest),
        }
    }
}

/// Nonce for payload-like decoys: the first 12 bytes of the unique probe id.
pub fn decoy_nonce(probe_id: &ProbeId) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(&probe_id[..12]);
    n
}

/// MAC a receiver returns for a probe.
pub fn reply_mac(key: &[u8; 32], session_id: &SessionId, probe_id: &ProbeId, seq: u64, content: &[u8]) -> [u8; 32] {
    mac(key, &[b"reply", session_id, probe_id, &seq.to_be_bytes(), &sha256(&[content])])
}

/// MAC a receiver returns for a delivered payload.
pub fn ack_mac(key: &[u8; 32], session_id: &SessionId, seq: u64, ciphertext: &[u8]) -> [u8; 32] {
    mac(key, &[b"ack", session_id, &seq.to_be_bytes(), &sha256(&[ciphertext])])
}

/// MAC authorizing a session close.
pub fn close_mac(key: &[u8; 32], session_id: &SessionId) -> [u8; 32] {
    mac(key, &[b"close", session_id])
}
