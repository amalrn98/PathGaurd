//! Receiver state machine.
//!
//! The receiver never panics on network input. Every malformed or
//! unauthenticated request yields a `Reject`.

use crate::crypto::{
    self, derive_session_keys, mac, mac_verify, sha256, Ephemeral, Identity, PublicIdentity, SessionKeys,
};
use crate::handshake::{ack_input, hello_input, transcript};
use crate::message::{Message, ProbeId, ProbeKind, RejectCode, SessionId};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroize;

const MAX_SESSIONS: usize = 1024;
const MAX_SEEN_PROBES: usize = 4096;

struct RecvSession {
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
}

/// Receiver endpoint.
pub struct Receiver {
    identity: Identity,
    policy: SenderPolicy,
    stats: ReceiverStats,
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
            stats: ReceiverStats::default(),
            sessions: HashMap::new(),
            delivered: Vec::new(),
        }
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
        let reply = match Message::decode(request) {
            Ok(m) => match self.dispatch(m) {
                Ok(r) => r,
                Err(code) => Message::Reject { code },
            },
            Err(_) => Message::Reject { code: RejectCode::BadRequest },
        };
        reply.encode()
    }

    fn dispatch(&mut self, msg: Message) -> Result<Message, RejectCode> {
        match msg {
            Message::Hello { session_id, sender_eph, sender_id, recipient, sig } => {
                let me = self.identity.public().0;
                if recipient != me {
                    return Err(RejectCode::AuthFailed);
                }
                if self.sessions.contains_key(&session_id) {
                    return Err(RejectCode::Replay);
                }
                if self.sessions.len() >= MAX_SESSIONS {
                    return Err(RejectCode::Busy);
                }
                let hi = hello_input(&session_id, &sender_eph, &sender_id, &recipient);
                if !PublicIdentity(sender_id).verify(&hi, &sig) {
                    return Err(RejectCode::AuthFailed);
                }
                // Authorization is checked after authentication and before any key
                // agreement or session state is created. The wire reply is the same
                // as for a bad signature, so a remote party learns nothing about
                // which identities are trusted.
                if !self.policy.permits(&sender_id) {
                    self.stats.rejected_unauthorized += 1;
                    return Err(RejectCode::AuthFailed);
                }
                let eph = Ephemeral::generate();
                let recv_eph = eph.public;
                let ai = ack_input(&sha256(&[&hi]), &session_id, &recv_eph, &me);
                let ack_sig = self.identity.sign(&ai);
                let mut shared = eph.agree(&sender_eph).map_err(|_| RejectCode::AuthFailed)?;
                let keys = derive_session_keys(&shared, &transcript(&hi, &ai));
                shared.zeroize();
                self.sessions.insert(
                    session_id,
                    RecvSession { sender: sender_id, keys, last_seq: 0, seen_probes: HashSet::new() },
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
