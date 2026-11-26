//! Shared helpers for integration tests: a hand-rolled sender handshake, so tests
//! can drive a `Receiver` directly with exact bytes.
#![allow(dead_code)]

use pathguard::clock::ManualClock;
use pathguard::crypto::{self, Ephemeral, Identity, PublicIdentity, SessionKeys};
use pathguard::handshake::{ack_input, hello_input, transcript};
use pathguard::message::{Message, RejectCode, SessionId};
use pathguard::{util, Receiver};
use std::sync::Arc;

pub fn reject(bytes: &[u8]) -> Option<RejectCode> {
    match Message::decode(bytes) {
        Ok(Message::Reject { code }) => Some(code),
        _ => None,
    }
}

/// A fully built Hello and the secrets needed to finish the handshake.
pub struct PendingHello {
    pub bytes: Vec<u8>,
    pub session_id: SessionId,
    eph: Ephemeral,
    hello_in: Vec<u8>,
    recipient: PublicIdentity,
}

pub fn make_hello(sender: &Identity, recipient: &PublicIdentity) -> PendingHello {
    make_hello_at(sender, recipient, NOW)
}

/// Fixed test time, matching `receiver_at`.
pub const NOW: u64 = 1_700_000_000;

pub fn make_hello_at(sender: &Identity, recipient: &PublicIdentity, timestamp: u64) -> PendingHello {
    let session_id = util::random::<16>();
    let eph = Ephemeral::generate();
    let hello_in = hello_input(&session_id, timestamp, &eph.public, &sender.public().0, &recipient.0);
    let bytes = Message::Hello {
        session_id,
        timestamp,
        sender_eph: eph.public,
        sender_id: sender.public().0,
        recipient: recipient.0,
        sig: sender.sign(&hello_in),
    }
    .encode();
    PendingHello { bytes, session_id, eph, hello_in, recipient: *recipient }
}

impl PendingHello {
    /// Verify the receiver's ack and derive the session keys.
    pub fn finish(self, ack: &[u8]) -> Option<SessionKeys> {
        match Message::decode(ack).ok()? {
            Message::HelloAck { session_id, recv_eph, recv_id, sig } => {
                if session_id != self.session_id || recv_id != self.recipient.0 {
                    return None;
                }
                let ai = ack_input(&crypto::sha256(&[&self.hello_in]), &session_id, &recv_eph, &recv_id);
                if !self.recipient.verify(&ai, &sig) {
                    return None;
                }
                let shared = self.eph.agree(&recv_eph).ok()?;
                Some(crypto::derive_session_keys(&shared, &transcript(&self.hello_in, &ai)))
            }
            _ => None,
        }
    }
}

/// Run a complete handshake against a receiver.
pub fn handshake(recv: &mut Receiver, sender: &Identity) -> Option<(SessionId, SessionKeys)> {
    let h = make_hello(sender, &recv.public());
    let sid = h.session_id;
    let ack = recv.handle(&h.bytes);
    h.finish(&ack).map(|k| (sid, k))
}

/// A receiver on a manual clock that starts at [`NOW`].
pub fn new_receiver() -> (Receiver, ManualClock) {
    let clock = ManualClock::new(NOW);
    let recv = Receiver::new(Identity::generate()).with_clock(Arc::new(clock.clone()));
    (recv, clock)
}
