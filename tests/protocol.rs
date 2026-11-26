//! Protocol-level properties checked against a live receiver.

use pathguard::crypto::{self, Identity};

mod common;
use common::{make_hello, new_receiver, reject};
use pathguard::message::{Message, ProbeKind, RejectCode};
use pathguard::sim::{self, World};
use pathguard::Policy;

#[test]
fn delivery_closes_the_session() {
    let w = World::new();
    let s = w.sender(Policy::paranoid());
    let mut paths = vec![w.honest_path("a", &["x", "y"], 1), w.honest_path("b", &["p", "q"], 2)];
    let r = s.send(b"data", &mut paths).unwrap();
    assert!(r.delivered);
    assert_eq!(w.take_delivered(), vec![b"data".to_vec()]);
    assert_eq!(w.receiver_sessions(), 0, "receiver must drop keys after close");
}

#[test]
fn withheld_attempts_leave_no_receiver_sessions() {
    let w = World::new();
    let s = w.sender(Policy::paranoid());
    let mut paths = vec![w.honest_path("a", &["x", "dst"], 1), w.honest_path("b", &["x", "dst"], 2)];
    assert!(s.send(b"data", &mut paths).is_err());
    assert!(w.take_delivered().is_empty());
    assert_eq!(w.receiver_sessions(), 0);
}

#[test]
fn hello_for_another_recipient_is_rejected() {
    let (mut recv, _) = new_receiver();
    recv.allow_any_authenticated_sender();
    let sender = Identity::generate();
    let other = Identity::generate().public();
    let h = make_hello(&sender, &other);
    assert_eq!(reject(&recv.handle(&h.bytes)), Some(RejectCode::AuthFailed));
}

#[test]
fn forged_hello_signature_is_rejected() {
    let (mut recv, _) = new_receiver();
    recv.allow_any_authenticated_sender();
    let sender = Identity::generate();
    let mut bytes = make_hello(&sender, &recv.public()).bytes;
    let n = bytes.len();
    bytes[n - 1] ^= 1;
    assert_eq!(reject(&recv.handle(&bytes)), Some(RejectCode::AuthFailed));
}

#[test]
fn replayed_hello_is_rejected_while_session_is_open() {
    let (mut recv, _) = new_receiver();
    recv.allow_any_authenticated_sender();
    let h = make_hello(&Identity::generate(), &recv.public());
    assert!(matches!(Message::decode(&recv.handle(&h.bytes)), Ok(Message::HelloAck { .. })));
    assert_eq!(reject(&recv.handle(&h.bytes)), Some(RejectCode::Replay));
}

#[test]
fn receiver_never_panics_on_garbage() {
    let mut recv = new_receiver().0;
    for len in 0..300usize {
        for fill in [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255] {
            let buf = vec![fill; len];
            let reply = recv.handle(&buf);
            assert!(Message::decode(&reply).is_ok());
        }
    }
}

#[test]
fn decoy_key_is_independent_of_payload_key() {
    let shared = [3u8; 32];
    let t = [4u8; 32];
    let k = crypto::derive_session_keys(&shared, &t);
    assert_ne!(k.payload, k.decoy);
    assert_ne!(k.payload, k.probe);
    assert_ne!(k.decoy, k.canary);
}

#[test]
fn probes_are_visible_but_carry_no_payload() {
    // Sanity check on the harness: bait and probe bodies are in the clear, the payload is not.
    let w = World::new();
    let s = w.sender(Policy::paranoid());
    let mut paths = vec![w.honest_path("a", &["x", "y"], 1), w.honest_path("b", &["p", "q"], 2)];
    s.send(sim::PAYLOAD, &mut paths).unwrap();
    assert!(w.observed_in_clear(b"pgprobe:"));
    assert!(w.observed_in_clear(b"pg-canary-"));
    assert!(!w.observed_in_clear(sim::PAYLOAD));
}

#[test]
fn probe_kind_values_are_stable() {
    assert_eq!(ProbeKind::Interception as u8, 0);
    assert_eq!(ProbeKind::Bait as u8, 1);
    assert_eq!(ProbeKind::PayloadLike as u8, 2);
}
