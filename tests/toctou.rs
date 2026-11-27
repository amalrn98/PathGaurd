//! Verification passes, then only the payload is modified. Probe verification does not
//! bypass payload integrity: the AEAD tag does.

mod common;

use common::{handshake, new_receiver, reject};
use pathguard::crypto::{self, Identity};
use pathguard::detect::{FindingKind, Severity};
use pathguard::message::{Message, RejectCode};
use pathguard::receiver::payload_aad;
use pathguard::sim::{self, Behavior, World};
use pathguard::{Policy, SendError};

fn tampered_world(policy: Policy) -> (World, Result<pathguard::SendReport, SendError>) {
    let w = World::new();
    let s = w.sender(policy);
    let mut paths = vec![
        w.path("a", &["isp-a", "ix-1", "dst"], 1, Behavior::TamperPayloadOnly),
        w.honest_path("b", &["isp-b", "ix-2", "dst"], 2),
        w.honest_path("c", &["isp-c", "ix-3", "dst"], 3),
    ];
    let res = s.send(sim::PAYLOAD, &mut paths);
    (w, res)
}

#[test]
fn successful_probes_do_not_protect_a_payload_modified_afterwards() {
    for policy in [Policy::balanced(), Policy::paranoid()] {
        let name = policy.name.clone();
        let (w, res) = tampered_world(policy);
        let Err(SendError::DeliveryUnconfirmed(r)) = res else {
            panic!("{name}: expected DeliveryUnconfirmed, got {res:?}")
        };

        // 1. The check really passed: every probe on every path verified, nothing critical before release.
        assert!(r.released, "{name}: policy must have allowed release");
        assert!(r.paths.iter().all(|p| p.verified && p.probes_ok == p.probes_sent), "{name}: {:?}", r.paths);
        assert!(
            r.findings.iter().all(|f| f.kind == FindingKind::PayloadRejected),
            "{name}: only the payload failed: {:?}",
            r.findings
        );

        // 2. The AEAD rejected the altered ciphertext at the receiver, and the sender classified it.
        let f = &r.findings[0];
        assert_eq!((f.kind, f.severity, f.path.as_str()), (FindingKind::PayloadRejected, Severity::Critical, "a"));
        assert!(!r.delivered);
        assert!(w.take_delivered().is_empty(), "{name}: modified data must never reach the application");
        assert!(!w.observed_in_clear(sim::PAYLOAD));

        // 3. Documented session policy: invalidated, not retried.
        assert_eq!(r.attempts, 1, "{name}: no automatic retry after the payload was sent");
        assert_eq!(w.receiver_sessions(), 0, "{name}: session closed and keys dropped");
        assert!(r.audit.iter().any(|l| l.contains("closed, not retried")), "{name}: {:?}", r.audit);
    }
}

#[test]
fn baseline_classifies_it_the_same_way_with_no_probes() {
    let (w, res) = tampered_world(Policy::baseline());
    let Err(SendError::DeliveryUnconfirmed(r)) = res else { panic!("expected DeliveryUnconfirmed") };
    assert!(r.paths.is_empty(), "baseline sent no probes");
    assert_eq!(r.findings[0].kind, FindingKind::PayloadRejected);
    assert!(w.take_delivered().is_empty());
}

#[test]
fn the_same_world_with_an_honest_primary_delivers() {
    let w = World::new();
    let s = w.sender(Policy::balanced());
    let mut paths = vec![w.honest_path("a", &["x"], 1)];
    assert!(s.send(sim::PAYLOAD, &mut paths).unwrap().delivered);
}

#[test]
fn receiver_side_a_rejected_payload_neither_delivers_nor_burns_the_sequence_number() {
    let (mut recv, _) = new_receiver();
    let alice = Identity::generate();
    recv.allow_sender(alice.public());
    let (sid, keys) = handshake(&mut recv, &alice).unwrap();
    let aad = payload_aad(&sid, &recv.public().0, 1);
    let ct = crypto::seal(&keys.payload, &crypto::seq_nonce(1), &aad, b"secret").unwrap();

    let mut bad = ct.clone();
    let n = bad.len();
    bad[n - 1] ^= 1; // flip one bit in the authentication tag
    let r = recv.handle(&Message::Payload { session_id: sid, seq: 1, ciphertext: bad }.encode());
    assert_eq!(reject(&r), Some(RejectCode::AuthFailed));
    assert!(recv.take_delivered().is_empty());
    assert_eq!(recv.session_count(), 1, "the session stays open at the receiver until it is closed or expires");

    // The genuine ciphertext with the same sequence number still works: an attacker cannot
    // use failed forgeries to make the receiver reject the real message.
    let ok = recv.handle(&Message::Payload { session_id: sid, seq: 1, ciphertext: ct }.encode());
    assert!(matches!(Message::decode(&ok), Ok(Message::PayloadAck { seq: 1, .. })));
    assert_eq!(recv.take_delivered(), vec![b"secret".to_vec()]);
}

#[test]
fn every_single_bit_flip_in_the_ciphertext_is_rejected() {
    let (mut recv, _) = new_receiver();
    let alice = Identity::generate();
    recv.allow_sender(alice.public());
    let (sid, keys) = handshake(&mut recv, &alice).unwrap();
    let aad = payload_aad(&sid, &recv.public().0, 1);
    let ct = crypto::seal(&keys.payload, &crypto::seq_nonce(1), &aad, b"0123456789abcdef").unwrap();
    for byte in 0..ct.len() {
        for bit in 0..8 {
            let mut bad = ct.clone();
            bad[byte] ^= 1 << bit;
            let r = recv.handle(&Message::Payload { session_id: sid, seq: 1, ciphertext: bad }.encode());
            assert_eq!(reject(&r), Some(RejectCode::AuthFailed), "flip byte {byte} bit {bit}");
        }
    }
    assert!(recv.take_delivered().is_empty());
}
