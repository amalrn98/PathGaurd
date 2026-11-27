//! Size and count limits are enforced before allocation and under sustained load.

mod common;

use common::{handshake, new_receiver, reject};
use pathguard::codec::Reader;
use pathguard::crypto::{self, Identity, SessionKeys};
use pathguard::limits::*;
use pathguard::message::{Message, ProbeKind, RejectCode, SessionId};
use pathguard::receiver::{ack_mac, payload_aad};
use pathguard::sim::World;
use pathguard::{Policy, Receiver, ReceiverConfig, SendError};

fn payload_msg(recv: &Receiver, sid: SessionId, keys: &SessionKeys, seq: u64, plain: &[u8]) -> Vec<u8> {
    let aad = payload_aad(&sid, &recv.public().0, seq);
    let ct = crypto::seal(&keys.payload, &crypto::seq_nonce(seq), &aad, plain).unwrap();
    Message::Payload { session_id: sid, seq, ciphertext: ct }.encode()
}

fn setup(cfg: ReceiverConfig) -> (Receiver, Identity) {
    let (recv, _) = new_receiver();
    let mut recv = recv.with_config(cfg).unwrap();
    let alice = Identity::generate();
    recv.allow_sender(alice.public());
    (recv, alice)
}

fn is_ack(b: &[u8]) -> bool {
    matches!(Message::decode(b), Ok(Message::PayloadAck { .. }))
}

#[test]
fn payload_at_the_limit_is_accepted_and_one_byte_over_is_rejected() {
    let (mut recv, alice) = setup(ReceiverConfig { max_delivered_bytes: 1 << 20, ..Default::default() });
    let (sid, keys) = handshake(&mut recv, &alice).unwrap();
    let ok = recv.handle(&payload_msg(&recv, sid, &keys, 1, &vec![7u8; MAX_PAYLOAD_BYTES]));
    assert!(is_ack(&ok));
    let too_big = payload_msg(&recv, sid, &keys, 2, &vec![7u8; MAX_PAYLOAD_BYTES + 1]);
    assert_eq!(reject(&recv.handle(&too_big)), Some(RejectCode::TooLarge));
    assert_eq!(recv.take_delivered().len(), 1);
}

#[test]
fn configured_payload_limit_can_be_lowered_but_not_raised() {
    let (mut recv, alice) =
        setup(ReceiverConfig { max_payload_bytes: 100, max_delivered_bytes: 1000, ..Default::default() });
    let (sid, keys) = handshake(&mut recv, &alice).unwrap();
    assert!(is_ack(&recv.handle(&payload_msg(&recv, sid, &keys, 1, &[1u8; 100]))));
    assert_eq!(reject(&recv.handle(&payload_msg(&recv, sid, &keys, 2, &[1u8; 101]))), Some(RejectCode::TooLarge));
    let raised = ReceiverConfig { max_payload_bytes: MAX_PAYLOAD_BYTES + 1, ..Default::default() };
    assert!(raised.validate().is_err());
}

#[test]
fn hostile_length_fields_fail_before_any_allocation() {
    // A probe or payload claiming ~4 GiB inside a 60 byte datagram.
    for tag in [3u8, 5u8] {
        let mut m = vec![tag];
        m.extend_from_slice(&[0u8; 16]); // session id
        if tag == 3 {
            m.extend_from_slice(&[0u8; 16]); // probe id
            m.push(0); // kind
        }
        m.extend_from_slice(&0u64.to_be_bytes()); // seq
        m.extend_from_slice(&0xFFFF_FFF0u32.to_be_bytes()); // declared length
        assert!(matches!(Message::decode(&m), Err(pathguard::Error::TooLarge)), "tag {tag}");
    }
    // Just over the limit is also refused, even with the bytes present is irrelevant: length is checked first.
    let len = (MAX_PROBE_BODY as u32 + 1).to_be_bytes();
    let mut r = Reader::new(&len);
    assert!(matches!(r.bytes_max(MAX_PROBE_BODY), Err(pathguard::Error::TooLarge)));
}

#[test]
fn oversized_datagram_is_rejected_whole() {
    let (mut recv, _) = new_receiver();
    let huge = vec![5u8; MAX_MESSAGE + 1];
    assert_eq!(reject(&recv.handle(&huge)), Some(RejectCode::TooLarge));
}

#[test]
fn probe_body_limit_and_count_limit() {
    let (mut recv, alice) = setup(ReceiverConfig { max_probes_per_session: 3, ..Default::default() });
    let (sid, keys) = handshake(&mut recv, &alice).unwrap();
    let probe = |recv: &mut Receiver, n: u8, body: Vec<u8>| {
        let pid = [n; 16];
        let seq = n as u64;
        let mac = crypto::mac(&keys.probe, &[b"probe", &sid, &pid, &[0u8], &seq.to_be_bytes(), &body]);
        recv.handle(
            &Message::Probe { session_id: sid, probe_id: pid, kind: ProbeKind::Interception, seq, body, mac }.encode(),
        )
    };
    let at_limit = probe(&mut recv, 1, vec![0u8; MAX_PROBE_BODY]);
    assert!(matches!(Message::decode(&at_limit), Ok(Message::ProbeReply { .. })));
    let over = Message::Probe {
        session_id: sid,
        probe_id: [9; 16],
        kind: ProbeKind::Interception,
        seq: 9,
        body: vec![0u8; MAX_PROBE_BODY + 1],
        mac: [0; 32],
    }
    .encode();
    assert_eq!(reject(&recv.handle(&over)), Some(RejectCode::TooLarge));
    assert!(matches!(Message::decode(&probe(&mut recv, 2, vec![1])), Ok(Message::ProbeReply { .. })));
    assert!(matches!(Message::decode(&probe(&mut recv, 3, vec![1])), Ok(Message::ProbeReply { .. })));
    assert_eq!(reject(&probe(&mut recv, 4, vec![1])), Some(RejectCode::Busy), "per-session probe cap");
}

#[test]
fn payloads_per_session_are_capped() {
    let (mut recv, alice) = setup(ReceiverConfig { max_payloads_per_session: 2, ..Default::default() });
    let (sid, keys) = handshake(&mut recv, &alice).unwrap();
    assert!(is_ack(&recv.handle(&payload_msg(&recv, sid, &keys, 1, b"a"))));
    assert!(is_ack(&recv.handle(&payload_msg(&recv, sid, &keys, 2, b"b"))));
    assert_eq!(reject(&recv.handle(&payload_msg(&recv, sid, &keys, 3, b"c"))), Some(RejectCode::Busy));
}

#[test]
fn delivery_queue_applies_backpressure_and_recovers() {
    let (mut recv, alice) = setup(ReceiverConfig { max_delivered_items: 3, ..Default::default() });
    let (sid, keys) = handshake(&mut recv, &alice).unwrap();
    for seq in 1..=3u64 {
        assert!(is_ack(&recv.handle(&payload_msg(&recv, sid, &keys, seq, b"x"))));
    }
    // Queue full: refused without consuming the sequence number.
    let blocked = payload_msg(&recv, sid, &keys, 4, b"y");
    assert_eq!(reject(&recv.handle(&blocked)), Some(RejectCode::Busy));
    assert_eq!(recv.delivered_len(), 3);
    assert_eq!(recv.take_delivered().len(), 3);
    assert_eq!(recv.delivered_bytes(), 0);
    // The very same bytes now succeed.
    let again = recv.handle(&blocked);
    match Message::decode(&again) {
        Ok(Message::PayloadAck { seq: 4, mac, .. }) => {
            let ct = match Message::decode(&blocked).unwrap() {
                Message::Payload { ciphertext, .. } => ciphertext,
                _ => unreachable!(),
            };
            assert_eq!(mac, ack_mac(&keys.probe, &sid, 4, &ct));
        }
        other => panic!("expected ack, got {other:?}"),
    }
}

#[test]
fn delivery_byte_budget_is_enforced() {
    let (mut recv, alice) =
        setup(ReceiverConfig { max_payload_bytes: 1000, max_delivered_bytes: 2500, ..Default::default() });
    let (sid, keys) = handshake(&mut recv, &alice).unwrap();
    assert!(is_ack(&recv.handle(&payload_msg(&recv, sid, &keys, 1, &[0u8; 1000]))));
    assert!(is_ack(&recv.handle(&payload_msg(&recv, sid, &keys, 2, &[0u8; 1000]))));
    assert_eq!(reject(&recv.handle(&payload_msg(&recv, sid, &keys, 3, &[0u8; 1000]))), Some(RejectCode::Busy));
    assert_eq!(recv.delivered_bytes(), 2000);
}

#[test]
fn memory_stays_bounded_under_sustained_unconsumed_load() {
    let cfg = ReceiverConfig { max_delivered_items: 8, max_handshakes_per_window: u32::MAX, ..Default::default() };
    let (mut recv, alice) = setup(cfg);
    let mut accepted = 0;
    for _ in 0..40 {
        let (sid, keys) = handshake(&mut recv, &alice).unwrap();
        if is_ack(&recv.handle(&payload_msg(&recv, sid, &keys, 1, &[9u8; 4096]))) {
            accepted += 1;
        }
        assert!(recv.delivered_len() <= 8 && recv.delivered_bytes() <= 8 * 4096);
        recv.handle(
            &Message::Close { session_id: sid, mac: pathguard::receiver::close_mac(&keys.probe, &sid) }.encode(),
        );
    }
    assert_eq!(accepted, 8, "only what the queue can hold is accepted; the rest is refused, not buffered");
}

#[test]
fn config_validation_covers_the_new_limits() {
    let d = ReceiverConfig::default;
    for bad in [
        ReceiverConfig { max_payloads_per_session: 0, ..d() },
        ReceiverConfig { max_payloads_per_session: 5000, ..d() },
        ReceiverConfig { max_probes_per_session: MAX_PROBES_PER_SESSION + 1, ..d() },
        ReceiverConfig { max_delivered_items: 0, ..d() },
        ReceiverConfig { max_delivered_items: 100_000, ..d() },
        ReceiverConfig { max_delivered_bytes: 10, ..d() },
        ReceiverConfig { max_delivered_bytes: 1 << 30, ..d() },
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
}

#[test]
fn sender_and_receiver_agree_on_the_payload_limit() {
    let w = World::new();
    let s = w.sender(Policy::baseline());
    let mut paths = vec![w.honest_path("a", &["x"], 1)];
    let max = vec![3u8; MAX_PAYLOAD_BYTES];
    assert!(s.send(&max, &mut paths).unwrap().delivered);
    assert_eq!(w.take_delivered()[0].len(), MAX_PAYLOAD_BYTES);
    let over = vec![3u8; MAX_PAYLOAD_BYTES + 1];
    assert!(matches!(s.send(&over, &mut paths), Err(SendError::Policy(_))));
}

#[test]
fn sender_limits_the_number_of_paths() {
    let w = World::new();
    let s = w.sender(Policy::baseline());
    let mut paths: Vec<_> = (0..MAX_PATHS + 1).map(|i| w.honest_path(&format!("p{i}"), &["x"], i as u64)).collect();
    assert!(matches!(s.send(b"x", &mut paths), Err(SendError::Policy(_))));
}
