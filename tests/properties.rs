//! Property-based tests: wire format, parsers and receiver state-machine invariants.
//!
//! Deterministic by default (fixed seed) so CI is reproducible. Raise coverage locally with
//! `PG_PROP_CASES=5000 cargo test --test properties`, or explore with a different seed via
//! `PG_PROP_SEED=123 cargo test --test properties`. A failing case is shrunk and saved to
//! `proptest-regressions/`; commit that file as a regression test.

mod common;

use common::{make_hello_at, new_receiver};
use pathguard::canary;
use pathguard::clock::Clock;
use pathguard::crypto::{self, Identity, SessionKeys};
use pathguard::limits::*;
use pathguard::message::{Message, ProbeKind, RejectCode, SessionId};
use pathguard::receiver::{close_mac, payload_aad};
use pathguard::{Error, Policy, ReceiverConfig};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;

fn is_reject(b: &[u8]) -> bool {
    matches!(Message::decode(b), Ok(Message::Reject { .. }))
}
fn is_probe_reply(b: &[u8]) -> bool {
    matches!(Message::decode(b), Ok(Message::ProbeReply { .. }))
}
fn is_close(b: &[u8]) -> bool {
    matches!(Message::decode(b), Ok(Message::Close { .. }))
}

fn env_num(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn cfg(default_cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases: env_num("PG_PROP_CASES", default_cases as u64) as u32,
        rng_seed: RngSeed::Fixed(env_num("PG_PROP_SEED", 0x5041_5448)),
        ..ProptestConfig::default()
    }
}

fn arr<const N: usize>() -> impl Strategy<Value = [u8; N]> {
    prop::collection::vec(any::<u8>(), N).prop_map(|v| {
        let mut a = [0u8; N];
        a.copy_from_slice(&v);
        a
    })
}

fn kind() -> impl Strategy<Value = ProbeKind> {
    prop::sample::select(vec![ProbeKind::Interception, ProbeKind::Bait, ProbeKind::PayloadLike])
}

fn reject_code() -> impl Strategy<Value = RejectCode> {
    prop::sample::select(vec![
        RejectCode::BadRequest,
        RejectCode::UnknownSession,
        RejectCode::AuthFailed,
        RejectCode::Replay,
        RejectCode::Busy,
        RejectCode::Stale,
        RejectCode::TooLarge,
    ])
}

fn arb_message() -> impl Strategy<Value = Message> {
    let body = prop_oneof![prop::collection::vec(any::<u8>(), 0..96), prop::collection::vec(any::<u8>(), 4000..4100)];
    prop_oneof![
        (arr::<16>(), any::<u64>(), arr::<32>(), arr::<32>(), arr::<32>(), arr::<64>()).prop_map(
            |(session_id, timestamp, sender_eph, sender_id, recipient, sig)| Message::Hello {
                session_id,
                timestamp,
                sender_eph,
                sender_id,
                recipient,
                sig
            }
        ),
        (arr::<16>(), arr::<32>(), arr::<32>(), arr::<64>())
            .prop_map(|(session_id, recv_eph, recv_id, sig)| Message::HelloAck { session_id, recv_eph, recv_id, sig }),
        (arr::<16>(), arr::<16>(), kind(), any::<u64>(), body.clone(), arr::<32>()).prop_map(
            |(session_id, probe_id, kind, seq, body, mac)| Message::Probe {
                session_id,
                probe_id,
                kind,
                seq,
                body,
                mac
            }
        ),
        (arr::<16>(), arr::<16>(), any::<u64>(), arr::<32>())
            .prop_map(|(session_id, probe_id, seq, mac)| Message::ProbeReply { session_id, probe_id, seq, mac }),
        (arr::<16>(), any::<u64>(), body).prop_map(|(session_id, seq, ciphertext)| Message::Payload {
            session_id,
            seq,
            ciphertext
        }),
        (arr::<16>(), any::<u64>(), arr::<32>()).prop_map(|(session_id, seq, mac)| Message::PayloadAck {
            session_id,
            seq,
            mac
        }),
        (arr::<16>(), arr::<32>()).prop_map(|(session_id, mac)| Message::Close { session_id, mac }),
        reject_code().prop_map(|code| Message::Reject { code }),
    ]
}

proptest! {
    #![proptest_config(cfg(512))]

    #[test]
    fn encode_then_decode_is_identity(m in arb_message()) {
        prop_assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn decode_never_panics_and_accepts_only_canonical_encodings(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(m) = Message::decode(&bytes) {
            prop_assert_eq!(m.encode(), bytes, "a decodable message must re-encode to the same bytes");
        }
    }

    #[test]
    fn every_strict_prefix_of_a_valid_message_is_rejected(m in arb_message()) {
        let enc = m.encode();
        for cut in 0..enc.len() {
            prop_assert!(Message::decode(&enc[..cut]).is_err(), "prefix of length {} accepted", cut);
        }
    }

    #[test]
    fn trailing_bytes_are_rejected(m in arb_message(), extra in prop::collection::vec(any::<u8>(), 1..16)) {
        let mut enc = m.encode();
        enc.extend_from_slice(&extra);
        prop_assert!(Message::decode(&enc).is_err());
    }

    #[test]
    fn a_length_field_that_lies_is_rejected_without_a_large_allocation(declared in any::<u32>(), actual in 0usize..64) {
        // Probe with an arbitrary declared body length and a short real body.
        let mut m = vec![3u8];
        m.extend_from_slice(&[1u8; 16]);
        m.extend_from_slice(&[2u8; 16]);
        m.push(0);
        m.extend_from_slice(&7u64.to_be_bytes());
        m.extend_from_slice(&declared.to_be_bytes());
        m.extend_from_slice(&vec![9u8; actual]);
        m.extend_from_slice(&[0u8; 32]);
        let r = Message::decode(&m);
        if declared as usize > MAX_PROBE_BODY {
            prop_assert!(matches!(r, Err(Error::TooLarge)), "{:?}", r);
        } else if declared as usize != actual {
            prop_assert!(r.is_err());
        }
    }

    #[test]
    fn oversized_messages_are_rejected_whole(extra in 1usize..2000) {
        let buf = vec![5u8; MAX_MESSAGE + extra];
        prop_assert!(matches!(Message::decode(&buf), Err(Error::TooLarge)));
    }

    #[test]
    fn receiver_answers_every_input_with_a_wellformed_message(bytes in prop::collection::vec(any::<u8>(), 0..1500)) {
        let (mut recv, _) = new_receiver();
        recv.allow_any_authenticated_sender();
        let reply = recv.handle(&bytes);
        prop_assert!(Message::decode(&reply).is_ok());
        prop_assert_eq!(recv.session_count(), 0);
    }

    #[test]
    fn mutated_valid_messages_never_break_the_receiver(m in arb_message(), flips in prop::collection::vec((any::<prop::sample::Index>(), 0u8..8), 0..6)) {
        let (mut recv, _) = new_receiver();
        recv.allow_any_authenticated_sender();
        let mut enc = m.encode();
        for (idx, bit) in flips {
            let i = idx.index(enc.len());
            enc[i] ^= 1 << bit;
        }
        let reply = recv.handle(&enc);
        prop_assert!(Message::decode(&reply).is_ok());
    }

    #[test]
    fn policy_parser_never_panics_and_accepted_policies_are_valid(text in "\\PC{0,400}") {
        if let Ok(p) = Policy::from_toml_str(&text) {
            prop_assert!(p.validate().is_ok());
            prop_assert_eq!(Policy::from_toml_str(&p.to_toml()).unwrap(), p);
        }
    }

    #[test]
    fn canary_scan_only_returns_wellformed_tokens(bytes in prop::collection::vec(any::<u8>(), 0..400), pre in 0usize..20) {
        let mut data = vec![b'x'; pre];
        data.extend_from_slice(b"pg-canary-0123456789abcdef01234567");
        data.extend_from_slice(&bytes);
        let found = canary::scan(&data);
        prop_assert!(!found.is_empty());
        for t in found {
            prop_assert!(canary::is_valid_token(&t), "{}", t);
        }
        for t in canary::scan(&bytes) {
            prop_assert!(canary::is_valid_token(&t));
        }
    }
}

// ---- receiver state machine -------------------------------------------------

const MAX_SESSIONS: usize = 6;
const PER_SENDER: usize = 3;
const PAYLOADS_PER_SESSION: usize = 4;
const DELIVERED_ITEMS: usize = 5;
const DELIVERED_BYTES: usize = 1000;
const PAYLOAD_MAX: usize = 100;
const REPLAY_CAP: usize = 32;
const TTL: u64 = 300;

#[derive(Debug, Clone)]
enum Op {
    NewSession(u8),
    ReplayHello(usize),
    Payload { sess: usize, seq: u64, len: usize, tamper: bool },
    Probe { sess: usize, tamper: bool },
    Close { sess: usize, tamper: bool },
    Advance(u64),
    Garbage(Vec<u8>),
    Take,
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u8..3).prop_map(Op::NewSession),
        2 => any::<usize>().prop_map(Op::ReplayHello),
        6 => (any::<usize>(), 0u64..8, 0usize..130, any::<bool>())
            .prop_map(|(sess, seq, len, tamper)| Op::Payload { sess, seq, len, tamper: tamper && len % 3 == 0 }),
        2 => (any::<usize>(), any::<bool>()).prop_map(|(sess, tamper)| Op::Probe { sess, tamper }),
        1 => (any::<usize>(), any::<bool>()).prop_map(|(sess, tamper)| Op::Close { sess, tamper }),
        2 => (0u64..400).prop_map(Op::Advance),
        1 => prop::collection::vec(any::<u8>(), 0..200).prop_map(Op::Garbage),
        2 => Just(Op::Take),
    ]
}

struct ModelSession {
    id: SessionId,
    keys: SessionKeys,
    hello: Vec<u8>,
    created: u64,
    closed: bool,
    last_ok_seq: u64,
    acked: usize,
}

proptest! {
    #![proptest_config(cfg(24))]

    #[test]
    fn receiver_invariants_hold_under_arbitrary_operation_sequences(ops in prop::collection::vec(arb_op(), 1..40)) {
        let (recv, clock) = new_receiver();
        let mut recv = recv
            .with_config(ReceiverConfig {
                max_sessions: MAX_SESSIONS,
                max_sessions_per_sender: PER_SENDER,
                max_payloads_per_session: PAYLOADS_PER_SESSION,
                max_delivered_items: DELIVERED_ITEMS,
                max_delivered_bytes: DELIVERED_BYTES,
                max_payload_bytes: PAYLOAD_MAX,
                replay_cache_capacity: REPLAY_CAP,
                session_ttl_secs: TTL,
                max_handshakes_per_window: u32::MAX,
                ..ReceiverConfig::default()
            })
            .unwrap();
        let senders: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
        for s in &senders {
            recv.allow_sender(s.public());
        }
        let mut sessions: Vec<ModelSession> = Vec::new();
        let mut model_queue: Vec<Vec<u8>> = Vec::new();

        for op in ops {
            let now = clock.unix_secs();
            match op {
                Op::NewSession(s) => {
                    let h = make_hello_at(&senders[s as usize], &recv.public(), now);
                    let (bytes, id) = (h.bytes.clone(), h.session_id);
                    let reply = recv.handle(&bytes);
                    if let Some(keys) = h.finish(&reply) {
                        sessions.push(ModelSession { id, keys, hello: bytes, created: now, closed: false, last_ok_seq: 0, acked: 0 });
                    } else {
                        prop_assert!(is_reject(&reply));
                    }
                }
                Op::ReplayHello(i) if !sessions.is_empty() => {
                    let before = recv.session_count();
                    let reply = recv.handle(&sessions[i % sessions.len()].hello);
                    prop_assert!(is_reject(&reply), "a replayed hello must never be accepted");
                    prop_assert!(recv.session_count() <= before);
                }
                Op::Payload { sess, seq, len, tamper } if !sessions.is_empty() => {
                    let n = sess % sessions.len();
                    let s = &mut sessions[n];
                    let aad = payload_aad(&s.id, &recv.public().0, seq);
                    let plain = vec![n as u8; len];
                    let mut ct = crypto::seal(&s.keys.payload, &crypto::seq_nonce(seq), &aad, &plain).unwrap();
                    if tamper {
                        let last = ct.len() - 1;
                        ct[last] ^= 1;
                    }
                    let reply = recv.handle(&Message::Payload { session_id: s.id, seq, ciphertext: ct }.encode());
                    match Message::decode(&reply) {
                        Ok(Message::PayloadAck { seq: acked_seq, .. }) => {
                            prop_assert!(!tamper, "a tampered payload was acknowledged");
                            prop_assert!(!s.closed, "payload accepted on a closed session");
                            prop_assert!(now < s.created + TTL, "payload accepted on an expired session");
                            prop_assert_eq!(acked_seq, seq);
                            prop_assert!(seq > s.last_ok_seq, "sequence numbers must strictly increase");
                            prop_assert!(len <= PAYLOAD_MAX);
                            s.last_ok_seq = seq;
                            s.acked += 1;
                            prop_assert!(s.acked <= PAYLOADS_PER_SESSION);
                            model_queue.push(plain);
                        }
                        Ok(Message::Reject { .. }) => {}
                        other => prop_assert!(false, "unexpected reply {:?}", other),
                    }
                }
                Op::Probe { sess, tamper } if !sessions.is_empty() => {
                    let s = &sessions[sess % sessions.len()];
                    let pid = pathguard::util::random::<16>();
                    let body = b"probe".to_vec();
                    let mut mac = crypto::mac(&s.keys.probe, &[b"probe", &s.id, &pid, &[0u8], &1u64.to_be_bytes(), &body]);
                    if tamper {
                        mac[0] ^= 1;
                    }
                    let reply = recv.handle(&Message::Probe { session_id: s.id, probe_id: pid, kind: ProbeKind::Interception, seq: 1, body, mac }.encode());
                    if is_probe_reply(&reply) {
                        prop_assert!(!tamper && !s.closed && now < s.created + TTL);
                    }
                }
                Op::Close { sess, tamper } if !sessions.is_empty() => {
                    let idx = sess % sessions.len();
                    let s = &mut sessions[idx];
                    let mut mac = close_mac(&s.keys.probe, &s.id);
                    if tamper {
                        mac[0] ^= 1;
                    }
                    let reply = recv.handle(&Message::Close { session_id: s.id, mac }.encode());
                    if is_close(&reply) {
                        prop_assert!(!tamper);
                        s.closed = true;
                    }
                }
                Op::Advance(secs) => clock.advance(secs),
                Op::Garbage(bytes) => {
                    prop_assert!(Message::decode(&recv.handle(&bytes)).is_ok());
                }
                Op::Take => {
                    let got = recv.take_delivered();
                    prop_assert_eq!(&got, &model_queue, "delivered payloads must be exactly the acknowledged ones, in order");
                    model_queue.clear();
                }
                _ => {}
            }
            // Invariants that must hold after every operation.
            prop_assert!(recv.session_count() <= MAX_SESSIONS);
            prop_assert!(recv.delivered_len() <= DELIVERED_ITEMS);
            prop_assert!(recv.delivered_bytes() <= DELIVERED_BYTES);
            prop_assert!(recv.replay_cache_len() <= REPLAY_CAP);
            prop_assert_eq!(recv.delivered_len(), model_queue.len());
            prop_assert_eq!(recv.delivered_bytes(), model_queue.iter().map(Vec::len).sum::<usize>());
        }
    }
}
