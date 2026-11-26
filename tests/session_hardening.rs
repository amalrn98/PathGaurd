//! Replay resistance, expiry and bounded resource use of the receiver.

mod common;

use common::{handshake, make_hello, make_hello_at, new_receiver, reject, NOW};
use pathguard::clock::Clock;
use pathguard::crypto::Identity;
use pathguard::message::{Message, RejectCode};
use pathguard::receiver::close_mac;
use pathguard::ReceiverConfig;

fn is_ack(bytes: &[u8]) -> bool {
    matches!(Message::decode(bytes), Ok(Message::HelloAck { .. }))
}

fn cfg() -> ReceiverConfig {
    ReceiverConfig::default()
}

#[test]
fn replaying_an_accepted_hello_after_its_session_closed_creates_nothing() {
    let (mut recv, clock) = new_receiver();
    let alice = Identity::generate();
    recv.allow_sender(alice.public());

    let h = make_hello(&alice, &recv.public());
    let (bytes, sid) = (h.bytes.clone(), h.session_id);
    let keys = h.finish(&recv.handle(&bytes)).expect("first hello is accepted");
    let close = Message::Close { session_id: sid, mac: close_mac(&keys.probe, &sid) }.encode();
    recv.handle(&close);
    assert_eq!(recv.session_count(), 0, "session closed and removed");

    // The captured hello is still byte-for-byte valid and its session id is free again.
    assert_eq!(reject(&recv.handle(&bytes)), Some(RejectCode::Replay));
    assert_eq!(recv.session_count(), 0, "replay must not create a session");
    assert_eq!(recv.stats().rejected_replayed_hello, 1);

    // Once the timestamp leaves the freshness window the hello is stale instead.
    clock.advance(cfg().max_clock_skew_secs + 1);
    assert_eq!(reject(&recv.handle(&bytes)), Some(RejectCode::Stale));
    assert_eq!(recv.session_count(), 0);
}

#[test]
fn replay_entries_are_pruned_once_the_hello_would_be_stale_anyway() {
    let (mut recv, clock) = new_receiver();
    let alice = Identity::generate();
    recv.allow_sender(alice.public());
    assert!(handshake(&mut recv, &alice).is_some());
    assert_eq!(recv.replay_cache_len(), 1);
    clock.advance(cfg().max_clock_skew_secs + 2);
    recv.maintain();
    assert_eq!(recv.replay_cache_len(), 0, "cache must not grow without bound");
}

#[test]
fn normal_reconnects_still_work() {
    let (mut recv, _) = new_receiver();
    let alice = Identity::generate();
    recv.allow_sender(alice.public());
    for _ in 0..5 {
        let (sid, keys) = handshake(&mut recv, &alice).expect("fresh hello with a new session id");
        let close = Message::Close { session_id: sid, mac: close_mac(&keys.probe, &sid) }.encode();
        recv.handle(&close);
    }
    assert_eq!(recv.session_count(), 0);
}

#[test]
fn hello_freshness_window_is_enforced_both_ways() {
    let (mut recv, clock) = new_receiver();
    let alice = Identity::generate();
    recv.allow_sender(alice.public());
    let skew = cfg().max_clock_skew_secs;
    let now = clock.unix_secs();
    for ts in [now - skew, now + skew] {
        assert!(is_ack(&recv.handle(&make_hello_at(&alice, &recv.public(), ts).bytes)), "ts {ts} within window");
    }
    for ts in [now - skew - 1, now + skew + 1, 0, u64::MAX] {
        let r = recv.handle(&make_hello_at(&alice, &recv.public(), ts).bytes);
        assert_eq!(reject(&r), Some(RejectCode::Stale), "ts {ts} outside window");
    }
    assert_eq!(recv.stats().rejected_stale, 4);
}

#[test]
fn abandoned_sessions_expire_and_are_reclaimed() {
    let (mut recv, clock) = new_receiver();
    let alice = Identity::generate();
    recv.allow_sender(alice.public());
    let (sid, keys) = handshake(&mut recv, &alice).unwrap();
    assert_eq!(recv.session_count(), 1);

    clock.advance(cfg().session_ttl_secs + 1);
    // The next request of any kind triggers cleanup.
    let close = Message::Close { session_id: sid, mac: close_mac(&keys.probe, &sid) }.encode();
    assert_eq!(reject(&recv.handle(&close)), Some(RejectCode::UnknownSession), "expired session is gone");
    assert_eq!(recv.session_count(), 0);
    assert_eq!(recv.stats().sessions_expired, 1);
}

#[test]
fn session_capacity_is_bounded_and_recovers() {
    let (recv, clock) = new_receiver();
    let mut recv = recv.with_config(ReceiverConfig { max_sessions: 3, max_sessions_per_sender: 2, ..cfg() }).unwrap();
    let (alice, bob) = (Identity::generate(), Identity::generate());
    recv.allow_sender(alice.public());
    recv.allow_sender(bob.public());

    assert!(handshake(&mut recv, &alice).is_some());
    assert!(handshake(&mut recv, &alice).is_some());
    assert!(handshake(&mut recv, &alice).is_none(), "per-sender cap reached");
    assert!(handshake(&mut recv, &bob).is_some(), "another sender is unaffected");
    assert!(handshake(&mut recv, &bob).is_none(), "global cap reached");
    assert_eq!(recv.session_count(), 3);
    assert_eq!(recv.stats().rejected_capacity, 2);

    // Existing sessions are never evicted to make room. Expiry frees capacity.
    clock.advance(cfg().session_ttl_secs + 1);
    let h = make_hello_at(&alice, &recv.public(), clock.unix_secs());
    assert!(is_ack(&recv.handle(&h.bytes)));
}

#[test]
fn handshake_rate_limit_applies_and_resets_each_window() {
    let (recv, clock) = new_receiver();
    let mut recv =
        recv.with_config(ReceiverConfig { max_handshakes_per_window: 5, handshake_window_secs: 10, ..cfg() }).unwrap();
    let alice = Identity::generate();
    recv.allow_sender(alice.public());
    for i in 0..5 {
        assert!(is_ack(&recv.handle(&make_hello(&alice, &recv.public()).bytes)), "hello {i} within limit");
    }
    let r = recv.handle(&make_hello(&alice, &recv.public()).bytes);
    assert_eq!(reject(&r), Some(RejectCode::Busy));
    assert_eq!(recv.stats().rejected_rate_limited, 1);

    clock.advance(10);
    assert!(is_ack(&recv.handle(&make_hello_at(&alice, &recv.public(), clock.unix_secs()).bytes)));
}

#[test]
fn replay_cache_capacity_fails_closed_then_recovers() {
    let (recv, clock) = new_receiver();
    let mut recv = recv.with_config(ReceiverConfig { replay_cache_capacity: 4, ..cfg() }).unwrap();
    let alice = Identity::generate();
    recv.allow_sender(alice.public());
    for _ in 0..4 {
        let (sid, keys) = handshake(&mut recv, &alice).unwrap();
        recv.handle(&Message::Close { session_id: sid, mac: close_mac(&keys.probe, &sid) }.encode());
    }
    assert_eq!(recv.replay_cache_len(), 4);
    assert!(handshake(&mut recv, &alice).is_none(), "full cache refuses instead of forgetting hellos");

    clock.advance(cfg().max_clock_skew_secs + 2);
    let h = make_hello_at(&alice, &recv.public(), clock.unix_secs());
    assert!(is_ack(&recv.handle(&h.bytes)), "capacity returns once entries age out");
}

#[test]
fn unauthenticated_floods_do_not_consume_session_or_replay_state() {
    let (recv, _) = new_receiver();
    let mut recv = recv.with_config(ReceiverConfig { max_handshakes_per_window: u32::MAX, ..cfg() }).unwrap();
    recv.allow_any_authenticated_sender();
    let alice = Identity::generate();
    for i in 0..300u32 {
        let mut b = make_hello(&alice, &recv.public()).bytes;
        let n = b.len();
        b[n - 1 - (i as usize % 60)] ^= 1; // corrupt the signature
        assert!(reject(&recv.handle(&b)).is_some());
    }
    assert_eq!(recv.session_count(), 0);
    assert_eq!(recv.replay_cache_len(), 0, "forged hellos must not fill the replay cache");

    // Replaying one real hello many times does not grow state either.
    let h = make_hello(&alice, &recv.public());
    assert!(is_ack(&recv.handle(&h.bytes)));
    for _ in 0..300 {
        assert_eq!(reject(&recv.handle(&h.bytes)), Some(RejectCode::Replay));
    }
    assert_eq!(recv.session_count(), 1);
    assert_eq!(recv.replay_cache_len(), 1);
}

#[test]
fn unauthorized_flood_creates_no_state() {
    let (recv, _) = new_receiver(); // deny-all
    let mut recv = recv.with_config(ReceiverConfig { max_handshakes_per_window: u32::MAX, ..cfg() }).unwrap();
    for _ in 0..300 {
        let h = make_hello(&Identity::generate(), &recv.public());
        assert_eq!(reject(&recv.handle(&h.bytes)), Some(RejectCode::AuthFailed));
    }
    assert_eq!(recv.session_count(), 0);
    assert_eq!(recv.replay_cache_len(), 0);
}

#[test]
fn config_cannot_exceed_hard_ceilings() {
    let (recv, _) = new_receiver();
    let bad = [
        ReceiverConfig { max_clock_skew_secs: 0, ..cfg() },
        ReceiverConfig { max_clock_skew_secs: ReceiverConfig::SKEW_CEILING + 1, ..cfg() },
        ReceiverConfig { session_ttl_secs: ReceiverConfig::TTL_CEILING + 1, ..cfg() },
        ReceiverConfig { max_sessions: ReceiverConfig::SESSIONS_CEILING + 1, ..cfg() },
        ReceiverConfig { max_sessions_per_sender: 2_000, ..cfg() },
        ReceiverConfig { max_handshakes_per_window: 0, ..cfg() },
        ReceiverConfig { replay_cache_capacity: ReceiverConfig::REPLAY_CEILING + 1, ..cfg() },
    ];
    for c in bad {
        assert!(c.validate().is_err(), "{c:?}");
    }
    assert!(cfg().validate().is_ok());
    drop(recv);
    let _ = NOW;
}
