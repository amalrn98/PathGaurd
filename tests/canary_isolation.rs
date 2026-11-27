//! Canary events belong to the session that issued the token.

use pathguard::canary;
use pathguard::detect::FindingKind;
use pathguard::sim::{Behavior, World};
use pathguard::{CanaryStatus, Policy};
use std::collections::HashSet;

#[test]
fn concurrent_senders_sharing_one_honeypot_each_see_their_own_events() {
    let world = World::new();
    let threads = 8;
    let results: Vec<(HashSet<String>, bool)> = std::thread::scope(|sc| {
        let handles: Vec<_> = (0..threads)
            .map(|i| {
                let w = &world;
                sc.spawn(move || {
                    let sender = w.sender(Policy::balanced());
                    let mut paths =
                        vec![w.path("snoop", &["x"], i, Behavior::Snoop), w.honest_path("clean", &["y"], 100 + i)];
                    let report = sender.send(b"data", &mut paths).expect("second attempt uses the clean path");
                    let tokens: HashSet<String> = report
                        .findings
                        .iter()
                        .filter(|f| f.kind == FindingKind::CanaryTriggered)
                        .flat_map(|f| canary::scan(f.detail.as_bytes()))
                        .collect();
                    (tokens, report.delivered)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let mut seen: HashSet<String> = HashSet::new();
    for (tokens, delivered) in &results {
        assert!(delivered);
        assert!(!tokens.is_empty(), "a sender lost its own canary event to another sender's poll");
        for t in tokens {
            assert!(seen.insert(t.clone()), "token {t} reported to two different senders");
        }
    }
    assert_eq!(world.honeypot().unclaimed(), 0, "every hit was claimed by exactly its owner");
}

#[test]
fn one_sessions_poll_does_not_consume_another_sessions_hit() {
    let world = World::new();
    let a = world.sender(Policy::balanced());
    let b = world.sender(Policy::balanced());
    let mut pa = vec![world.honest_path("a", &["x"], 1)];
    let mut pb = vec![world.honest_path("b", &["y"], 2)];
    a.send(b"1", &mut pa).unwrap();
    b.send(b"2", &mut pb).unwrap();
    // Tokens as seen on the wire: A's first, B's after.
    let tokens = world.observed_canary_tokens();
    assert!(tokens.len() >= 2);
    let (ta, tb) = (tokens[0].clone(), tokens.last().unwrap().clone());
    world.honeypot().touch(&ta, "attacker-1");
    world.honeypot().touch(&tb, "attacker-2");

    let ea = a.collect_late_events().unwrap();
    assert_eq!(ea.len(), 1);
    assert_eq!(ea[0].token, ta);
    assert_eq!(world.honeypot().unclaimed(), 1, "B's hit must still be waiting");
    let eb = b.collect_late_events().unwrap();
    assert_eq!(eb.len(), 1);
    assert_eq!(eb[0].token, tb);
    assert_ne!(ea[0].session_id, eb[0].session_id);
}

#[test]
fn late_event_marks_the_session_compromised_and_is_reported_once() {
    let world = World::new();
    let sender = world.sender(Policy::balanced());
    let mut paths = vec![world.honest_path("a", &["x"], 1)];
    let report = sender.send(b"data", &mut paths).unwrap();
    assert!(report.delivered);
    assert_eq!(report.canary_status, CanaryStatus::Checked);
    assert!(sender.compromised_sessions().is_empty());

    let token = world.observed_canary_tokens().remove(0);
    world.honeypot().touch(&token, "late attacker");
    let events = sender.collect_late_events().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].session_id, report.session_id);
    assert_eq!(events[0].source, "late attacker");
    assert_eq!(sender.compromised_sessions(), vec![report.session_id]);

    world.honeypot().touch(&token, "late attacker again");
    assert!(sender.collect_late_events().unwrap().is_empty(), "already reported");
    assert_eq!(sender.compromised_sessions().len(), 1);
}

#[test]
fn hits_for_unknown_tokens_are_ignored_not_misattributed() {
    let world = World::new();
    let sender = world.sender(Policy::balanced());
    let mut paths = vec![world.honest_path("a", &["x"], 1)];
    sender.send(b"data", &mut paths).unwrap();
    world.honeypot().touch("pg-canary-000000000000000000000000", "stranger");
    assert!(sender.collect_late_events().unwrap().is_empty());
    assert!(sender.compromised_sessions().is_empty());
    assert_eq!(world.honeypot().unclaimed(), 1, "left in place for whoever owns it");
}

#[test]
fn canary_status_reflects_policy() {
    let world = World::new();
    let mut paths = vec![world.honest_path("a", &["x"], 1)];
    let r = world.sender(Policy::baseline()).send(b"d", &mut paths).unwrap();
    assert_eq!(r.canary_status, CanaryStatus::NotUsed);
}
