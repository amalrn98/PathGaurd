//! Each response-attack scenario must fail at the protocol check it is named after,
//! and report that reason, not merely fail.

use pathguard::detect::{FindingKind, Severity};
use pathguard::sim::{self, Outcome};
use pathguard::Policy;

fn run(name: &str) -> Outcome {
    let scn = sim::scenarios().into_iter().find(|s| s.name == name).unwrap_or_else(|| panic!("no scenario {name}"));
    sim::run(&scn, &Policy::balanced())
}

/// Distinct finding kinds recorded against the attacked path `a`.
fn kinds_on_a(o: &Outcome) -> Vec<String> {
    let mut k: Vec<String> =
        o.report.as_ref().unwrap().findings.iter().filter(|f| f.path == "a").map(|f| format!("{:?}", f.kind)).collect();
    k.sort();
    k.dedup();
    k
}

fn first_on_a(o: &Outcome, kind: FindingKind) -> &pathguard::detect::Finding {
    o.report.as_ref().unwrap().findings.iter().find(|f| f.path == "a" && f.kind == kind).expect("expected finding")
}

fn audit(o: &Outcome) -> String {
    o.report.as_ref().unwrap().audit.join("\n")
}

#[test]
fn tampered_hello_ack_fails_at_the_handshake_before_any_probe() {
    let o = run("tampered-hello-ack");
    assert_eq!(kinds_on_a(&o), ["HandshakeFailure"]);
    let f = first_on_a(&o, FindingKind::HandshakeFailure);
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.detail.contains("signature"), "{}", f.detail);
    assert!(!audit(&o).contains("probed 'a'"), "no probe may be sent over a path whose handshake failed");
    assert!(o.delivered && o.attempts == 2, "recovers on the next path");
}

#[test]
fn forged_probe_reply_mac_fails_at_reply_authentication() {
    let o = run("forged-reply-mac");
    assert_eq!(kinds_on_a(&o), ["ReplyAuthFailure"]);
    let f = first_on_a(&o, FindingKind::ReplyAuthFailure);
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.detail.contains("MAC invalid"), "{}", f.detail);
    let a = audit(&o);
    assert!(
        a.contains("handshake via 'a'") && !a.contains("handshake failed on 'a'"),
        "handshake must have succeeded:\n{a}"
    );
    assert!(a.contains("probed 'a'"), "the scenario must reach ProbeReply verification:\n{a}");
}

#[test]
fn replayed_reply_is_authentic_but_answers_a_different_probe() {
    let o = run("replayed-reply");
    // The MAC of a stale reply is valid, so the failure must be the binding to the probe,
    // detected before (and independently of) MAC verification.
    assert_eq!(kinds_on_a(&o), ["MalformedReply"]);
    assert!(first_on_a(&o, FindingKind::MalformedReply).detail.contains("different probe"));
}

#[test]
fn relabelled_stale_reply_fails_the_mac_because_the_mac_covers_the_probe_ids() {
    let o = run("rewritten-reply-ids");
    assert_eq!(kinds_on_a(&o), ["ReplyAuthFailure"]);
    assert!(first_on_a(&o, FindingKind::ReplyAuthFailure).detail.contains("MAC invalid"));
}

#[test]
fn duplicate_replies_are_a_weak_signal_not_an_authentication_failure() {
    let o = run("duplicate-replies");
    assert_eq!(kinds_on_a(&o), ["DuplicateReply"]);
    assert_eq!(first_on_a(&o, FindingKind::DuplicateReply).severity, Severity::Medium);
}
