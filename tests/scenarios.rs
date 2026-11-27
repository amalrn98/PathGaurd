//! Scenario matrix expectations. Each expectation is justified in
//! docs/EVALUATION.md. If a change flips one of these, the change alters a
//! security property and needs a deliberate update here.

use pathguard::sim::{self, Outcome};

fn find<'a>(all: &'a [Outcome], scenario: &str, policy: &str) -> &'a Outcome {
    all.iter().find(|o| o.scenario == scenario && o.policy == policy).unwrap()
}

#[test]
fn payload_is_never_visible_on_any_path() {
    for o in sim::matrix() {
        assert!(!o.plaintext_leaked, "{} / {}", o.scenario, o.policy);
    }
}

#[test]
fn matrix_expectations() {
    let all = sim::matrix();
    // (scenario, baseline, balanced, paranoid) as "delivered" booleans.
    let expected: &[(&str, bool, bool, bool)] = &[
        ("honest", true, true, true),
        ("lossy-link", true, true, true),
        ("latency-spike", true, true, true),
        ("mitm-all-paths", false, false, false),
        ("mitm-one-path", true, true, true),
        ("tamper-primary", false, true, true),
        ("tamper-secondary", true, true, true),
        ("tampered-hello-ack", true, true, true),
        ("forged-reply-mac", true, true, true),
        ("replayed-reply", true, true, true),
        ("rewritten-reply-ids", true, true, true),
        ("payload-only-tamper", false, false, false),
        ("duplicate-replies", true, true, true),
        ("snooping-primary", true, true, false),
        ("snooping-secondary", true, true, false),
        ("passive-relay", true, true, true),
        ("shared-infrastructure", true, true, false),
    ];
    for (name, b, m, p) in expected {
        assert_eq!(find(&all, name, "baseline").delivered, *b, "{name} baseline");
        assert_eq!(find(&all, name, "balanced").delivered, *m, "{name} balanced");
        assert_eq!(find(&all, name, "paranoid").delivered, *p, "{name} paranoid");
    }
}

#[test]
fn mitm_is_never_a_delivery() {
    for p in ["baseline", "balanced", "paranoid"] {
        let o = find(&sim::matrix(), "mitm-all-paths", p).status.to_string();
        assert_eq!(o, "no-auth");
    }
}

#[test]
fn baseline_sends_tampered_payload_but_balanced_withholds_it() {
    let all = sim::matrix();
    assert_eq!(find(&all, "tamper-primary", "baseline").status, "unconfirmed");
    let bal = find(&all, "tamper-primary", "balanced");
    assert_eq!(bal.attempts, 2);
    assert!(bal.report.as_ref().unwrap().findings.iter().any(|f| f.severity == pathguard::detect::Severity::Critical));
}

#[test]
fn weak_timing_evidence_alone_does_not_withhold() {
    let all = sim::matrix();
    let o = find(&all, "latency-spike", "balanced");
    assert!(o.delivered);
    let r = o.report.as_ref().unwrap();
    assert!(r.findings.iter().any(|f| f.kind == pathguard::detect::FindingKind::TimingAnomaly));
    assert!(r.score < 1.0);
}

#[test]
fn single_lost_probe_is_tolerated() {
    let o = find(&sim::matrix(), "lossy-link", "balanced").report.as_ref().unwrap().attempts;
    assert_eq!(o, 1);
}

#[test]
fn paranoid_excludes_bad_secondary_but_raises_alert() {
    let all = sim::matrix();
    let o = find(&all, "tamper-secondary", "paranoid");
    assert!(o.delivered);
    let r = o.report.as_ref().unwrap();
    assert!(r.paths.iter().any(|p| p.excluded));
    assert!(!r.findings.is_empty());
}

#[test]
fn shared_infrastructure_fails_diversity_requirement() {
    let all = sim::matrix();
    let r = find(&all, "shared-infrastructure", "paranoid").report.as_ref().unwrap();
    assert_eq!(r.diversity, Some(0.0));
    assert!(r.reasons.iter().any(|m| m.contains("diversity")));
}

#[test]
fn passive_relay_is_undetected_but_learns_nothing() {
    // Documented limitation: a verbatim relay is indistinguishable from a slow
    // honest path. Confidentiality still holds because only the authenticated
    // receiver holds the session keys.
    let all = sim::matrix();
    for p in ["baseline", "balanced", "paranoid"] {
        let o = find(&all, "passive-relay", p);
        assert!(o.delivered);
        assert!(!o.plaintext_leaked);
    }
}
