# Evaluation

PathGuard makes a claim that has to be tested: do decoys, canaries and multi-path checks add useful detection on top of authenticated encryption, at an acceptable cost?

## Comparison groups

1. Authenticated encryption only (`baseline`).
2. Plus interception detection and canaries (`balanced`).
3. Plus multi-path verification.
4. All four mechanisms (`paranoid`).
5. All mechanisms with canary monitoring.

## Metrics

| Metric | Status |
|---|---|
| Interception detection rate | Simulated scenarios only |
| False-positive rate | Not measured. Needs real network noise |
| Authentication failure detection | Covered by tests |
| Added latency | Not measured on real networks |
| Bandwidth overhead | Not measured. Probes per path are configurable |
| CPU and memory overhead | Not measured |
| Recovery time | Not measured |
| Path diversity accuracy | Depends on hop data. Not measured |

Run `cargo run --release -- matrix` for the current simulated results. They are regression tests for design decisions, not evidence of real-world security.

## Scenario expectations

Each row is asserted in `tests/scenarios.rs`. The response-attack rows are additionally asserted by finding kind and stage in `tests/failure_classification.rs`, and the payload row in `tests/toctou.rs`, so a scenario that fails at the wrong check fails its test.

| Scenario | Expected outcome and why |
|---|---|
| honest | Delivered under all policies. |
| lossy-link | Delivered. One lost probe is tolerated (majority rule, Medium weight 0.5 is below the limit 1.0). |
| latency-spike | Delivered with an alert. Timing is weak evidence and cannot withhold alone. |
| mitm-all-paths | Never delivered. Receiver signature does not match the pinned identity. |
| mitm-one-path | Delivered after a retry on another path. |
| tamper-primary | `baseline` sends a modified payload, the receiver rejects it, delivery is unconfirmed. Probing policies detect tampering first and never send. |
| tamper-secondary | Delivered. Only `paranoid` looks at secondary paths and records an alert. |
| tampered-hello-ack | Fails at the **handshake** (`HandshakeFailure`, receiver signature invalid). No probe is sent on that path. Next attempt uses a clean path. |
| forged-reply-mac | Handshake succeeds; fails at **ProbeReply MAC verification** (`ReplyAuthFailure`). |
| replayed-reply | A stale reply with an authentic MAC but for another probe. Fails at **probe binding** (`MalformedReply`, "different probe"), before the MAC is even checked. |
| rewritten-reply-ids | The stale reply relabelled with the current probe's ids. The MAC covers the ids, so it fails at **MAC verification** (`ReplyAuthFailure`). This is the "authentic but incorrect response" case. |
| payload-only-tamper | All probes verify, then only the payload is modified. The receiver's AEAD check rejects it (`PayloadRejected`). Nothing is delivered, the session is closed, no automatic retry. Same result under every policy. |
| duplicate-replies | `balanced` retries on another path. `paranoid` excludes the noisy secondary and alerts. |
| snooping-primary | `paranoid` withholds on every attempt because a bait token was touched (session-level). `balanced` moves to another path and delivers. |
| snooping-secondary | Only policies that probe secondary paths notice. `paranoid` withholds. |
| passive-relay | Delivered everywhere, undetected. Plaintext never exposed. Documented limitation. |
| shared-infrastructure | `paranoid` withholds: diversity 0.0 is below 0.5. |

## Planned real-world experiments

* Linux network namespaces with `tc netem` for loss, delay and reordering, to measure false positives.
* A real on-path proxy implementing each adversary.
* Overhead curves for probes per path against detection rate.
* Comparison with a plain TLS 1.3 or Noise session on the same paths.
