# Threat model

## Assets

1. Confidentiality and integrity of the payload.
2. Correct identification of the receiver.
3. Visibility into manipulation of the path (a detection goal, not a guarantee).

## Adversaries

| Adversary | Capability |
|---|---|
| Passive observer | Reads all traffic on one or more paths |
| Active on-path attacker | Drops, delays, duplicates, modifies, replays, injects |
| Impersonator | Answers on behalf of the receiver with its own keys |
| Relay attacker | Forwards every message verbatim between sender and the real receiver |
| Snooper | Reads plaintext it sees and acts on it (for example by using bait credentials) |
| Multi-path attacker | Controls some, but not all, independent paths |

Out of scope: compromise of either endpoint, theft of private keys, denial of service by a network attacker, global passive adversaries.

## What defends what

| Threat | Defence | Strength |
|---|---|---|
| Destination spoofing | Pinned receiver identity, signed ack | Cryptographic |
| Man in the middle | Authenticated ephemeral key agreement | Cryptographic |
| Payload modification | AEAD with identity-bound AAD | Cryptographic |
| Payload replay | Strictly increasing sequence, per-session keys | Cryptographic |
| Probe replay | Unique probe ids remembered by the receiver | Cryptographic |
| Hello replay to another receiver | Recipient inside the signed hello | Cryptographic |
| Hello replay to the same receiver | Signed timestamp, replay cache until the hello is stale | Cryptographic plus bounded state |
| Abandoned or exhausted sessions | Absolute session lifetime, session caps, fail-closed capacity | Resource bound |
| Handshake flood | Global fixed-window rate limit | Mitigation only, see below |
| Tampering with probes or replies | Probe and reply MACs | Cryptographic detection |
| Packet duplication | Duplicate reply finding | Heuristic, weak |
| Timing manipulation | RTT baseline z-score | Heuristic, weak |
| Snooping | Canary tokens in bait, honeypot polling | Fires only if the attacker acts on it |
| Single bad path | Multi-path verification and retry on another path | Depends on real path independence |
| Session exposure | Close, key discard, fresh handshake on retry | Procedural |

## Relay attacks

A relay forwards the handshake and every probe unchanged. All MACs verify, because the real receiver produced them. PathGuard cannot, and does not claim to, detect this. The relay still cannot read or alter the payload: it has no ephemeral secret, so it cannot derive the session keys. The only observable effect is extra latency, which is indistinguishable from a slow route. The scenario `passive-relay` encodes this expectation and its test asserts both facts.

## Time of check, time of use

Verification and release are separate steps, so a path that passed every probe can still change behaviour before the payload crosses it. An attacker who behaves honestly toward probes and modifies only the payload defeats the *detection* layer completely. That is expected: probes never protected the payload.

The protection is cryptographic and independent of verification. The payload is sealed with ChaCha20-Poly1305 under a key only the authenticated receiver holds, with the session id, receiver identity and sequence number as associated data. Any modification, in any bit of ciphertext or tag, fails authentication at the receiver (`tests/toctou.rs` flips every bit of a ciphertext). The receiver delivers nothing and answers `Reject(AuthFailed)`.

What PathGuard does about it, by policy:

* **Classification:** the sender records `PayloadRejected` (Critical) against the path.
* **Session:** invalidated. The sender closes it and drops the keys. The receiver also does not burn the sequence number on a failed authentication, so forged ciphertexts cannot make it reject the real one.
* **No automatic retry.** A `Reject` is unauthenticated: an attacker can forge one after dropping a genuine acknowledgement, which would otherwise trick the sender into resending data the receiver already holds. The result is `DeliveryUnconfirmed`, and the application decides whether to resend.
* **Residual exposure:** the attacker can still deny service on that path. Confidentiality and integrity hold.

## Route changes

A new route with correct authentication is not an attack. PathGuard never treats a changed path, hop list or latency baseline as compromise on its own. Hop changes only matter for the diversity requirement.

## Known gaps

* **Traffic analysis:** probes add traffic with a recognizable shape in plaintext (`pgprobe:` and bait). Padding and timing obfuscation are not implemented. Payload-like decoys match payload size only roughly.
* **Probe confidentiality:** kinds 0 and 1 are intentionally readable (they are bait). An observer can tell a verification phase is happening.
* **Honeypot:** the in-process honeypot is for the simulator. Real deployments use the [canary service](CANARY_SERVICE.md). It is a small single-instance service with a shared symmetric key, and an outage lowers confidence (or withholds, with `canary_required`) rather than being treated as clean.
* **Handshake rate limit is global, not per source.** Before a hello is authenticated the receiver cannot attribute it to anyone, so unauthenticated traffic can consume the rate budget and delay legitimate senders. The limit protects CPU and memory, not availability. Per-address limiting belongs in the transport layer, which sees addresses.
* **Clock dependence:** hello freshness needs loosely synchronized clocks (default window 120 s). An attacker who can move the receiver's clock can widen the replay window. Within the window, replay is blocked by the replay cache.
* **Replay cache is in memory:** a receiver restart forgets it. Hellos older than the skew window are still rejected as stale, so after a restart a captured hello is replayable only for the remaining part of its window if the receiver restarts inside it.
* **Post-quantum:** key agreement is classical X25519.
* **No audit:** protocol and code have not been reviewed by third parties.

## Assumptions

* The sender has the correct receiver public key out of band.
* The OS random number generator is sound.
* The RustCrypto and dalek implementations are correct.
