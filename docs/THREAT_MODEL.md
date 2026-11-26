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
| Tampering with probes or replies | Probe and reply MACs | Cryptographic detection |
| Packet duplication | Duplicate reply finding | Heuristic, weak |
| Timing manipulation | RTT baseline z-score | Heuristic, weak |
| Snooping | Canary tokens in bait, honeypot polling | Fires only if the attacker acts on it |
| Single bad path | Multi-path verification and retry on another path | Depends on real path independence |
| Session exposure | Close, key discard, fresh handshake on retry | Procedural |

## Relay attacks

A relay forwards the handshake and every probe unchanged. All MACs verify, because the real receiver produced them. PathGuard cannot, and does not claim to, detect this. The relay still cannot read or alter the payload: it has no ephemeral secret, so it cannot derive the session keys. The only observable effect is extra latency, which is indistinguishable from a slow route. The scenario `passive-relay` encodes this expectation and its test asserts both facts.

## Route changes

A new route with correct authentication is not an attack. PathGuard never treats a changed path, hop list or latency baseline as compromise on its own. Hop changes only matter for the diversity requirement.

## Known gaps

* **Traffic analysis:** probes add traffic with a recognizable shape in plaintext (`pgprobe:` and bait). Padding and timing obfuscation are not implemented. Payload-like decoys match payload size only roughly.
* **Probe confidentiality:** kinds 0 and 1 are intentionally readable (they are bait). An observer can tell a verification phase is happening.
* **Honeypot:** the honeypot is an in-process log. A real deployment needs a listener that records contact with bait endpoints and calls `touch`.
* **Session lifetime:** receiver sessions have no timeout or eviction beyond a hard cap.
* **Clock-free design:** no timestamps are used, so no clock attacks, but also no expiry.
* **Post-quantum:** key agreement is classical X25519.
* **No audit:** protocol and code have not been reviewed by third parties.

## Assumptions

* The sender has the correct receiver public key out of band.
* The OS random number generator is sound.
* The RustCrypto and dalek implementations are correct.
