# PathGuard protocol specification (draft v1)

Status: draft, matches the code in `src/`. Nothing here is audited. All integers are big endian.

## 1. Roles and keys

* **Sender** and **Receiver** each hold a long-term Ed25519 identity.
* The sender is configured with the receiver's public identity (pinning). The receiver may keep an allow-list of sender identities.
* Each session uses fresh X25519 ephemeral keys on both sides, so a later key leak does not expose past sessions (forward secrecy).

## 2. Wire format

Every message starts with a one byte tag. Variable-length fields have a `u32` length prefix.
Limits: message 1 MiB, field 512 KiB. Decoding is bounds-checked and rejects trailing bytes.

| Tag | Message | Fields |
|---|---|---|
| 1 | Hello | session_id[16], sender_eph[32], sender_id[32], recipient[32], sig[64] |
| 2 | HelloAck | session_id[16], recv_eph[32], recv_id[32], sig[64] |
| 3 | Probe | session_id[16], probe_id[16], kind u8, seq u64, body bytes, mac[32] |
| 4 | ProbeReply | session_id[16], probe_id[16], seq u64, mac[32] |
| 5 | Payload | session_id[16], seq u64, ciphertext bytes |
| 6 | PayloadAck | session_id[16], seq u64, mac[32] |
| 7 | Close | session_id[16], mac[32] |
| 8 | Reject | code u8 (1 bad request, 2 unknown session, 3 auth failed, 4 replay, 5 busy) |

Probe kinds: 0 interception, 1 bait, 2 payload-like.

## 3. Handshake

```
hello_input = "pathguard/v1/hello" || session_id || sender_eph || sender_id || recipient
Hello.sig   = Ed25519(sender_sk, hello_input)

ack_input   = "pathguard/v1/ack" || SHA256(len-prefixed hello_input) || session_id || recv_eph || recv_id
HelloAck.sig = Ed25519(receiver_sk, ack_input)
```

Receiver checks: `recipient == own id`, session id unused, valid sender signature, then **authorization**: the sender identity must be permitted by the receiver's `SenderPolicy` (deny-by-default, see [KEYS_AND_AUTHORIZATION.md](KEYS_AND_AUTHORIZATION.md)). Nothing is allocated before the authorization check passes.
Sender checks: session id echoed, `recv_id == pinned id` (constant time), valid receiver signature, X25519 output is contributory (low-order points rejected).

Naming the recipient inside the signed hello stops a hello from being replayed to a different receiver.

## 4. Key schedule

```
shared     = X25519(own_eph_secret, peer_eph_public)
transcript = SHA256(len-prefixed hello_input, len-prefixed ack_input)
PRK        = HKDF-Extract(salt = transcript, ikm = shared)
payload_key = HKDF-Expand(PRK, "pathguard/v1/payload", 32)
probe_key   = HKDF-Expand(PRK, "pathguard/v1/probe", 32)
decoy_key   = HKDF-Expand(PRK, "pathguard/v1/decoy", 32)
canary_key  = HKDF-Expand(PRK, "pathguard/v1/canary", 32)
```

The four keys are independent. Decoys use `decoy_key`, never `payload_key`, so decoy traffic contains no payload key material.
Keys are zeroized on drop. Every retry performs a new handshake, so keys are never reused across attempts.

## 5. MACs

`MAC(k, parts...)` is HMAC-SHA256 over each part prefixed with its `u32` length, so part boundaries are unambiguous.

| Use | Key | Parts |
|---|---|---|
| Probe | probe_key | "probe", session_id, probe_id, kind, seq, body |
| ProbeReply | probe_key | "reply", session_id, probe_id, seq, SHA256(content) |
| PayloadAck | probe_key | "ack", session_id, seq, SHA256(ciphertext) |
| Close | probe_key | "close", session_id |

`content` is the body for kinds 0 and 1, and the decrypted plaintext for kind 2. A valid ProbeReply therefore proves the responder holds the session keys.

## 6. Probes

* Kind 0 body: `pgprobe:<16 hex>` plus a canary token when canaries are enabled.
* Kind 1 body: plaintext bait that looks like a credential and embeds a canary token.
* Kind 2 body: `ChaCha20-Poly1305(decoy_key, nonce = probe_id[0..12], aad = session_id, random plaintext)`.

Canary tokens are `pg-canary-` followed by 24 hex characters, derived with a MAC under `canary_key`. They are unique per session and non-secret.
The receiver rejects a repeated `probe_id` (replay) and probes with a bad MAC.

## 7. Payload

```
nonce      = 0x00000000 || seq(u64)
aad        = "pathguard/v1/payload" || session_id || receiver_id || seq
ciphertext = ChaCha20-Poly1305(payload_key, nonce, aad, plaintext)
```

The receiver requires `seq` to be strictly greater than the last accepted one. Binding the receiver identity into the AAD ties the ciphertext to its intended recipient. Maximum payload accepted by the reference sender is 256 KiB.

## 8. Sender state machine

```
for attempt in 0..=max_retries:
    path order = rotate(paths, attempt)
    handshake on order[0]            -- failure: record finding, next attempt
    run probes (primary only, or all paths if multipath)
    poll honeypot for canary touches
    decide(policy, findings, path reports)
    if allowed: send payload, require valid PayloadAck, send Close
    else:       send Close (best effort), drop keys, next attempt
```

If the payload was sent but no valid ack arrives, the sender stops and reports `DeliveryUnconfirmed`. It does not retry, because the receiver may already hold the data.

## 9. Decision rules

Findings carry a severity: Low 0.25, Medium 0.5, Critical 100.

Withhold when any of these hold:

1. A Critical finding exists on the primary path or at session level (handshake failure, bad reply MAC, rejected probe, canary trigger).
2. The summed weight of relevant findings reaches `max_suspicion_score` (default 1.0).
3. The primary path did not verify (fewer than half of its probes valid).
4. With multipath: fewer than `min_verified_paths` verified paths, or, when two or more are required, the minimum pairwise diversity is below `min_path_diversity`.

With `tolerate_failed_secondary_paths`, a secondary path that fails verification or shows Medium or worse findings is excluded from the decision. Its findings still appear in the report as alerts. Canary triggers are session-level and are never excluded.

## 10. Receiver limits

At most 1024 concurrent sessions and 4096 remembered probe ids per session. Sessions have no timeout yet (see roadmap). The receiver never panics on network input.
