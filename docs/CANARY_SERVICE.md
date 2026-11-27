# Canary service

A canary token only means something if touching it can be observed **outside** the sender. The in-process `Honeypot` is for the simulator. For real deployments PathGuard ships a separately deployable listener (`CanaryService`) and a sender-side client (`RemoteCanary`).

## Run it

```bash
pathguard canary-keygen canary.key          # shared reporting key, mode 0600
pathguard canary-serve --listen 0.0.0.0:8099 --key-file canary.key
```

Options: `--ttl SECS` (retention, default 86 400), `--log-source` (store peer addresses, off by default).

Sender side:

```rust
use pathguard::canary_service::RemoteCanary;
use pathguard::clock::SystemClock;
use std::sync::Arc;

let remote = RemoteCanary::new("canary.example.org:8099", key, Arc::new(SystemClock));
let sender = Sender::new(identity, receiver_pub, Policy::paranoid())
    .with_canary_source(Arc::new(remote))
    .with_bait_base_url("https://canary.example.org");   // bait URLs: <base>/c/<token>
```

Put TLS in front of the service (a reverse proxy is enough). The reporting key authenticates answers but does not hide the token list.

## How a token gets from the sender to an alert

1. The sender derives tokens from the session canary key (HKDF output, so unguessable and unique per session).
2. **Before** any bait leaves, the sender calls `POST /register` with the tokens it is about to use. The body is authenticated with HMAC-SHA256 under the reporting key and carries a nonce and a timestamp.
3. Bait carrying the token (`<base>/c/<token>`) is sent in probes.
4. If anyone fetches `GET /c/<token>`, the service records an event, but **only for registered tokens**. The reply is always `200 ok`, so a visitor cannot learn which tokens are registered, and random traffic cannot fill the store.
5. The sender polls `GET /events?nonce=<n>&tokens=<its tokens>`. The answer contains the nonce, the service time, the events, and an HMAC over all of it **including the question**.

## What the authentication buys

| Attack | Result |
|---|---|
| Forged event added to an answer | Tag invalid, `Untrusted` |
| Real event silently removed | Tag invalid, `Untrusted` |
| Old genuine answer replayed | Nonce mismatch, `Untrusted` |
| Answer for a different token list | Tag invalid, `Untrusted` |
| Answer with a stale timestamp | Rejected (120 s skew) |
| Someone else's key | Registration answers 401, `Untrusted` |
| Random hits on the bait URL | Ignored unless registered; same reply as a registered token |

Because the answer is authenticated, **"no events" is itself a signed statement** that the service answered this question at this time.

## When the service cannot be reached

An outage is not a clean path.

* The report carries `canary_status: Unchecked` (as opposed to `Checked` or `NotUsed`) and a `CanarySourceFailure` finding.
* The finding is `Medium` by default (the send continues, with reduced confidence and a visible record).
* With `canary_required = true` (the `paranoid` preset) it is `Critical` and the payload is withheld.
* An answer that fails authentication is `Critical` under every policy, because it is evidence of tampering, not only an outage.

## Late events

A touch after release cannot undo a delivery. `Sender::collect_late_events()` polls for all remembered sessions (the latest 256), returns each event once with its session id, and marks the session compromised (`compromised_sessions()`). Sessions are single-use, so no later `send` reuses compromised keys. What to do about it (rotate keys, investigate the receiver, alert) is up to the application. A touch is an indicator of exposure, not proof of interception.

## Privacy and retention

* Events hold the token, a timestamp and a source label. The label is the literal `external` unless `--log-source` is set.
* Events and registrations expire after the TTL. Held registrations (100 000) and events (10 000) are capped; the oldest events go first.
* Tokens are random-looking and carry no payload, identity or session data.

## Limits

* The HTTP server is deliberately small (standard library only, 64 concurrent connections, 3 s timeouts, 16 KiB head, 256 KiB body). Put it behind a real proxy for anything public.
* The reporting key is symmetric and shared by the service and every sender it serves. Rotate it by deploying a new key to both sides.
* The service is a single instance with in-memory state. A restart forgets registrations and events.
* The service sees every touch from anyone who finds the bait, including scanners. A hit is a signal to investigate, not a verdict.
