# Keys, authentication and authorization

These are three different questions, and PathGuard answers each one separately.

| Question | Mechanism | Where |
|---|---|---|
| Did the holder of this public key sign the hello? | Ed25519 signature over the hello | Authentication |
| Is that key allowed to send to this receiver? | `SenderPolicy` | **Authorization** |
| Is this the receiver I meant to talk to? | Pinned receiver identity, signed ack | Sender-side authentication |

A valid signature alone proves nothing about permission. Any party can generate a key pair and sign a hello.

## Receiver policy: deny by default

`Receiver::new` starts with `SenderPolicy::DenyAll`. Until you configure a policy, every hello is refused, and no session or key material is created for it.

```rust
use pathguard::{Identity, Receiver, SenderPolicy};

let mut recv = Receiver::new(Identity::generate());
recv.allow_sender(alice_public);              // allow-list (narrowing, never widening)
recv.revoke_sender(&alice_public);            // revocation, closes alice's live sessions
recv.set_sender_policy(SenderPolicy::DenyAll); // replace the policy, closes disallowed sessions
recv.allow_any_authenticated_sender();        // explicit opt-out of authorization
```

* `AllowList` is the normal production mode.
* `AllowAnyAuthenticated` exists for public services and tests. It gives authentication without authorization, and the name says so.
* `allow_sender` on a deny-all or allow-any receiver produces an allow-list containing only that identity, so the call can never silently widen access.

The check runs after the signature is verified and before any key agreement or session state exists. A refused hello costs the receiver one signature verification and allocates nothing.

On the wire, an unauthorized sender and a forged signature produce the same `Reject(AuthFailed)`, so a remote party cannot probe which identities are trusted. Locally, `Receiver::stats().rejected_unauthorized` counts them for operators.

## Provisioning

1. The sender runs `pathguard keygen sender.key` and keeps the seed file private (mode 0600). It prints the public identity and a short fingerprint.
2. The sender gives the receiver operator the public identity over a channel the operator trusts, and compares fingerprints out of band.
3. The operator adds it with `allow_sender`.
4. The receiver operator gives the sender the **receiver's** public identity the same way. The sender pins it when it builds a `Sender`.

PathGuard does not provide a PKI, certificate chain or trust-on-first-use. Both sides pin keys explicitly.

## Rotation and revocation

* **Rotation:** generate a new key, allow it on the receiver, switch the sender, then revoke the old one.
* **Revocation:** `revoke_sender` removes the identity and closes its sessions immediately. Payloads already delivered are not affected.
* The policy lives in memory. A deployment that needs it persisted must load it at start-up from its own configuration store.
* There is no revocation list distributed between receivers. Each receiver is authoritative for itself.
