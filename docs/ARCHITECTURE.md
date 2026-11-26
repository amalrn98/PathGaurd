# Architecture

```text
            +-----------------+
policy.toml |  Policy engine  |  which mechanisms, what thresholds
            +--------+--------+
                     |
+--------+   +-------v--------+   probes / payload   +----------+   +----------+
| Sender +-->| verify + decide+--------------------->|   Path   +-->| Receiver |
+--------+   +-------+--------+   (trait object)     +----------+   +----------+
                     |
            +--------v--------+
            | findings, audit |
            +-----------------+
```

| Module | Responsibility |
|---|---|
| `crypto` | The only place cryptographic primitives are called. Thin wrappers, no custom primitives. |
| `handshake` | Byte layouts that are signed and hashed. Shared by sender, receiver and the simulator. |
| `message`, `codec` | Wire format. Decoding is total: arbitrary bytes give an error, never a panic. |
| `sender` | Orchestrates handshake, probes, decision, release and retry. Holds no network code. |
| `receiver` | Pure state machine: bytes in, bytes out. Easy to fuzz and to embed behind any transport. |
| `detect` | Findings, weights, RTT baseline. |
| `canary` | Token issue and scan, honeypot log. |
| `multipath` | Diversity maths over caller-supplied hop lists. |
| `policy` | TOML schema, presets, validation. |
| `path` | `Path` trait: one request/response route. |
| `sim` | Deterministic network with explicit adversaries and the scenario matrix. |

Design rules:

* Sender and receiver are transport-agnostic. All I/O goes through `Path`.
* Time is injected as a value (`PathResponse::rtt`), which keeps tests deterministic.
* Anything the network can influence is parsed with bounds checks and answered with `Reject`.
* Secrets (`SessionKeys`, the canary key) are zeroized on drop.
* `#![deny(unsafe_code)]` is set for the crate.
