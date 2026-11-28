# Testing

```bash
cargo test                                  # everything below except coverage-guided fuzzing
cargo test --test properties                # property-based tests only
cargo test --test fuzz_smoke                # deterministic mutation fuzzing
cargo run -- matrix                         # scenario matrix (see EVALUATION.md)
```

## Layers

| Layer | Where | What it protects |
|---|---|---|
| Unit tests | `src/**` | Codec, crypto wrappers, policy, detection maths |
| Scenario tests | `tests/scenarios.rs`, `failure_classification.rs`, `toctou.rs` | Outcomes and the protocol stage at which each attack fails |
| Receiver hardening | `authorization.rs`, `session_hardening.rs`, `limits.rs` | Authorization, replay, expiry, caps, backpressure |
| Canary tests | `canary_isolation.rs`, `canary_service.rs` | Session scoping, the external service, forged and replayed answers |
| Property tests | `tests/properties.rs` (proptest) | Wire-format laws, parser totality, receiver state-machine invariants |
| Fuzz smoke | `tests/fuzz_smoke.rs` | No panics, well-formed replies, bounded allocations on 15 000 mutated inputs per target |
| Coverage-guided fuzzing | `fuzz/` (cargo-fuzz) | Same properties, with coverage feedback, on nightly |

## Properties checked

* `decode(encode(m)) == m` for every message kind, including near-limit sizes.
* Decoding arbitrary bytes never panics, and anything accepted re-encodes to the **same bytes** (the format is canonical).
* Every strict prefix of a valid message is rejected, and so are trailing bytes.
* A length field that lies is rejected, and lengths above the limit give `TooLarge` before any allocation.
* The receiver answers every input with a well-formed message.
* Policy parsing never panics, and every accepted policy validates and round-trips.
* **State machine:** over random sequences of hellos, replayed hellos, payloads (valid, tampered, out of order), probes, closes, clock jumps, garbage and `take_delivered`, the receiver never exceeds its session, queue, byte and replay-cache limits; never acknowledges a tampered, closed or expired payload; keeps sequence numbers strictly increasing; never accepts a replayed hello; and delivers exactly the acknowledged payloads in order.

## Reproducing and shrinking failures

Property tests are **deterministic**: the seed is fixed, so CI runs are repeatable.

```bash
PG_PROP_CASES=5000 cargo test --release --test properties   # more cases
PG_PROP_SEED=7 cargo test --release --test properties       # a different seed
```

When a property fails, proptest shrinks it to a minimal input, prints it, and writes it to `proptest-regressions/properties.txt`. That file is replayed first on every run. Commit it together with the fix.

Deterministic fuzz smoke: `PG_FUZZ_ITERS=200000 cargo test --release --test fuzz_smoke`. The seed is fixed. Change `0x00F0_221E` in the test to explore.

## Coverage-guided fuzzing

Needs nightly Rust and `cargo install cargo-fuzz`.

```bash
cargo run --example gen_fuzz_seeds                  # (re)create the seed corpus in fuzz/corpus
cargo +nightly fuzz run message_decode -- -max_total_time=120
cargo +nightly fuzz list
```

Targets: `message_decode`, `receiver_handle`, `policy_toml`, `canary_service_request`, `canary_scan`. A crash is saved under `fuzz/artifacts/<target>/`. Reproduce it with `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`.

CI runs the same targets weekly (`.github/workflows/fuzz.yml`) and uploads crashing inputs as artifacts.

## Triage procedure

1. Reproduce with the saved input or the printed minimal case.
2. Decide whether it is a protocol flaw, an implementation bug or a test bug. A reachable panic, unbounded allocation, accepted forgery or invariant violation is a **security-relevant bug**: handle it as described in [SECURITY.md](../SECURITY.md) if it is exploitable.
3. Add a regression test (a unit or integration test with the minimal input, or the committed `proptest-regressions` entry) **before** fixing.
4. Fix, then confirm the regression test and the full suite pass.
5. Add a line to the changelog.

## Results so far

The property suite and the smoke fuzzer were run with the default seed and with three further seeds at 3 000 cases per property. No violations were found. That is evidence the parsers and receiver are robust against the input classes covered, not a proof. Coverage-guided fuzzing has not yet been run for a meaningful duration, so treat the receiver and the canary service parser as unfuzzed in depth.
