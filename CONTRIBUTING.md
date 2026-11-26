# Contributing to PathGuard

Thank you for helping. This is a security research project, so critical review is as valuable as code. Good first contributions:

* A new adversary or scenario for the simulator that breaks an assumption.
* Review of [PROTOCOL.md](docs/PROTOCOL.md) and [THREAT_MODEL.md](docs/THREAT_MODEL.md).
* Fuzz targets, property tests, real transports, measurements.
* Documentation fixes.

By contributing you agree that your contribution is licensed under Apache-2.0 (see [LICENSE](LICENSE)). Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Setup

You need Rust 1.88 or newer.

```bash
git clone https://github.com/amalrn98/PathGuard.git
cd PathGuard
cargo test
cargo run -- matrix
```

## Before you open a pull request

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs the same checks. Please also:

* Keep pull requests focused. One topic per PR.
* Add tests. Anything that touches the protocol, key schedule, decision rules or parsing needs a test that fails without the change.
* Update the docs when behaviour changes. `docs/PROTOCOL.md` must match the code.
* If a scenario outcome changes in `tests/scenarios.rs`, explain why in the PR. Those expectations encode security decisions.

## Rules for security-sensitive code

* **No custom cryptographic primitives.** Use the existing RustCrypto and dalek crates, and keep every primitive call inside `src/crypto.rs`.
* **No panics on network input.** Parsing and receiver code must return errors. Avoid `unwrap`, `expect` and unchecked indexing there.
* **No secrets in decoys, logs or errors.**
* **Zeroize** key material on drop.
* New dependencies need a reason in the PR. Prefer well-maintained, widely used crates.
* Constant-time comparison (`util::ct_eq`) for anything derived from secrets.

## Adding a scenario

1. Add a `Behavior` variant in `src/sim.rs` if you need a new adversary capability.
2. Add a `Scenario` to `scenarios()`.
3. Run `cargo run -- matrix`, check the result is what the design says it should be, and add expectations to `tests/scenarios.rs` and a line to `docs/EVALUATION.md`.

## Commit messages

Short imperative summary line, then a body that explains why. Reference issues with `#123`.

## Reporting vulnerabilities

Do not file them as issues. See [SECURITY.md](SECURITY.md).

## Questions

Open a discussion or issue, or message the maintainer on Discord at **@mythicavalon**.
