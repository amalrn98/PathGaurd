## What and why

<!-- What does this change, and why? Link issues with #123. -->

## Checklist

- [ ] `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings` and `cargo test` pass
- [ ] Tests added or updated (required for protocol, decision-rule or parsing changes)
- [ ] `docs/PROTOCOL.md` and other docs updated if behaviour changed
- [ ] No custom crypto, no secrets in decoys or logs, no panics on network input
- [ ] Changes to `tests/scenarios.rs` expectations are explained above
