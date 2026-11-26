# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/), and the project follows [Semantic Versioning](https://semver.org/) once it has stable releases.

## [Unreleased]

### Changed (breaking, draft protocol)

- Receivers are deny-by-default: a sender must be allowed explicitly (`allow_sender`, `set_sender_policy`) or the receiver must opt out with `allow_any_authenticated_sender` (#10).
- The hello message carries a signed timestamp. Receivers reject stale or future hellos, replayed hellos (bounded replay cache), expired sessions, and enforce handshake rate and session caps (#9). New reject codes `Stale` (6) and `TooLarge` (7).

### Added

- Reference implementation in Rust: Ed25519 pinned-identity handshake, X25519 key agreement, HKDF key schedule, ChaCha20-Poly1305 payload encryption.
- Sender and receiver state machines with replay protection, authenticated probe replies, authenticated close.
- Mechanisms A to E: interception detection, active decoys, multi-path verification, payload-like decoys, canary invalidation.
- TOML policies with `baseline`, `balanced` and `paranoid` presets and validation.
- Deterministic network simulator with 13 adversary and network scenarios.
- `pathguard` CLI: `demo`, `scenarios`, `matrix`, `policy`, `keygen`.
- Protocol specification, threat model, architecture, evaluation and roadmap documents.

### Changed

- Upgraded the cryptography and randomness stack together: `chacha20poly1305` 0.11, `hmac` 0.13, `hkdf` 0.13, `sha2` 0.11, `ed25519-dalek` 3, `x25519-dalek` 3, `rand` 0.10, `toml` 1.2.
- Minimum supported Rust version raised from 1.85 to 1.88.
- CI uses `actions/checkout@v7`.

### Fixed

- Repository URL typo (`PathGaurd`) in the README, `Cargo.toml`, `CITATION.cff`, `NOTICE`, `CONTRIBUTING.md` and issue template config.
