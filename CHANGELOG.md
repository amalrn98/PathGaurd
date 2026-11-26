# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/), and the project follows [Semantic Versioning](https://semver.org/) once it has stable releases.

## [Unreleased]

### Added

- Reference implementation in Rust: Ed25519 pinned-identity handshake, X25519 key agreement, HKDF key schedule, ChaCha20-Poly1305 payload encryption.
- Sender and receiver state machines with replay protection, authenticated probe replies, authenticated close.
- Mechanisms A to E: interception detection, active decoys, multi-path verification, payload-like decoys, canary invalidation.
- TOML policies with `baseline`, `balanced` and `paranoid` presets and validation.
- Deterministic network simulator with 13 adversary and network scenarios.
- `pathguard` CLI: `demo`, `scenarios`, `matrix`, `policy`, `keygen`.
- Protocol specification, threat model, architecture, evaluation and roadmap documents.
