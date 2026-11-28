# Roadmap

Phases follow the original [proposal](PROPOSAL.md).

| Phase | Scope | Status |
|---|---|---|
| 1 | Threat model, trust model, packet formats, handshake, policy, documented limits | Done (draft v1) |
| 2 | Authenticated communication, receiver identity, encrypted delivery, replay protection, session termination | Done in the reference implementation |
| 3 | Decoy generator, interception indicators, payload-like decoys, decoy monitoring, canaries | Done in simulation |
| 4 | Multi-path probing, response comparison, diversity, route manipulation tests, overhead | Core logic done. Needs real paths |
| 5 | Configurable policy, incident logging, automated revalidation | Policy and audit log done. Structured logs and OpenTelemetry pending |
| 6 | Independent evaluation, pen test, relay and replay testing, FP/FN rates, audits | Not started |

## Maturity levels

The project status is tracked by evidence, not by feel. The criteria are the same as in the [README](../README.md#status-and-maturity):

* **Research prototype (current):** reference implementation, tests, documented limits.
* **Alpha:** real transports, long fuzz runs, real-network measurements with false-positive rates, a formal handshake model.
* **Beta:** independent protocol and code review, a versioned and stable wire format.
* **Stable:** a completed external audit and published fixes for its findings.

## Next up

- [ ] Real transports: UDP and QUIC `Path` implementations, plus a `pathguard-recv` daemon
- [x] Receiver session expiry, caps and rate limits (session lifetime, per-sender caps, handshake rate limit)
- [x] `cargo-fuzz` targets for the decoder, receiver, policy parser and canary service (scheduled in CI)
- [ ] Long coverage-guided fuzz runs and triage of results
- [ ] Traffic padding and timing obfuscation options
- [ ] Network namespace test bench with `tc netem`
- [ ] Structured audit output (JSON) and OpenTelemetry export
- [ ] Hop discovery helpers (traceroute and ASN lookup) feeding diversity scoring
- [ ] Noise Protocol Framework handshake option and TLS 1.3 transport option
- [ ] Post-quantum hybrid key establishment (X25519 plus ML-KEM)
- [ ] Formal model of the handshake (Tamarin or ProVerif)
- [ ] External cryptographic and implementation audit
