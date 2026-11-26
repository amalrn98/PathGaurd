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

## Next up

- [ ] Real transports: UDP and QUIC `Path` implementations, plus a `pathguard-recv` daemon
- [ ] Receiver session expiry and eviction
- [ ] `cargo-fuzz` targets for `Message::decode` and `Receiver::handle`
- [ ] Traffic padding and timing obfuscation options
- [ ] Network namespace test bench with `tc netem`
- [ ] Structured audit output (JSON) and OpenTelemetry export
- [ ] Hop discovery helpers (traceroute and ASN lookup) feeding diversity scoring
- [ ] Noise Protocol Framework handshake option and TLS 1.3 transport option
- [ ] Post-quantum hybrid key establishment (X25519 plus ML-KEM)
- [ ] Formal model of the handshake (Tamarin or ProVerif)
- [ ] External cryptographic and implementation audit
