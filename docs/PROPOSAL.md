# PathGuard: an adaptive, decoy-assisted and authenticated data transmission security protocol

*Original project proposal. Preserved as the starting point of the project. The implementation status is tracked in the [roadmap](ROADMAP.md), and where the code differs from this text, [PROTOCOL.md](PROTOCOL.md) is authoritative.*

Project type: open-source cybersecurity and network protocol research
Status at proposal time: concept and preliminary architecture
Primary focus: secure data transmission, interception detection, path validation and deceptive packet mechanisms
Development approach: modular, configurable and extensible

## 1. Executive summary

PathGuard is a proposed open-source communication security project designed to investigate how digital information can be protected when transmitted between two endpoints over potentially compromised or manipulated network pathways.

The central concept is to introduce a verification and deception layer before transmitting sensitive information. When a sender (A) intends to transmit data to a receiver (B), the system first sends one or more decoy or tracker packets. These packets help identify suspicious network behaviour, detect unexpected redirection, test receiver authentication and evaluate multiple transmission pathways.

Only after the required security conditions are satisfied does the system release the encrypted payload. If suspicious activity is detected, the system can withhold the payload, terminate the affected session, rotate session keys and initiate a new verification process.

PathGuard proposes four independently configurable mechanisms:

1. Interception detection.
2. Active decoy attraction.
3. Multi-path verification.
4. Payload-like decoy packets.

A fifth complementary mechanism, canary-triggered session invalidation, is also proposed. The project aims to combine established cryptographic security with experimental deception-based network monitoring.

## 2. Problem statement

A simplified communication model is A to B. During transmission, several threats can arise: malicious routing or destination redirection, man-in-the-middle attacks, packet interception and duplication, packet modification, replay attacks, malicious network intermediaries, traffic analysis and compromised network infrastructure.

Conventional encryption protects message contents, but it does not necessarily prevent an attacker from observing traffic, disrupting communication or manipulating its routing. PathGuard investigates whether additional decoy-based verification and active monitoring can improve the detection of these threats before sensitive payload delivery.

## 3. Core concept

Verify the communication environment before releasing the actual payload.

Instead of immediately transmitting sensitive information, the sender initiates a preliminary verification phase using decoy packets, cryptographic challenges and optional multi-path testing. The intended receiver must demonstrate its identity through an authenticated response. The sender evaluates the results against a configurable security policy. If verification succeeds, the encrypted payload is released. If verification fails or suspicious activity is detected, the transmission is withheld or terminated.

Network routing can legitimately change. PathGuard should therefore distinguish normal route changes from destination impersonation, unexpected packet behaviour and failed authentication.

## 4. Proposed system architecture

Components: Sender, Decoy Packet Generator, Path Verification Engine, Multi-Path Controller, Security Policy Engine, Payload Release Controller, Receiver.

Transmission workflow:

1. Sender A prepares information for receiver B.
2. The payload is encrypted and bound to B's authenticated identity.
3. PathGuard generates decoy probes.
4. The policy engine selects the enabled verification mechanisms.
5. Probe packets are transmitted.
6. Responses are collected and authenticated.
7. The verification engine evaluates the results.
8. If the security policy is satisfied, the encrypted payload is released.
9. If verification fails, the payload remains withheld.
10. The affected session may be terminated, and new session keys generated.

## 5. Four core security mechanisms

**A. Interception detection.** Detect suspicious behaviour associated with packet interception, duplication, modification or unexpected redirection, using decoy probes with unique identifiers. Limitation: interception cannot always be proven through timing or packet duplication alone.

**B. Active decoy attraction.** Introduce controlled deceptive traffic that can help expose malicious intermediaries, without real credentials or useful payloads. Limitation: a decoy cannot guarantee that an attacker will interact with it, so this mechanism is supplementary.

**C. Multi-path verification.** Evaluate multiple independent network pathways before releasing sensitive information. Limitation: multiple routes may share the same underlying infrastructure, so path diversity must be measured rather than assumed.

**D. Payload-like decoy packets.** Deceptive packets that resemble real application traffic but contain no useful information. The decoy must never contain reusable cryptographic material or actual confidential data.

## 6. Canary-triggered session invalidation

Each session can contain unique, non-secret canary identifiers. If a canary appears in an unexpected context, the system generates an alert and, depending on policy, terminates the session, invalidates its keys, withholds pending payloads, initiates a new authenticated handshake and records an incident. Canary detection is an indicator of possible exposure, not definitive proof of interception.

## 7. Configurable security architecture

All four core mechanisms should be optional and independently configurable. A low-bandwidth environment may use only interception detection and cryptographic authentication. A high-security research environment may enable all mechanisms. A multi-network infrastructure may prioritise multi-path verification. A monitoring environment may use active decoys to study suspicious interactions.

## 8. Cryptographic foundation

PathGuard should use established cryptographic standards rather than inventing its own algorithms: AES-256-GCM or ChaCha20-Poly1305 for authenticated encryption, X25519 for key agreement, Ed25519 for signatures, TLS 1.3 for transport and the Noise Protocol Framework for handshakes. Requirements: forward secrecy, replay protection, receiver identity binding, nonce management, session key rotation, secure failure handling and authentication before payload release. Post-quantum key establishment may be investigated later.

## 9. Threat model

Destination spoofing (receiver authentication), man-in-the-middle (authenticated key establishment), packet modification (authenticated encryption), replay and duplication (nonces, sequence numbers, session ids), malicious intermediary (decoy monitoring), route manipulation (multi-path observations and endpoint authentication), traffic analysis (optional padding and timing obfuscation), session compromise (termination and key rotation).

No decoy packet can guarantee that a network pathway is free from interception. An attacker may relay verification packets to the genuine receiver and forward its response (a relay attack). PathGuard must rely on cryptographic endpoint authentication and challenge-response protocols, and must not treat route changes as automatic evidence of compromise.

## 10. Failure and recovery

If the intended receiver cannot be authenticated, sensitive information must not be released. Stop payload transmission, mark the session unverified, record the event, invalidate affected keys, initiate a fresh handshake, retry through an alternative path if appropriate, and abort if verification continues to fail. This prioritises confidentiality and integrity over uninterrupted delivery.

## 11. Proposed technology stack

Rust core, audited cryptographic libraries, QUIC/UDP/TCP, Protobuf or CBOR, TOML configuration, OpenTelemetry, Rust test tooling, Linux network namespaces for simulation, Markdown documentation.

## 12. Development roadmap

Phase 1 research and specification. Phase 2 core transmission prototype. Phase 3 decoy mechanisms. Phase 4 multi-path verification. Phase 5 adaptive security policy. Phase 6 independent security evaluation.

## 13. Evaluation metrics

Interception detection rate, false-positive rate, authentication failure detection, latency, bandwidth overhead, CPU and memory overhead, recovery time, path diversity. Compare standard authenticated encryption, with decoy detection, with multi-path verification, the combined four-mechanism configuration, and the combined configuration with canary monitoring.

## 14. Open-source development model

Open protocol specification, transparent security architecture, reproducible experiments, independent audits, modular implementations, no proprietary cryptographic dependencies and community-driven development, under a licence such as Apache-2.0.

## 15. Research questions

1. Can decoy packets improve the detection of malicious network intermediaries?
2. Can multiple independent verification paths reduce dependence on a compromised route?
3. Can payload-like decoys expose suspicious packet interactions?
4. Can adaptive verification provide measurable benefits without excessive transmission overhead?
5. How effectively can the system distinguish legitimate routing changes from malicious redirection?
6. What are the limitations of decoy-assisted verification against sophisticated relay attacks?
7. Can the proposed mechanisms improve security when combined with established authenticated encryption?

## 16. Conclusion

Cryptographic authentication and encryption provide the fundamental security guarantees. Decoy mechanisms supplement them with additional monitoring and detection. PathGuard should be treated as a research and experimental protocol, with its effectiveness established through controlled testing, threat modelling and independent security review before any production security claim is made.
