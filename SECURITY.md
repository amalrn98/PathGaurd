# Security policy

PathGuard is an **unaudited research prototype**. It is not suitable for protecting real secrets. That said, flaws in its protocol design or code are exactly what this project wants to find.

## Reporting a vulnerability

Please report privately. Do not open a public issue for a vulnerability.

* Use GitHub's private reporting: open the **Security** tab of this repository and choose **Report a vulnerability**.
* Include: affected version or commit, a description, impact, and steps or a test that reproduces it.

You will get an acknowledgement within 7 days. This is a volunteer project with no bounty program. Reporters are credited in the changelog unless they prefer otherwise.

## What is in scope

* Flaws in the handshake, key schedule, message formats or decision rules ([PROTOCOL.md](docs/PROTOCOL.md)).
* Memory-safety, panic or resource-exhaustion bugs reachable from network input (`Message::decode`, `Receiver::handle`).
* Ways to get the sender to release a payload without an authenticated receiver, or to make the receiver accept forged data.
* Secret material leaking into probes, decoys, logs or errors.
* Incorrect use of cryptographic primitives.

## Known and intentionally out of scope

* Relay attacks are undetectable by design and documented in the [threat model](docs/THREAT_MODEL.md). They do not expose the payload.
* Traffic analysis, endpoint compromise, denial of service by a network attacker, post-quantum attacks.
* Findings that only apply to the in-memory simulator.

## Supported versions

Only the latest commit on `main`. There are no stable releases yet.

## Handling

Fixes for confirmed issues are developed privately, released with a changelog entry, and disclosed after a fix is available.
