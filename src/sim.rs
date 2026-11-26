//! Deterministic in-memory network simulator.
//!
//! Used by the test-suite, the benchmark-style scenario matrix and the CLI.
//! Time is virtual: round-trip times are values, not sleeps, so runs are fast
//! and repeatable. Adversaries are small and explicit so each scenario shows
//! exactly which capability the attacker has.

use crate::canary::{self, Honeypot};
use crate::crypto::{sha256, Ephemeral, Identity, PublicIdentity};
use crate::handshake::{ack_input, hello_input};
use crate::message::{Message, TAG_PAYLOAD, TAG_PROBE};
use crate::path::{Path, PathError, PathResponse};
use crate::policy::Policy;
use crate::receiver::Receiver;
use crate::sender::{SendError, SendReport, Sender};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The payload used by the scenario matrix.
pub const PAYLOAD: &[u8] = b"top secret: launch codes 0000";

/// Shared log of everything an on-path observer saw in requests.
pub type Capture = Arc<Mutex<Vec<Vec<u8>>>>;

/// What a simulated path does to traffic.
#[derive(Clone)]
pub enum Behavior {
    /// Forwards faithfully.
    Honest,
    /// Never answers.
    Drop,
    /// Drops the first `first` probe messages, then behaves honestly (a lossy link).
    DropProbes {
        /// Number of probe messages to drop.
        first: u32,
    },
    /// Flips a bit in probes and payloads before they reach the receiver.
    TamperProbes,
    /// Flips a bit in every response.
    TamperResponses,
    /// Duplicates probe replies.
    DuplicateReplies,
    /// Answers the handshake itself with an attacker identity (man in the middle).
    Impersonate(Arc<Identity>),
    /// Forwards everything verbatim and adds latency. Models a relay attack.
    Relay {
        /// Added round-trip time in milliseconds.
        extra_ms: f64,
    },
    /// Forwards, and touches any canary token it sees in plaintext.
    Snoop,
    /// Honest, but latency jumps after `probes` probe messages.
    SpikeAfter {
        /// Probe messages before the spike.
        probes: u32,
        /// Latency multiplier.
        factor: f64,
    },
}

/// A simulated route to the receiver.
pub struct SimPath {
    id: String,
    hops: Vec<String>,
    receiver: Arc<Mutex<Receiver>>,
    behavior: Behavior,
    rng: StdRng,
    base_ms: f64,
    honeypot: Honeypot,
    capture: Capture,
    probe_msgs: u32,
}

impl SimPath {
    fn impersonate(&self, att: &Identity, req: &[u8]) -> PathResponse {
        let reply = match Message::decode(req) {
            Ok(Message::Hello { session_id, sender_eph, sender_id, recipient, .. }) => {
                let eph = Ephemeral::generate();
                let hi = hello_input(&session_id, &sender_eph, &sender_id, &recipient);
                let rid = att.public().0;
                let ai = ack_input(&sha256(&[&hi]), &session_id, &eph.public, &rid);
                Message::HelloAck { session_id, recv_eph: eph.public, recv_id: rid, sig: att.sign(&ai) }
            }
            _ => Message::Reject { code: crate::message::RejectCode::UnknownSession },
        };
        PathResponse { replies: vec![reply.encode()], rtt: Duration::from_secs_f64(self.base_ms / 1000.0) }
    }
}

impl Path for SimPath {
    fn id(&self) -> &str {
        &self.id
    }
    fn hops(&self) -> &[String] {
        &self.hops
    }
    fn exchange(&mut self, req: &[u8]) -> Result<PathResponse, PathError> {
        if let Ok(mut c) = self.capture.lock() {
            c.push(req.to_vec());
        }
        let tag = req.first().copied();
        if tag == Some(TAG_PROBE) {
            self.probe_msgs += 1;
        }
        let jitter = 1.0 + self.rng.gen_range(-0.05..0.05);
        let mut rtt_ms = self.base_ms * jitter;
        let mut forwarded = req.to_vec();
        match &self.behavior {
            Behavior::Drop => return Err(PathError::Timeout),
            Behavior::DropProbes { first } => {
                if tag == Some(TAG_PROBE) && self.probe_msgs <= *first {
                    return Err(PathError::Timeout);
                }
            }
            Behavior::TamperProbes => {
                if tag == Some(TAG_PROBE) || tag == Some(TAG_PAYLOAD) {
                    if let Some(l) = forwarded.last_mut() {
                        *l ^= 1;
                    }
                }
            }
            Behavior::Snoop => {
                for t in canary::scan(req) {
                    self.honeypot.touch(&t, &format!("snooper on path {}", self.id));
                }
            }
            Behavior::Relay { extra_ms } => rtt_ms += *extra_ms,
            Behavior::SpikeAfter { probes, factor } => {
                if self.probe_msgs > *probes {
                    rtt_ms *= *factor;
                }
            }
            Behavior::Impersonate(att) => return Ok(self.impersonate(att, req)),
            Behavior::Honest | Behavior::TamperResponses | Behavior::DuplicateReplies => {}
        }
        let mut reply = self.receiver.lock().map_err(|_| PathError::Closed)?.handle(&forwarded);
        let replies = match &self.behavior {
            Behavior::TamperResponses => {
                if let Some(l) = reply.last_mut() {
                    *l ^= 1;
                }
                vec![reply]
            }
            Behavior::DuplicateReplies if tag == Some(TAG_PROBE) => vec![reply.clone(), reply],
            _ => vec![reply],
        };
        Ok(PathResponse { replies, rtt: Duration::from_secs_f64(rtt_ms / 1000.0) })
    }
}

/// One sender, one receiver, and the shared observation points.
pub struct World {
    receiver: Arc<Mutex<Receiver>>,
    recipient: PublicIdentity,
    sender_seed: [u8; 32],
    honeypot: Honeypot,
    capture: Capture,
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

impl World {
    /// Fresh identities and an empty network.
    pub fn new() -> Self {
        let sender_id = Identity::generate();
        let mut recv = Receiver::new(Identity::generate());
        recv.allow_sender(sender_id.public());
        let recipient = recv.public();
        Self {
            receiver: Arc::new(Mutex::new(recv)),
            recipient,
            sender_seed: sender_id.seed_bytes(),
            honeypot: Honeypot::new(),
            capture: Arc::new(Mutex::new(Vec::new())),
        }
    }
    /// A sender pinned to this world's receiver and sharing its honeypot.
    pub fn sender(&self, policy: Policy) -> Sender {
        Sender::new(Identity::from_seed(self.sender_seed), self.recipient, policy).with_honeypot(self.honeypot.clone())
    }
    /// Receiver identity.
    pub fn recipient(&self) -> PublicIdentity {
        self.recipient
    }
    /// A path with the given behavior. `seed` drives the latency jitter.
    pub fn path(&self, id: &str, hops: &[&str], seed: u64, behavior: Behavior) -> Box<dyn Path> {
        Box::new(SimPath {
            id: id.to_string(),
            hops: hops.iter().map(|s| s.to_string()).collect(),
            receiver: self.receiver.clone(),
            behavior,
            rng: StdRng::seed_from_u64(seed),
            base_ms: 20.0,
            honeypot: self.honeypot.clone(),
            capture: self.capture.clone(),
            probe_msgs: 0,
        })
    }
    /// A faithful path.
    pub fn honest_path(&self, id: &str, hops: &[&str], seed: u64) -> Box<dyn Path> {
        self.path(id, hops, seed, Behavior::Honest)
    }
    /// Payloads the receiver has accepted.
    pub fn take_delivered(&self) -> Vec<Vec<u8>> {
        self.receiver.lock().map(|mut r| r.take_delivered()).unwrap_or_default()
    }
    /// Live receiver sessions.
    pub fn receiver_sessions(&self) -> usize {
        self.receiver.lock().map(|r| r.session_count()).unwrap_or(0)
    }
    /// True if any observed request contained `needle` in the clear.
    pub fn observed_in_clear(&self, needle: &[u8]) -> bool {
        self.capture.lock().map(|c| c.iter().any(|m| m.windows(needle.len()).any(|w| w == needle))).unwrap_or(false)
    }
}

/// A named attack or network condition.
pub struct Scenario {
    /// Short name.
    pub name: &'static str,
    /// One-line description.
    pub description: &'static str,
    /// Builds the paths for a world.
    pub build: fn(&World) -> Vec<Box<dyn Path>>,
}

fn three(w: &World, a: Behavior, b: Behavior, c: Behavior) -> Vec<Box<dyn Path>> {
    vec![
        w.path("a", &["isp-a", "ix-1", "dst"], 11, a),
        w.path("b", &["isp-b", "ix-2", "dst"], 22, b),
        w.path("c", &["isp-c", "ix-3", "dst"], 33, c),
    ]
}

/// All built-in scenarios.
pub fn scenarios() -> Vec<Scenario> {
    use Behavior::*;
    vec![
        Scenario {
            name: "honest",
            description: "three clean, independent paths",
            build: |w| three(w, Honest, Honest, Honest),
        },
        Scenario {
            name: "lossy-link",
            description: "primary loses its first probe (benign packet loss)",
            build: |w| three(w, DropProbes { first: 1 }, Honest, Honest),
        },
        Scenario {
            name: "latency-spike",
            description: "primary latency jumps 4x mid-verification",
            build: |w| three(w, SpikeAfter { probes: 2, factor: 4.0 }, Honest, Honest),
        },
        Scenario {
            name: "mitm-all-paths",
            description: "attacker answers the handshake on every path with its own identity",
            build: |w| {
                let att = Arc::new(Identity::generate());
                three(w, Impersonate(att.clone()), Impersonate(att.clone()), Impersonate(att))
            },
        },
        Scenario {
            name: "mitm-one-path",
            description: "attacker impersonates the receiver on the primary path only",
            build: |w| three(w, Impersonate(Arc::new(Identity::generate())), Honest, Honest),
        },
        Scenario {
            name: "tamper-primary",
            description: "primary path modifies probes and payload in transit",
            build: |w| three(w, TamperProbes, Honest, Honest),
        },
        Scenario {
            name: "tamper-secondary",
            description: "a secondary path modifies probes; primary is clean",
            build: |w| three(w, Honest, TamperProbes, Honest),
        },
        Scenario {
            name: "forged-replies",
            description: "primary corrupts replies on the way back",
            build: |w| three(w, TamperResponses, Honest, Honest),
        },
        Scenario {
            name: "duplicate-replies",
            description: "primary duplicates every probe reply",
            build: |w| three(w, DuplicateReplies, Honest, Honest),
        },
        Scenario {
            name: "snooping-primary",
            description: "primary reads plaintext bait and touches its canary tokens",
            build: |w| three(w, Snoop, Honest, Honest),
        },
        Scenario {
            name: "snooping-secondary",
            description: "a secondary path touches canary tokens it sees",
            build: |w| three(w, Honest, Snoop, Honest),
        },
        Scenario {
            name: "passive-relay",
            description: "attacker relays every message verbatim (cannot be told apart)",
            build: |w| three(w, Relay { extra_ms: 6.0 }, Honest, Honest),
        },
        Scenario {
            name: "shared-infrastructure",
            description: "three paths that look different but share the same hops",
            build: |w| {
                vec![
                    w.honest_path("a", &["isp-a", "ix-1", "dst"], 11),
                    w.honest_path("b", &["isp-a", "ix-1", "dst"], 22),
                    w.honest_path("c", &["isp-a", "ix-1", "dst"], 33),
                ]
            },
        },
    ]
}

/// Result of one scenario under one policy.
pub struct Outcome {
    /// Scenario name.
    pub scenario: &'static str,
    /// Policy name.
    pub policy: String,
    /// The receiver delivered the payload to its application.
    pub delivered: bool,
    /// Short status.
    pub status: &'static str,
    /// Attempts made.
    pub attempts: u32,
    /// The payload bytes appeared in cleartext to an on-path observer.
    pub plaintext_leaked: bool,
    /// Full report.
    pub report: Option<SendReport>,
}

/// Run one scenario under one policy in a fresh world.
pub fn run(scn: &Scenario, policy: &Policy) -> Outcome {
    let world = World::new();
    let sender = world.sender(policy.clone());
    let mut paths = (scn.build)(&world);
    let res = sender.send(PAYLOAD, &mut paths);
    let delivered = world.take_delivered().iter().any(|p| p == PAYLOAD);
    let (status, report) = match res {
        Ok(r) => ("delivered", Some(r)),
        Err(SendError::Withheld(r)) => ("withheld", Some(*r)),
        Err(SendError::Handshake(r)) => ("no-auth", Some(*r)),
        Err(SendError::DeliveryUnconfirmed(r)) => ("unconfirmed", Some(*r)),
        Err(SendError::Policy(_)) => ("invalid", None),
    };
    Outcome {
        scenario: scn.name,
        policy: policy.name.clone(),
        delivered,
        status,
        attempts: report.as_ref().map_or(0, |r| r.attempts),
        plaintext_leaked: world.observed_in_clear(PAYLOAD),
        report,
    }
}

/// Every scenario under every preset policy.
pub fn matrix() -> Vec<Outcome> {
    let policies = [Policy::baseline(), Policy::balanced(), Policy::paranoid()];
    let mut out = Vec::new();
    for s in scenarios() {
        for p in &policies {
            out.push(run(&s, p));
        }
    }
    out
}
