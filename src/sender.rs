//! Sender: verify the communication environment, then release the payload.
//!
//! Flow per attempt: authenticated handshake, verification probes (according to
//! the policy), policy decision, payload release only if the decision allows it.
//! A withheld attempt tears the session down and the next attempt performs a
//! fresh handshake with new ephemeral keys, starting from the next path.

use crate::canary::{CanaryIssuer, Honeypot};
use crate::clock::{Clock, SystemClock};
use crate::crypto::{self, derive_session_keys, sha256, Ephemeral, Identity, PublicIdentity, SessionKeys};
use crate::detect::{score, summarize, Detector, Finding, FindingKind, Severity};
use crate::handshake::{ack_input, hello_input, transcript};
use crate::limits::MAX_PATHS;
use crate::message::{Message, ProbeId, ProbeKind, SessionId};
use crate::multipath::min_pairwise_diversity;
use crate::path::Path;
use crate::policy::Policy;
use crate::receiver::{ack_mac, close_mac, decoy_nonce, payload_aad, reply_mac};
use crate::util;
use rand::rngs::SysRng;
use rand::TryRng;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroize;

pub use crate::limits::MAX_PAYLOAD_BYTES as MAX_PAYLOAD;

/// Per-path verification result.
#[derive(Debug, Clone)]
pub struct PathReport {
    /// Path id.
    pub path: String,
    /// Probes sent.
    pub probes_sent: u32,
    /// Probes that returned a valid authenticated reply.
    pub probes_ok: u32,
    /// A majority of probes valid and no critical finding (one lost probe is tolerated).
    pub verified: bool,
    /// Excluded from the decision (failing secondary path, when tolerated).
    pub excluded: bool,
    /// Mean round-trip time of valid probes in milliseconds.
    pub mean_rtt_ms: f64,
}

/// Outcome and audit trail of `send`.
#[derive(Debug, Clone)]
pub struct SendReport {
    /// Policy name.
    pub policy: String,
    /// Id of the last session attempted.
    pub session_id: SessionId,
    /// The policy allowed release in the final attempt.
    pub released: bool,
    /// The receiver acknowledged the payload with a valid MAC.
    pub delivered: bool,
    /// Attempts made.
    pub attempts: u32,
    /// All findings across attempts.
    pub findings: Vec<Finding>,
    /// Suspicion score of the last decision.
    pub score: f64,
    /// Verification results of the last decision.
    pub paths: Vec<PathReport>,
    /// Minimum pairwise diversity of the verified paths, when computed.
    pub diversity: Option<f64>,
    /// Reasons the last decision withheld the payload.
    pub reasons: Vec<String>,
    /// Chronological audit log.
    pub audit: Vec<String>,
}

impl SendReport {
    fn new(policy: &str) -> Self {
        Self {
            policy: policy.to_string(),
            session_id: [0; 16],
            released: false,
            delivered: false,
            attempts: 0,
            findings: Vec::new(),
            score: 0.0,
            paths: Vec::new(),
            diversity: None,
            reasons: Vec::new(),
            audit: Vec::new(),
        }
    }
    fn log(&mut self, msg: impl Into<String>) {
        self.audit.push(msg.into());
    }
    /// Multi-line text rendering for terminals.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "policy={} attempts={} released={} delivered={} score={:.2}\n",
            self.policy, self.attempts, self.released, self.delivered, self.score
        ));
        for p in &self.paths {
            s.push_str(&format!(
                "  path {:<10} probes {}/{} verified={} excluded={} mean_rtt={:.1}ms\n",
                p.path, p.probes_ok, p.probes_sent, p.verified, p.excluded, p.mean_rtt_ms
            ));
        }
        if let Some(d) = self.diversity {
            s.push_str(&format!("  min pairwise path diversity: {d:.2}\n"));
        }
        for (f, n) in summarize(&self.findings) {
            if n > 1 {
                s.push_str(&format!("  finding (x{n}) {f}\n"));
            } else {
                s.push_str(&format!("  finding {f}\n"));
            }
        }
        for r in &self.reasons {
            s.push_str(&format!("  withheld because: {r}\n"));
        }
        s.push_str("  audit:\n");
        for (i, a) in self.audit.iter().enumerate() {
            s.push_str(&format!("    {:>2}. {a}\n", i + 1));
        }
        s
    }
}

/// Why `send` did not deliver.
#[derive(Debug, Clone)]
pub enum SendError {
    /// Invalid policy or arguments.
    Policy(String),
    /// No attempt completed a handshake with the expected receiver.
    Handshake(Box<SendReport>),
    /// The policy withheld the payload in every attempt. Nothing was sent.
    Withheld(Box<SendReport>),
    /// The payload was sent but no valid acknowledgement arrived. It is not
    /// retried automatically because the receiver may already have it.
    DeliveryUnconfirmed(Box<SendReport>),
}

impl SendError {
    /// The report, if there is one.
    pub fn report(&self) -> Option<&SendReport> {
        match self {
            SendError::Policy(_) => None,
            SendError::Handshake(r) | SendError::Withheld(r) | SendError::DeliveryUnconfirmed(r) => Some(r),
        }
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::Policy(m) => write!(f, "invalid request: {m}"),
            SendError::Handshake(_) => write!(f, "receiver could not be authenticated on any attempt"),
            SendError::Withheld(_) => write!(f, "payload withheld by policy; nothing was sent"),
            SendError::DeliveryUnconfirmed(_) => write!(f, "payload sent but not acknowledged"),
        }
    }
}

impl std::error::Error for SendError {}

struct Session {
    id: SessionId,
    keys: SessionKeys,
    probe_seq: u64,
}

struct Decision {
    allow: bool,
    reasons: Vec<String>,
    score: f64,
    diversity: Option<f64>,
}

enum AttemptResult {
    Delivered,
    Withheld,
    HandshakeFailed,
    DeliveryUnconfirmed,
}

/// Sender endpoint.
pub struct Sender {
    clock: Arc<dyn Clock>,
    identity: Identity,
    recipient: PublicIdentity,
    policy: Policy,
    honeypot: Honeypot,
}

impl Sender {
    /// New sender pinned to one receiver identity.
    pub fn new(identity: Identity, recipient: PublicIdentity, policy: Policy) -> Self {
        Self { clock: Arc::new(SystemClock), identity, recipient, policy, honeypot: Honeypot::new() }
    }
    /// Use a specific clock (tests and simulation).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
    /// Use an existing honeypot, so the thing that watches your bait and this sender share one log.
    pub fn with_honeypot(mut self, honeypot: Honeypot) -> Self {
        self.honeypot = honeypot;
        self
    }
    /// Shared honeypot handle. Whatever watches your bait must call `touch` on it.
    pub fn honeypot(&self) -> Honeypot {
        self.honeypot.clone()
    }
    /// Active policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Verify, decide, and (only if allowed) release `payload` to the pinned receiver.
    pub fn send(&self, payload: &[u8], paths: &mut [Box<dyn Path>]) -> Result<SendReport, SendError> {
        self.policy.validate().map_err(|e| SendError::Policy(e.to_string()))?;
        if paths.is_empty() {
            return Err(SendError::Policy("at least one path is required".into()));
        }
        if paths.len() > MAX_PATHS {
            return Err(SendError::Policy(format!("at most {MAX_PATHS} paths are supported")));
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(SendError::Policy(format!("payload exceeds the {MAX_PAYLOAD} byte protocol limit")));
        }
        let mut rep = SendReport::new(&self.policy.name);
        let mut det = Detector::new(self.policy.verification.max_rtt_zscore);
        let n = paths.len();
        let mut reached_decision = false;
        for attempt in 0..=self.policy.failure.max_retries {
            rep.attempts = attempt + 1;
            rep.released = false;
            let order: Vec<usize> = (0..n).map(|k| (attempt as usize + k) % n).collect();
            match self.attempt(payload, paths, &order, &mut det, &mut rep) {
                AttemptResult::Delivered => {
                    rep.delivered = true;
                    return Ok(rep);
                }
                AttemptResult::DeliveryUnconfirmed => return Err(SendError::DeliveryUnconfirmed(Box::new(rep))),
                AttemptResult::Withheld => reached_decision = true,
                AttemptResult::HandshakeFailed => {}
            }
        }
        if reached_decision {
            Err(SendError::Withheld(Box::new(rep)))
        } else {
            Err(SendError::Handshake(Box::new(rep)))
        }
    }

    fn kinds(&self) -> Vec<ProbeKind> {
        let m = &self.policy.mechanisms;
        let mut k = Vec::new();
        if m.interception_detection || m.canary || m.multipath {
            k.push(ProbeKind::Interception);
        }
        if m.active_decoys {
            k.push(ProbeKind::Bait);
        }
        if m.payload_like_decoys {
            k.push(ProbeKind::PayloadLike);
        }
        k
    }

    fn handshake(&self, path: &mut dyn Path) -> Result<Session, String> {
        let session_id = util::random::<16>();
        let eph = Ephemeral::generate();
        let eph_pub = eph.public;
        let me = self.identity.public().0;
        let timestamp = self.clock.unix_secs();
        let hi = hello_input(&session_id, timestamp, &eph_pub, &me, &self.recipient.0);
        let sig = self.identity.sign(&hi);
        let req = Message::Hello {
            session_id,
            timestamp,
            sender_eph: eph_pub,
            sender_id: me,
            recipient: self.recipient.0,
            sig,
        }
        .encode();
        let resp = path.exchange(&req).map_err(|e| format!("transport: {e}"))?;
        let first = resp.replies.first().ok_or_else(|| "no reply to hello".to_string())?;
        match Message::decode(first) {
            Ok(Message::HelloAck { session_id: sid, recv_eph, recv_id, sig }) => {
                if sid != session_id {
                    return Err("session id mismatch in hello ack".into());
                }
                if !util::ct_eq(&recv_id, &self.recipient.0) {
                    return Err(format!(
                        "receiver identity mismatch: got {}, expected {}",
                        PublicIdentity(recv_id).fingerprint(),
                        self.recipient.fingerprint()
                    ));
                }
                let ai = ack_input(&sha256(&[&hi]), &session_id, &recv_eph, &recv_id);
                if !self.recipient.verify(&ai, &sig) {
                    return Err("receiver signature invalid".into());
                }
                let mut shared = eph.agree(&recv_eph).map_err(|e| e.to_string())?;
                let keys = derive_session_keys(&shared, &transcript(&hi, &ai));
                shared.zeroize();
                Ok(Session { id: session_id, keys, probe_seq: 0 })
            }
            Ok(Message::Reject { code }) => Err(format!("receiver rejected hello: {code:?}")),
            _ => Err("unexpected reply to hello".into()),
        }
    }

    fn build_body(
        &self,
        kind: ProbeKind,
        session: &Session,
        probe_id: &ProbeId,
        issuer: &mut CanaryIssuer,
    ) -> (Vec<u8>, Vec<u8>) {
        match kind {
            ProbeKind::Interception => {
                let mut s = format!("pgprobe:{}", util::hex(&util::random::<8>()));
                if self.policy.mechanisms.canary {
                    s.push(' ');
                    s.push_str(&issuer.issue("probe"));
                }
                let b = s.into_bytes();
                (b.clone(), b)
            }
            ProbeKind::Bait => {
                let t = issuer.issue("bait");
                let b = format!("svc-backup credentials: user=backup token={t} url=https://pg-honeypot.invalid/{t}")
                    .into_bytes();
                (b.clone(), b)
            }
            ProbeKind::PayloadLike => {
                let mut plain = vec![0u8; self.policy.verification.payload_like_len as usize];
                SysRng.try_fill_bytes(&mut plain).expect("operating system CSPRNG unavailable");
                let body = crypto::seal(&session.keys.decoy, &decoy_nonce(probe_id), &session.id, &plain)
                    .expect("AEAD encryption of a bounded decoy cannot fail");
                (body, plain)
            }
        }
    }

    fn check_reply(
        raw: &[u8],
        session: &Session,
        probe_id: &ProbeId,
        seq: u64,
        content: &[u8],
        pid: &str,
    ) -> Option<Finding> {
        match Message::decode(raw) {
            Ok(Message::ProbeReply { session_id, probe_id: rp, seq: rs, mac: tag }) => {
                if session_id != session.id || rp != *probe_id || rs != seq {
                    return Some(Finding::new(
                        FindingKind::MalformedReply,
                        Severity::Critical,
                        pid,
                        "reply answers a different probe or session",
                    ));
                }
                let expect = reply_mac(&session.keys.probe, &session.id, probe_id, seq, content);
                if !util::ct_eq(&expect, &tag) {
                    return Some(Finding::new(
                        FindingKind::ReplyAuthFailure,
                        Severity::Critical,
                        pid,
                        "reply MAC invalid: responder lacks the session keys or the reply was altered",
                    ));
                }
                None
            }
            Ok(Message::Reject { code }) => Some(Finding::new(
                FindingKind::ProbeRejected,
                Severity::Critical,
                pid,
                format!("receiver rejected an authentic probe ({code:?}); it was altered in transit"),
            )),
            _ => Some(Finding::new(FindingKind::MalformedReply, Severity::Critical, pid, "unparseable reply")),
        }
    }

    fn probe_path(
        &self,
        path: &mut dyn Path,
        session: &mut Session,
        kinds: &[ProbeKind],
        issuer: &mut CanaryIssuer,
        det: &mut Detector,
    ) -> (PathReport, Vec<Finding>) {
        let pid = path.id().to_string();
        let intercept = self.policy.mechanisms.interception_detection;
        let (mut sent, mut ok) = (0u32, 0u32);
        let mut rtts: Vec<f64> = Vec::new();
        let mut fs: Vec<Finding> = Vec::new();
        for i in 0..self.policy.verification.probes_per_path {
            let kind = kinds[i as usize % kinds.len()];
            session.probe_seq += 1;
            let seq = session.probe_seq;
            let probe_id = util::random::<16>();
            let (body, content) = self.build_body(kind, session, &probe_id, issuer);
            let tag = crypto::mac(
                &session.keys.probe,
                &[b"probe", &session.id, &probe_id, &[kind as u8], &seq.to_be_bytes(), &body],
            );
            let req = Message::Probe { session_id: session.id, probe_id, kind, seq, body, mac: tag }.encode();
            sent += 1;
            match path.exchange(&req) {
                Err(e) => fs.push(Finding::new(FindingKind::NoReply, Severity::Medium, &pid, format!("no reply: {e}"))),
                Ok(resp) => {
                    if resp.replies.is_empty() {
                        fs.push(Finding::new(FindingKind::NoReply, Severity::Medium, &pid, "empty response"));
                        continue;
                    }
                    if resp.replies.len() > 1 && intercept {
                        fs.push(Finding::new(
                            FindingKind::DuplicateReply,
                            Severity::Medium,
                            &pid,
                            format!("{} replies to one probe", resp.replies.len()),
                        ));
                    }
                    match Self::check_reply(&resp.replies[0], session, &probe_id, seq, &content, &pid) {
                        None => {
                            ok += 1;
                            rtts.push(resp.rtt.as_secs_f64() * 1000.0);
                            if intercept {
                                if let Some(f) = det.observe_rtt(&pid, resp.rtt) {
                                    fs.push(f);
                                }
                            }
                        }
                        Some(f) => fs.push(f),
                    }
                }
            }
        }
        let critical = fs.iter().any(|f| f.severity == Severity::Critical);
        let mean = if rtts.is_empty() { 0.0 } else { rtts.iter().sum::<f64>() / rtts.len() as f64 };
        (
            PathReport {
                path: pid,
                probes_sent: sent,
                probes_ok: ok,
                verified: sent > 0 && ok >= sent.div_ceil(2) && !critical,
                excluded: false,
                mean_rtt_ms: mean,
            },
            fs,
        )
    }

    fn decide(
        &self,
        primary_id: &str,
        reports: &mut [PathReport],
        hops: &[Vec<String>],
        findings: &[Finding],
    ) -> Decision {
        let v = &self.policy.verification;
        let m = &self.policy.mechanisms;
        let tolerate = m.multipath && v.tolerate_failed_secondary_paths;
        for r in reports.iter_mut() {
            let noisy = findings.iter().any(|f| f.path == r.path && f.severity >= Severity::Medium);
            r.excluded = tolerate && r.path != primary_id && (!r.verified || noisy);
        }
        let excluded: HashSet<&str> = reports.iter().filter(|r| r.excluded).map(|r| r.path.as_str()).collect();
        let relevant: Vec<&Finding> = findings.iter().filter(|f| !excluded.contains(f.path.as_str())).collect();
        let mut reasons: Vec<String> = summarize(relevant.iter().copied().filter(|f| f.severity == Severity::Critical))
            .into_iter()
            .map(
                |(f, n)| if n > 1 { format!("critical finding (x{n}): {f}") } else { format!("critical finding: {f}") },
            )
            .collect();
        let sc = score(relevant.iter().copied());
        let any_critical = !reasons.is_empty();
        if !any_critical && sc > 0.0 && sc >= v.max_suspicion_score {
            reasons.push(format!("suspicion score {sc:.2} reached the limit {:.2}", v.max_suspicion_score));
        }
        let mut diversity = None;
        if !reports.is_empty() {
            if let Some(p) = reports.iter().find(|r| r.path == primary_id) {
                if !p.verified {
                    reasons.push(format!("primary path '{primary_id}' failed verification"));
                }
            }
            if m.multipath {
                let verified: Vec<usize> =
                    (0..reports.len()).filter(|&i| reports[i].verified && !reports[i].excluded).collect();
                if (verified.len() as u32) < v.min_verified_paths {
                    reasons.push(format!(
                        "{} verified path(s), policy requires {}",
                        verified.len(),
                        v.min_verified_paths
                    ));
                }
                if verified.len() >= 2 {
                    let hs: Vec<&[String]> = verified.iter().map(|&i| hops[i].as_slice()).collect();
                    diversity = min_pairwise_diversity(&hs);
                    if let Some(d) = diversity {
                        if v.min_verified_paths >= 2 && d < v.min_path_diversity {
                            reasons.push(format!(
                                "path diversity {d:.2} is below the required {:.2}",
                                v.min_path_diversity
                            ));
                        }
                    }
                }
            }
        }
        Decision { allow: reasons.is_empty(), reasons, score: sc, diversity }
    }

    fn close(&self, path: &mut dyn Path, session: &Session) {
        let tag = close_mac(&session.keys.probe, &session.id);
        let _ = path.exchange(&Message::Close { session_id: session.id, mac: tag }.encode());
    }

    fn poll_honeypot(&self, issuer: &CanaryIssuer) -> Vec<Finding> {
        let m = &self.policy.mechanisms;
        if !(m.canary || m.active_decoys) {
            return Vec::new();
        }
        self.honeypot
            .drain()
            .into_iter()
            .filter_map(|hit| {
                issuer.label_of(&hit.token).map(|label| {
                    Finding::new(
                        FindingKind::CanaryTriggered,
                        Severity::Critical,
                        "session",
                        format!("{label} token touched by {}", hit.source),
                    )
                })
            })
            .collect()
    }

    fn attempt(
        &self,
        payload: &[u8],
        paths: &mut [Box<dyn Path>],
        order: &[usize],
        det: &mut Detector,
        rep: &mut SendReport,
    ) -> AttemptResult {
        let n = rep.attempts;
        let primary = order[0];
        let primary_id = paths[primary].id().to_string();
        rep.log(format!("attempt {n}: handshake via '{primary_id}'"));
        let mut session = match self.handshake(&mut *paths[primary]) {
            Ok(s) => s,
            Err(e) => {
                rep.log(format!("attempt {n}: handshake failed on '{primary_id}': {e}"));
                rep.findings.push(Finding::new(FindingKind::HandshakeFailure, Severity::Critical, &primary_id, e));
                return AttemptResult::HandshakeFailed;
            }
        };
        rep.session_id = session.id;
        rep.log(format!("attempt {n}: receiver authenticated, fresh session keys derived"));

        let kinds = self.kinds();
        let mut issuer = CanaryIssuer::new(session.keys.canary);
        let mut reports: Vec<PathReport> = Vec::new();
        let mut hops: Vec<Vec<String>> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();
        if !kinds.is_empty() {
            let targets: Vec<usize> = if self.policy.mechanisms.multipath { order.to_vec() } else { vec![primary] };
            for pi in targets {
                let (pr, fs) = self.probe_path(&mut *paths[pi], &mut session, &kinds, &mut issuer, det);
                rep.log(format!(
                    "attempt {n}: probed '{}': {}/{} valid, {} finding(s)",
                    pr.path,
                    pr.probes_ok,
                    pr.probes_sent,
                    fs.len()
                ));
                hops.push(paths[pi].hops().to_vec());
                reports.push(pr);
                findings.extend(fs);
            }
        } else {
            rep.log(format!("attempt {n}: no verification mechanisms enabled"));
        }
        findings.extend(self.poll_honeypot(&issuer));

        let decision = self.decide(&primary_id, &mut reports, &hops, &findings);
        rep.score = decision.score;
        rep.diversity = decision.diversity;
        rep.paths = reports;
        rep.findings.extend(findings);
        if !decision.allow {
            rep.reasons = decision.reasons.clone();
            for r in &decision.reasons {
                rep.log(format!("attempt {n}: WITHHELD: {r}"));
            }
            if self.policy.failure.close_session_on_failure {
                self.close(&mut *paths[primary], &session);
                rep.log(format!("attempt {n}: session closed, keys discarded"));
            }
            return AttemptResult::Withheld;
        }
        rep.reasons.clear();
        rep.released = true;
        rep.log(format!("attempt {n}: policy satisfied, releasing payload via '{primary_id}'"));

        let seq = 1u64;
        let aad = payload_aad(&session.id, &self.recipient.0, seq);
        let ct = match crypto::seal(&session.keys.payload, &crypto::seq_nonce(seq), &aad, payload) {
            Ok(c) => c,
            Err(e) => {
                rep.log(format!("attempt {n}: encryption failed: {e}"));
                rep.released = false;
                return AttemptResult::Withheld;
            }
        };
        let req = Message::Payload { session_id: session.id, seq, ciphertext: ct.clone() }.encode();
        let acked = match paths[primary].exchange(&req) {
            Ok(resp) => resp
                .replies
                .first()
                .map(|raw| match Message::decode(raw) {
                    Ok(Message::PayloadAck { session_id, seq: s, mac: tag }) => {
                        session_id == session.id
                            && s == seq
                            && util::ct_eq(&ack_mac(&session.keys.probe, &session.id, seq, &ct), &tag)
                    }
                    _ => false,
                })
                .unwrap_or(false),
            Err(_) => false,
        };
        let late = self.poll_honeypot(&issuer);
        for f in late {
            rep.log(format!("attempt {n}: canary triggered after release (session may be exposed): {f}"));
            rep.findings.push(f);
        }
        if acked {
            rep.log(format!("attempt {n}: payload acknowledged by authenticated receiver"));
            self.close(&mut *paths[primary], &session);
            AttemptResult::Delivered
        } else {
            rep.log(format!("attempt {n}: no valid acknowledgement; delivery unconfirmed"));
            AttemptResult::DeliveryUnconfirmed
        }
    }
}
