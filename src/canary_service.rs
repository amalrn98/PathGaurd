//! A separately deployable canary listener and its client.
//!
//! In production the bait must live **outside** the sender: a URL on a host the
//! attacker can reach and the sender does not control the path to. This module
//! provides that host ([`CanaryService`]) and the sender-side client
//! ([`RemoteCanary`]).
//!
//! ## Protocol (HTTP/1.1, `Connection: close`)
//!
//! * `POST /register`: the sender announces the tokens of an upcoming session.
//!   The body is authenticated with HMAC-SHA256 under the shared reporting key.
//!   The service **ignores hits on tokens nobody registered**, so random traffic
//!   cannot fill its storage or fake events.
//! * `GET /c/<token>`: the bait. Anyone may call it. A hit on a registered token
//!   is recorded. The response is always the same `200 ok`, so a visitor learns
//!   nothing about whether the token was registered.
//! * `GET /events?nonce=<hex>&tokens=<t1,t2,...>`: the sender asks about its tokens.
//!   The answer carries the nonce, the service time, the events and an HMAC over
//!   all of it **including the question**. "No events" is therefore an
//!   authenticated statement, and an old or forged answer is rejected.
//!
//! The reporting key is a symmetric secret shared by the service and the senders
//! it serves. Events contain no payload data, but run the service behind TLS in
//! production so the token list is not exposed on the wire.
//!
//! ## Privacy and retention
//!
//! Events hold the token, a timestamp and a source label. The source is the literal
//! `external` unless the operator enables `log_source`, which stores the peer
//! address. Events expire after `event_ttl_secs` (default 24 hours) and the store
//! is bounded.

use crate::canary::{is_valid_token, CanaryError, CanarySource, HoneypotHit};
use crate::clock::Clock;
use crate::crypto::{mac, mac_verify};
use crate::util;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 256 * 1024;
const MAX_TOKENS_PER_REQUEST: usize = 4096;
const MAX_RESPONSE: usize = 1 << 20;

/// Service settings.
#[derive(Clone)]
pub struct ServiceConfig {
    /// Shared reporting key.
    pub key: [u8; 32],
    /// Store the peer address as the event source. Off by default for privacy.
    pub log_source: bool,
    /// How long registrations and events are kept.
    pub event_ttl_secs: u64,
    /// Registered tokens held at once.
    pub max_tokens: usize,
    /// Events held at once. Oldest are dropped first.
    pub max_events: usize,
    /// Accepted difference between a request time and the service clock.
    pub max_clock_skew_secs: u64,
}

impl ServiceConfig {
    /// Defaults with the given key.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            log_source: false,
            event_ttl_secs: 86_400,
            max_tokens: 100_000,
            max_events: 10_000,
            max_clock_skew_secs: 120,
        }
    }
}

/// Counters for operators.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceStats {
    /// Registrations accepted.
    pub registrations: u64,
    /// Hits recorded on registered tokens.
    pub hits_recorded: u64,
    /// Hits on tokens nobody registered (ignored).
    pub hits_ignored: u64,
    /// Requests refused because authentication failed.
    pub auth_failures: u64,
    /// Requests refused as malformed or oversized.
    pub bad_requests: u64,
}

struct StoredEvent {
    token: String,
    observed_at: u64,
    source: String,
}

#[derive(Default)]
struct Inner {
    registered: HashMap<String, u64>,
    events: VecDeque<StoredEvent>,
    stats: ServiceStats,
    last_prune: u64,
}

/// The canary listener, independent of any socket so it can be tested directly.
pub struct CanaryService {
    cfg: ServiceConfig,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
}

struct Request<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a str,
    body: &'a [u8],
}

fn response(status: u16, reason: &str, body: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        .into_bytes()
}

/// Split a raw request into its parts. `Err` carries the status to answer with.
fn parse(raw: &[u8]) -> Result<Request<'_>, (u16, &'static str)> {
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or((400, "Bad Request"))?;
    if head_end > MAX_HEAD {
        return Err((431, "Request Header Fields Too Large"));
    }
    let head = std::str::from_utf8(&raw[..head_end]).map_err(|_| (400, "Bad Request"))?;
    let mut lines = head.split("\r\n");
    let line = lines.next().ok_or((400, "Bad Request"))?;
    let mut it = line.split(' ');
    let (method, target, version) = (it.next(), it.next(), it.next());
    let (Some(method), Some(target), Some(version)) = (method, target, version) else {
        return Err((400, "Bad Request"));
    };
    if it.next().is_some() || !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return Err((400, "Bad Request"));
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut content_len = 0usize;
    for h in lines {
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().map_err(|_| (400, "Bad Request"))?;
            }
        }
    }
    if content_len > MAX_BODY {
        return Err((413, "Payload Too Large"));
    }
    let body = &raw[head_end + 4..];
    if body.len() < content_len {
        return Err((400, "Bad Request"));
    }
    Ok(Request { method, path, query, body: &body[..content_len] })
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| v))
}

fn sanitize_source(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_graphic() { c } else { '_' }).take(64).collect()
}

impl CanaryService {
    /// New service.
    pub fn new(cfg: ServiceConfig, clock: Arc<dyn Clock>) -> Self {
        Self { cfg, clock, inner: Mutex::new(Inner::default()) }
    }
    /// Counters.
    pub fn stats(&self) -> ServiceStats {
        self.inner.lock().map(|i| i.stats.clone()).unwrap_or_default()
    }
    /// Registered tokens and stored events currently held.
    pub fn sizes(&self) -> (usize, usize) {
        self.inner.lock().map(|i| (i.registered.len(), i.events.len())).unwrap_or((0, 0))
    }

    fn prune(&self, inner: &mut Inner, now: u64) {
        if now == inner.last_prune {
            return;
        }
        inner.last_prune = now;
        let ttl = self.cfg.event_ttl_secs;
        inner.registered.retain(|_, exp| *exp > now);
        inner.events.retain(|e| e.observed_at.saturating_add(ttl) > now);
    }

    /// Answer one complete HTTP request. Returns the full response bytes.
    pub fn handle_request(&self, raw: &[u8], peer: Option<&str>) -> Vec<u8> {
        let now = self.clock.unix_secs();
        let Ok(mut inner) = self.inner.lock() else {
            return response(500, "Internal Server Error", "");
        };
        self.prune(&mut inner, now);
        let req = match parse(raw) {
            Ok(r) => r,
            Err((code, reason)) => {
                inner.stats.bad_requests += 1;
                return response(code, reason, "");
            }
        };
        match (req.method, req.path) {
            ("GET", p) if p.starts_with("/c/") => self.hit(&mut inner, &p[3..], peer, now),
            ("POST", "/register") => self.register(&mut inner, &req, now),
            ("GET", "/events") => self.events(&mut inner, &req, now),
            ("GET", "/healthz") => response(200, "OK", "ok"),
            ("GET" | "POST", _) => response(404, "Not Found", ""),
            _ => response(405, "Method Not Allowed", ""),
        }
    }

    fn hit(&self, inner: &mut Inner, token: &str, peer: Option<&str>, now: u64) -> Vec<u8> {
        // Same answer for every visitor, registered or not.
        let ok = response(200, "OK", "ok");
        if !is_valid_token(token) {
            inner.stats.hits_ignored += 1;
            return ok;
        }
        if inner.registered.get(token).is_some_and(|exp| *exp > now) {
            let source =
                if self.cfg.log_source { sanitize_source(peer.unwrap_or("unknown")) } else { "external".to_string() };
            inner.events.push_back(StoredEvent { token: token.to_string(), observed_at: now, source });
            while inner.events.len() > self.cfg.max_events {
                inner.events.pop_front();
            }
            inner.stats.hits_recorded += 1;
        } else {
            inner.stats.hits_ignored += 1;
        }
        ok
    }

    fn register(&self, inner: &mut Inner, req: &Request<'_>, now: u64) -> Vec<u8> {
        let Ok(body) = std::str::from_utf8(req.body) else {
            inner.stats.bad_requests += 1;
            return response(400, "Bad Request", "");
        };
        let (mut nonce, mut at, mut tag, mut tokens) = (None, None, None, Vec::new());
        for line in body.lines() {
            match line.split_once(' ') {
                Some(("nonce", v)) => nonce = Some(v),
                Some(("now", v)) => at = v.parse::<u64>().ok(),
                Some(("token", v)) => tokens.push(v),
                Some(("tag", v)) => tag = util::from_hex::<32>(v),
                _ => {
                    inner.stats.bad_requests += 1;
                    return response(400, "Bad Request", "");
                }
            }
        }
        let (Some(nonce), Some(at), Some(tag)) = (nonce, at, tag) else {
            inner.stats.bad_requests += 1;
            return response(400, "Bad Request", "");
        };
        if tokens.is_empty() || tokens.len() > MAX_TOKENS_PER_REQUEST || !tokens.iter().all(|t| is_valid_token(t)) {
            inner.stats.bad_requests += 1;
            return response(400, "Bad Request", "");
        }
        let joined = tokens.join("\n");
        if !mac_verify(
            &self.cfg.key,
            &[b"canary-register", nonce.as_bytes(), &at.to_be_bytes(), joined.as_bytes()],
            &tag,
        ) {
            inner.stats.auth_failures += 1;
            return response(401, "Unauthorized", "");
        }
        if at.abs_diff(now) > self.cfg.max_clock_skew_secs {
            inner.stats.auth_failures += 1;
            return response(401, "Unauthorized", "");
        }
        let new = tokens.iter().filter(|t| !inner.registered.contains_key(**t)).count();
        if inner.registered.len() + new > self.cfg.max_tokens {
            return response(503, "Service Unavailable", "");
        }
        let expires = now.saturating_add(self.cfg.event_ttl_secs);
        for t in tokens {
            inner.registered.insert(t.to_string(), expires);
        }
        inner.stats.registrations += 1;
        response(200, "OK", "ok")
    }

    fn events(&self, inner: &mut Inner, req: &Request<'_>, now: u64) -> Vec<u8> {
        let nonce = query_param(req.query, "nonce").unwrap_or("");
        let tokens: Vec<&str> =
            query_param(req.query, "tokens").unwrap_or("").split(',').filter(|t| !t.is_empty()).collect();
        if nonce.len() != 32
            || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
            || tokens.is_empty()
            || tokens.len() > MAX_TOKENS_PER_REQUEST
            || !tokens.iter().all(|t| is_valid_token(t))
        {
            inner.stats.bad_requests += 1;
            return response(400, "Bad Request", "");
        }
        let wanted: HashSet<&str> = tokens.iter().copied().collect();
        let lines: Vec<String> = inner
            .events
            .iter()
            .filter(|e| wanted.contains(e.token.as_str()))
            .map(|e| format!("event {} {} {}", e.token, e.observed_at, e.source))
            .collect();
        let tag = poll_tag(&self.cfg.key, nonce, now, &tokens.join(","), &lines.join("\n"));
        let mut body = format!("nonce {nonce}\nnow {now}\n");
        for l in &lines {
            body.push_str(l);
            body.push('\n');
        }
        body.push_str(&format!("tag {}\n", util::hex(&tag)));
        response(200, "OK", &body)
    }

    /// Serve on `listener` until `stop` is set. Each connection is handled on its own
    /// thread, at most 64 at once, with short read timeouts.
    pub fn serve(self: Arc<Self>, listener: TcpListener, stop: Arc<AtomicBool>) -> std::io::Result<()> {
        listener.set_nonblocking(true)?;
        let active = Arc::new(AtomicUsize::new(0));
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    if active.load(Ordering::SeqCst) >= 64 {
                        let _ = (&stream).write_all(&response(503, "Service Unavailable", ""));
                        continue;
                    }
                    active.fetch_add(1, Ordering::SeqCst);
                    let (svc, active) = (self.clone(), active.clone());
                    std::thread::spawn(move || {
                        let _ = svc.serve_one(stream, &peer.ip().to_string());
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn serve_one(&self, mut stream: TcpStream, peer: &str) -> std::io::Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let need = content_length(&buf[..end]) + end + 4;
                if buf.len() >= need || need > MAX_HEAD + MAX_BODY + 4 {
                    break;
                }
            } else if buf.len() > MAX_HEAD {
                break;
            }
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        stream.write_all(&self.handle_request(&buf, Some(peer)))
    }
}

fn content_length(head: &[u8]) -> usize {
    std::str::from_utf8(head)
        .ok()
        .and_then(|h| {
            h.split("\r\n").find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse().ok()).flatten()
            })
        })
        .unwrap_or(0)
}

fn poll_tag(key: &[u8; 32], nonce: &str, now: u64, tokens: &str, events: &str) -> [u8; 32] {
    mac(key, &[b"canary-poll", nonce.as_bytes(), &now.to_be_bytes(), tokens.as_bytes(), events.as_bytes()])
}

/// Sender-side client for a [`CanaryService`].
pub struct RemoteCanary {
    addr: String,
    key: [u8; 32],
    clock: Arc<dyn Clock>,
    timeout: Duration,
    max_skew: u64,
}

impl RemoteCanary {
    /// Client for the service at `addr` (`host:port`), sharing `key`.
    pub fn new(addr: impl Into<String>, key: [u8; 32], clock: Arc<dyn Clock>) -> Self {
        Self { addr: addr.into(), key, clock, timeout: Duration::from_secs(3), max_skew: 120 }
    }
    /// Change the connect, read and write timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn roundtrip(&self, request: &[u8]) -> Result<(u16, Vec<u8>), CanaryError> {
        let unavailable = |e: std::io::Error| CanaryError::Unavailable(format!("{}: {e}", self.addr));
        let addr = self
            .addr
            .to_socket_addrs()
            .map_err(unavailable)?
            .next()
            .ok_or_else(|| CanaryError::Unavailable(format!("{}: no address", self.addr)))?;
        let mut s = TcpStream::connect_timeout(&addr, self.timeout).map_err(unavailable)?;
        s.set_read_timeout(Some(self.timeout)).map_err(unavailable)?;
        s.set_write_timeout(Some(self.timeout)).map_err(unavailable)?;
        s.write_all(request).map_err(unavailable)?;
        let mut buf = Vec::new();
        let mut limited = (&s).take(MAX_RESPONSE as u64 + 1);
        limited.read_to_end(&mut buf).map_err(unavailable)?;
        if buf.len() > MAX_RESPONSE {
            return Err(CanaryError::Untrusted("response too large".into()));
        }
        let head_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| CanaryError::Untrusted("malformed response".into()))?;
        let status_line = std::str::from_utf8(&buf[..head_end])
            .ok()
            .and_then(|h| h.lines().next())
            .ok_or_else(|| CanaryError::Untrusted("malformed response".into()))?;
        let status: u16 = status_line
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| CanaryError::Untrusted("malformed status line".into()))?;
        Ok((status, buf[head_end + 4..].to_vec()))
    }

    /// Verify and parse a `/events` answer. Exposed for tests of forged answers.
    pub fn verify_events(&self, body: &[u8], nonce: &str, tokens: &[String]) -> Result<Vec<HoneypotHit>, CanaryError> {
        let untrusted = |m: &str| CanaryError::Untrusted(m.to_string());
        let text = std::str::from_utf8(body).map_err(|_| untrusted("body is not text"))?;
        let (mut got_nonce, mut now, mut tag, mut events) = (None, None, None, Vec::new());
        for line in text.lines() {
            match line.split_once(' ') {
                Some(("nonce", v)) => got_nonce = Some(v),
                Some(("now", v)) => now = v.parse::<u64>().ok(),
                Some(("tag", v)) => tag = util::from_hex::<32>(v),
                Some(("event", _)) => events.push(line),
                _ => return Err(untrusted("unexpected line")),
            }
        }
        let (Some(got_nonce), Some(now), Some(tag)) = (got_nonce, now, tag) else {
            return Err(untrusted("missing fields"));
        };
        if got_nonce != nonce {
            return Err(untrusted("answer is for a different request (replay)"));
        }
        let expected = poll_tag(&self.key, nonce, now, &tokens.join(","), &events.join("\n"));
        if !util::ct_eq(&expected, &tag) {
            return Err(untrusted("authentication tag is invalid"));
        }
        if now.abs_diff(self.clock.unix_secs()) > self.max_skew {
            return Err(untrusted("answer timestamp is outside the allowed skew"));
        }
        let wanted: HashSet<&str> = tokens.iter().map(String::as_str).collect();
        let mut hits = Vec::new();
        for e in events {
            let parts: Vec<&str> = e.splitn(4, ' ').collect();
            if parts.len() != 4 || !wanted.contains(parts[1]) {
                return Err(untrusted("event for a token that was not requested"));
            }
            hits.push(HoneypotHit { token: parts[1].to_string(), source: parts[3].to_string() });
        }
        Ok(hits)
    }
}

impl CanarySource for RemoteCanary {
    fn register(&self, tokens: &[String]) -> Result<(), CanaryError> {
        if tokens.is_empty() {
            return Ok(());
        }
        let mut done = 0;
        for chunk in tokens.chunks(MAX_TOKENS_PER_REQUEST) {
            let nonce = util::hex(&util::random::<16>());
            let now = self.clock.unix_secs();
            let tag = mac(
                &self.key,
                &[b"canary-register", nonce.as_bytes(), &now.to_be_bytes(), chunk.join("\n").as_bytes()],
            );
            let mut body = format!("nonce {nonce}\nnow {now}\n");
            for t in chunk {
                body.push_str(&format!("token {t}\n"));
            }
            body.push_str(&format!("tag {}\n", util::hex(&tag)));
            let req = format!(
                "POST /register HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                self.addr,
                body.len()
            );
            match self.roundtrip(req.as_bytes())? {
                (200, _) => done += chunk.len(),
                (401, _) => {
                    return Err(CanaryError::Untrusted("service rejected our registration (key mismatch?)".into()))
                }
                (s, _) => return Err(CanaryError::Unavailable(format!("register answered status {s}"))),
            }
        }
        debug_assert_eq!(done, tokens.len());
        Ok(())
    }

    fn poll(&self, tokens: &HashSet<String>) -> Result<Vec<HoneypotHit>, CanaryError> {
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        let mut sorted: Vec<String> = tokens.iter().cloned().collect();
        sorted.sort();
        let mut all = Vec::new();
        for chunk in sorted.chunks(MAX_TOKENS_PER_REQUEST) {
            let nonce = util::hex(&util::random::<16>());
            let req = format!(
                "GET /events?nonce={nonce}&tokens={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                chunk.join(","),
                self.addr
            );
            match self.roundtrip(req.as_bytes())? {
                (200, body) => all.extend(self.verify_events(&body, &nonce, chunk)?),
                (s, _) => return Err(CanaryError::Unavailable(format!("events answered status {s}"))),
            }
        }
        Ok(all)
    }
}
