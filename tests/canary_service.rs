//! The external canary service: real sockets for the end-to-end paths, direct
//! request handling for protocol edge cases.

use pathguard::canary::{CanaryError, CanarySource, Honeypot};
use pathguard::canary_service::{CanaryService, RemoteCanary, ServiceConfig};
use pathguard::clock::{Clock, ManualClock};
use pathguard::crypto::mac;
use pathguard::detect::{FindingKind, Severity};
use pathguard::sim::{Behavior, World};
use pathguard::{util, CanaryStatus, Policy, SendError};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const KEY: [u8; 32] = [42; 32];

struct Running {
    addr: String,
    svc: Arc<CanaryService>,
    stop: Arc<AtomicBool>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn start(cfg: ServiceConfig, clock: ManualClock) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let svc = Arc::new(CanaryService::new(cfg, Arc::new(clock)));
    let stop = Arc::new(AtomicBool::new(false));
    let (s, st) = (svc.clone(), stop.clone());
    std::thread::spawn(move || {
        let _ = s.serve(listener, st);
    });
    Running { addr, svc, stop }
}

fn http(addr: &str, raw: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    parse_response(&buf)
}

fn parse_response(buf: &[u8]) -> (u16, String) {
    let text = String::from_utf8_lossy(buf).into_owned();
    let status = text.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, body)
}

fn get(addr: &str, path: &str) -> (u16, String) {
    http(addr, &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
}

fn raw(method: &str, target: &str, body: &str) -> Vec<u8> {
    format!("{method} {target} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}

fn token(n: u8) -> String {
    format!("pg-canary-{}", util::hex(&[n; 12]))
}

fn register_body(key: &[u8; 32], tokens: &[String], now: u64) -> String {
    let nonce = util::hex(&util::random::<16>());
    let tag = mac(key, &[b"canary-register", nonce.as_bytes(), &now.to_be_bytes(), tokens.join("\n").as_bytes()]);
    let mut b = format!("nonce {nonce}\nnow {now}\n");
    for t in tokens {
        b.push_str(&format!("token {t}\n"));
    }
    b.push_str(&format!("tag {}\n", util::hex(&tag)));
    b
}

fn pure_service(clock: &ManualClock) -> CanaryService {
    CanaryService::new(ServiceConfig::new(KEY), Arc::new(clock.clone()))
}

fn status(resp: &[u8]) -> u16 {
    parse_response(resp).0
}

fn world_with(r: &Running, clock_world: &World) -> RemoteCanary {
    RemoteCanary::new(r.addr.clone(), KEY, Arc::new(clock_world.clock().clone()))
}

// ---- end to end ----------------------------------------------------------

#[test]
fn an_external_touch_withholds_the_payload_and_is_attributed_to_its_session() {
    let world = World::new();
    let svc = start(ServiceConfig::new(KEY), world.clock().clone());
    let addr = svc.addr.clone();
    // The "attacker" acts over a real socket against the real service.
    world.set_toucher(Arc::new(move |tok, _| {
        let _ = get(&addr, &format!("/c/{tok}"));
    }));
    let sender = world
        .sender(Policy::balanced())
        .with_canary_source(Arc::new(world_with(&svc, &world)))
        .with_bait_base_url(format!("http://{}", svc.addr));
    let mut paths = vec![world.path("snoop", &["x"], 1, Behavior::Snoop), world.honest_path("clean", &["y"], 2)];
    let report = sender.send(b"data", &mut paths).expect("delivered on the second attempt");

    let hits: Vec<_> = report.findings.iter().filter(|f| f.kind == FindingKind::CanaryTriggered).collect();
    assert!(!hits.is_empty(), "the external touch must be reported");
    assert!(hits.iter().all(|f| f.severity == Severity::Critical));
    assert_eq!(report.attempts, 2, "first attempt withheld because of the touch");
    assert_eq!(report.canary_status, CanaryStatus::Checked);
    let st = svc.svc.stats();
    assert!(st.registrations >= 1 && st.hits_recorded >= 1);
    assert_eq!(st.auth_failures, 0);
    assert_eq!(world.honeypot().unclaimed(), 0, "the in-process honeypot was not involved");
}

#[test]
fn no_touch_means_an_authenticated_no_events_answer() {
    let world = World::new();
    let svc = start(ServiceConfig::new(KEY), world.clock().clone());
    let sender = world.sender(Policy::balanced()).with_canary_source(Arc::new(world_with(&svc, &world)));
    let mut paths = vec![world.honest_path("a", &["x"], 1)];
    let report = sender.send(b"data", &mut paths).unwrap();
    assert!(report.delivered);
    assert_eq!(report.canary_status, CanaryStatus::Checked);
    assert!(report.findings.iter().all(|f| f.kind != FindingKind::CanaryTriggered));
}

#[test]
fn late_external_events_are_collected_per_session() {
    let world = World::new();
    let svc = start(ServiceConfig::new(KEY), world.clock().clone());
    let sender = world.sender(Policy::balanced()).with_canary_source(Arc::new(world_with(&svc, &world)));
    let mut paths = vec![world.honest_path("a", &["x"], 1)];
    let report = sender.send(b"data", &mut paths).unwrap();
    let tok = world.observed_canary_tokens().remove(0);
    assert_eq!(get(&svc.addr, &format!("/c/{tok}")).0, 200);
    let events = sender.collect_late_events().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].session_id, report.session_id);
    assert_eq!(events[0].source, "external");
}

#[test]
fn unreachable_service_is_not_reported_as_a_clean_path() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    for (policy, expect_delivered) in [(Policy::balanced(), true), (Policy::paranoid(), false)] {
        let world = World::new();
        let remote = RemoteCanary::new(dead.clone(), KEY, Arc::new(world.clock().clone()))
            .with_timeout(Duration::from_millis(300));
        let sender = world.sender(policy.clone()).with_canary_source(Arc::new(remote));
        let mut paths = vec![world.honest_path("a", &["x"], 1), world.honest_path("b", &["y"], 2)];
        let res = sender.send(b"data", &mut paths);
        let report = match (&res, expect_delivered) {
            (Ok(r), true) => r,
            (Err(SendError::Withheld(r)), false) => r.as_ref(),
            other => panic!("{}: unexpected {other:?}", policy.name),
        };
        assert_eq!(report.canary_status, CanaryStatus::Unchecked, "{}", policy.name);
        let f = report
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::CanarySourceFailure)
            .expect("outage must be visible");
        let want = if policy.verification.canary_required { Severity::Critical } else { Severity::Medium };
        assert_eq!(f.severity, want, "{}", policy.name);
    }
}

#[test]
fn a_replayed_valid_answer_is_rejected() {
    // Serve an old, genuinely signed "no events" answer to a new question.
    let clock = ManualClock::new(1_700_000_000);
    let real = pure_service(&clock);
    let toks = vec![token(1)];
    assert_eq!(
        status(&real.handle_request(&raw("POST", "/register", &register_body(&KEY, &toks, clock.unix_secs())), None)),
        200
    );
    let old_nonce = "00".repeat(16);
    let old = real.handle_request(&raw("GET", &format!("/events?nonce={old_nonce}&tokens={}", toks[0]), ""), None);
    let canned = parse_response(&old).1;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let canned2 = canned.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten().take(10) {
            let mut s = stream;
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = if req.starts_with("POST") { "ok".to_string() } else { canned2.clone() };
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
        }
    });
    let world = World::new();
    let remote = RemoteCanary::new(addr, KEY, Arc::new(world.clock().clone()));
    let tokens: HashSet<String> = toks.iter().cloned().collect();
    match remote.poll(&tokens) {
        Err(CanaryError::Untrusted(m)) => assert!(m.contains("different request") || m.contains("skew"), "{m}"),
        other => panic!("replay accepted: {other:?}"),
    }
    // And through the sender: an untrusted answer is critical under every policy.
    let sender = world.sender(Policy::balanced()).with_canary_source(Arc::new(remote));
    let mut paths = vec![world.honest_path("a", &["x"], 1)];
    match sender.send(b"data", &mut paths) {
        Err(SendError::Withheld(r)) => {
            assert!(r
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::CanarySourceFailure && f.severity == Severity::Critical));
        }
        other => panic!("expected withheld, got {other:?}"),
    }
}

// ---- answer authentication ------------------------------------------------

fn valid_answer(nonce: &str, toks: &[String], hit: Option<&str>) -> (RemoteCanary, String) {
    let clock = ManualClock::new(1_700_000_000);
    let svc = pure_service(&clock);
    svc.handle_request(&raw("POST", "/register", &register_body(&KEY, toks, clock.unix_secs())), None);
    if let Some(h) = hit {
        svc.handle_request(&raw("GET", &format!("/c/{h}"), ""), None);
    }
    let resp = svc.handle_request(&raw("GET", &format!("/events?nonce={nonce}&tokens={}", toks.join(",")), ""), None);
    (RemoteCanary::new("unused:1", KEY, Arc::new(clock)), parse_response(&resp).1)
}

#[test]
fn answer_verification_accepts_the_real_thing_and_rejects_every_alteration() {
    let nonce = util::hex(&[7u8; 16]);
    let toks = vec![token(1), token(2)];
    let (client, body) = valid_answer(&nonce, &toks, Some(&toks[0]));
    let hits = client.verify_events(body.as_bytes(), &nonce, &toks).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].token, toks[0]);

    let forged_event = body.replace("tag ", &format!("event {} 1700000000 external\ntag ", toks[1]));
    let dropped_event = body.lines().filter(|l| !l.starts_with("event")).collect::<Vec<_>>().join("\n") + "\n";
    let flipped_tag = {
        let i = body.rfind("tag ").unwrap() + 4;
        let mut b = body.clone().into_bytes();
        b[i] = if b[i] == b'0' { b'1' } else { b'0' };
        String::from_utf8(b).unwrap()
    };
    let other_source = body.replace("external", "friendly");
    for (name, bad) in [
        ("forged event", forged_event),
        ("silently dropped event", dropped_event),
        ("flipped tag", flipped_tag),
        ("edited source", other_source),
        ("garbage", "hello".to_string()),
        ("empty", String::new()),
    ] {
        assert!(
            matches!(client.verify_events(bad.as_bytes(), &nonce, &toks), Err(CanaryError::Untrusted(_))),
            "{name} was accepted"
        );
    }
    // Wrong nonce, wrong token list, wrong key.
    assert!(client.verify_events(body.as_bytes(), &util::hex(&[8u8; 16]), &toks).is_err());
    assert!(client.verify_events(body.as_bytes(), &nonce, &toks[..1]).is_err(), "answer is bound to the question");
    let wrong_key = RemoteCanary::new("unused:1", [1; 32], Arc::new(ManualClock::new(1_700_000_000)));
    assert!(wrong_key.verify_events(body.as_bytes(), &nonce, &toks).is_err());
    // Stale answer (client clock far ahead of the signed service time).
    let late = RemoteCanary::new("unused:1", KEY, Arc::new(ManualClock::new(1_700_100_000)));
    assert!(late.verify_events(body.as_bytes(), &nonce, &toks).is_err());
}

// ---- service behaviour -----------------------------------------------------

#[test]
fn bait_answers_are_identical_for_registered_and_unregistered_tokens() {
    let clock = ManualClock::new(1_700_000_000);
    let svc = pure_service(&clock);
    svc.handle_request(&raw("POST", "/register", &register_body(&KEY, &[token(1)], clock.unix_secs())), None);
    let known = svc.handle_request(&raw("GET", &format!("/c/{}", token(1)), ""), None);
    let unknown = svc.handle_request(&raw("GET", &format!("/c/{}", token(2)), ""), None);
    let junk = svc.handle_request(&raw("GET", "/c/not-a-token", ""), None);
    assert_eq!(known, unknown, "a visitor must not learn which tokens are registered");
    assert_eq!(known, junk);
    let st = svc.stats();
    assert_eq!((st.hits_recorded, st.hits_ignored), (1, 2));
    assert_eq!(svc.sizes(), (1, 1), "ignored hits store nothing");
}

#[test]
fn registration_requires_the_key_a_fresh_time_and_valid_tokens() {
    let clock = ManualClock::new(1_700_000_000);
    let svc = pure_service(&clock);
    let now = clock.unix_secs();
    let ok = |b: String| status(&svc.handle_request(&raw("POST", "/register", &b), None));
    assert_eq!(ok(register_body(&KEY, &[token(1)], now)), 200);
    assert_eq!(ok(register_body(&[9; 32], &[token(1)], now)), 401, "wrong key");
    assert_eq!(ok(register_body(&KEY, &[token(1)], now - 500)), 401, "stale");
    assert_eq!(ok(register_body(&KEY, &["nope".to_string()], now)), 400, "bad token");
    assert_eq!(ok(register_body(&KEY, &[], now)), 400, "no tokens");
    let many: Vec<String> = (0..4097u32).map(|i| format!("pg-canary-{:024x}", i)).collect();
    assert_eq!(ok(register_body(&KEY, &many, now)), 400, "too many tokens in one request");
    assert_eq!(svc.stats().auth_failures, 2);
    // Tampering with a signed body invalidates it.
    let b = register_body(&KEY, &[token(3)], now).replace(&token(3), &token(4));
    assert_eq!(ok(b), 401);
}

#[test]
fn malformed_and_hostile_requests_never_panic() {
    let clock = ManualClock::new(1_700_000_000);
    let svc = pure_service(&clock);
    let huge_head = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(20_000));
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        b"\r\n\r\n".to_vec(),
        b"GET".to_vec(),
        b"GET / HTTP/1.1".to_vec(),
        b"GET / HTTP/2.0\r\n\r\n".to_vec(),
        b"GET nothttp HTTP/1.1\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1 extra\r\n\r\n".to_vec(),
        b"POST /register HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n".to_vec(),
        b"POST /register HTTP/1.1\r\nContent-Length: abc\r\n\r\n".to_vec(),
        b"POST /register HTTP/1.1\r\nContent-Length: 50\r\n\r\nshort".to_vec(),
        b"GET /events HTTP/1.1\r\n\r\n".to_vec(),
        b"GET /events?nonce=zz&tokens=a HTTP/1.1\r\n\r\n".to_vec(),
        b"DELETE /c/x HTTP/1.1\r\n\r\n".to_vec(),
        b"GET /unknown HTTP/1.1\r\n\r\n".to_vec(),
        vec![0xff, 0xfe, 0x00, 0x80, b'\r', b'\n', b'\r', b'\n'],
        huge_head.into_bytes(),
    ];
    for c in cases {
        let r = svc.handle_request(&c, Some("peer"));
        let code = status(&r);
        assert!((200..600).contains(&code), "{:?} -> {code}", String::from_utf8_lossy(&c[..c.len().min(40)]));
    }
    assert_eq!(status(&svc.handle_request(b"DELETE /c/x HTTP/1.1\r\n\r\n", None)), 405);
}

#[test]
fn retention_is_bounded_in_time_and_count() {
    let clock = ManualClock::new(1_700_000_000);
    let cfg = ServiceConfig { max_events: 3, event_ttl_secs: 1000, ..ServiceConfig::new(KEY) };
    let svc = CanaryService::new(cfg, Arc::new(clock.clone()));
    let t = token(1);
    svc.handle_request(
        &raw("POST", "/register", &register_body(&KEY, std::slice::from_ref(&t), clock.unix_secs())),
        None,
    );
    for _ in 0..5 {
        svc.handle_request(&raw("GET", &format!("/c/{t}"), ""), None);
    }
    assert_eq!(svc.sizes(), (1, 3), "oldest events are dropped past the cap");
    clock.advance(1001);
    svc.handle_request(&raw("GET", "/healthz", ""), None);
    assert_eq!(svc.sizes(), (0, 0), "registrations and events expire after the retention period");
    // After expiry a hit on the old token is ignored.
    svc.handle_request(&raw("GET", &format!("/c/{t}"), ""), None);
    assert_eq!(svc.sizes(), (0, 0));
}

#[test]
fn token_registry_capacity_is_bounded() {
    let clock = ManualClock::new(1_700_000_000);
    let cfg = ServiceConfig { max_tokens: 2, ..ServiceConfig::new(KEY) };
    let svc = CanaryService::new(cfg, Arc::new(clock.clone()));
    let reg = |toks: &[String]| {
        status(&svc.handle_request(&raw("POST", "/register", &register_body(&KEY, toks, clock.unix_secs())), None))
    };
    assert_eq!(reg(&[token(1), token(2)]), 200);
    assert_eq!(reg(&[token(3)]), 503);
    assert_eq!(reg(&[token(1)]), 200, "re-registering a known token needs no new space");
}

#[test]
fn source_address_is_not_stored_unless_enabled() {
    let clock = ManualClock::new(1_700_000_000);
    for (log, expect) in [(false, "external"), (true, "203.0.113.9")] {
        let svc =
            CanaryService::new(ServiceConfig { log_source: log, ..ServiceConfig::new(KEY) }, Arc::new(clock.clone()));
        let t = token(1);
        svc.handle_request(
            &raw("POST", "/register", &register_body(&KEY, std::slice::from_ref(&t), clock.unix_secs())),
            None,
        );
        svc.handle_request(&raw("GET", &format!("/c/{t}"), ""), Some("203.0.113.9"));
        let body = parse_response(
            &svc.handle_request(&raw("GET", &format!("/events?nonce={}&tokens={t}", "ab".repeat(16)), ""), None),
        )
        .1;
        assert!(body.contains(&format!("{t} 1700000000 {expect}")), "log_source={log}: {body}");
    }
}

#[test]
fn wrong_reporting_key_is_reported_as_untrusted_not_as_a_clean_path() {
    let world = World::new();
    let svc = start(ServiceConfig::new(KEY), world.clock().clone());
    let remote = RemoteCanary::new(svc.addr.clone(), [1; 32], Arc::new(world.clock().clone()));
    assert!(matches!(remote.register(&[token(1)]), Err(CanaryError::Untrusted(_))));
    let _ = Honeypot::new();
}
