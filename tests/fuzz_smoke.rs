//! Deterministic mutation fuzzing that runs on stable in CI.
//!
//! It is a smoke test, not a replacement for coverage-guided fuzzing (`fuzz/`, see
//! docs/TESTING.md). It mutates valid messages, HTTP requests and policy files with a
//! seeded RNG and checks three things on every input: nothing panics, the receiver
//! always answers with a well-formed message, and no single allocation is larger than
//! the protocol limits justify (so a hostile length field cannot request gigabytes).
//!
//! Everything lives in one test because the allocation tracker is process-wide.

mod common;

use common::{handshake, new_receiver};
use pathguard::canary_service::{CanaryService, ServiceConfig};
use pathguard::clock::ManualClock;
use pathguard::crypto::{self, Identity};
use pathguard::limits::{MAX_MESSAGE, MAX_PAYLOAD_CIPHERTEXT};
use pathguard::message::{Message, ProbeKind};
use pathguard::receiver::{close_mac, payload_aad};
use pathguard::Policy;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct Tracking;
static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LARGEST.fetch_max(l.size(), Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        LARGEST.fetch_max(new, Ordering::Relaxed);
        System.realloc(p, l, new)
    }
}

#[global_allocator]
static A: Tracking = Tracking;

fn iterations() -> u64 {
    std::env::var("PG_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(15_000)
}

fn mutate(rng: &mut StdRng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..rng.random_range(1..5) {
        match rng.random_range(0..8) {
            0 if !b.is_empty() => {
                let i = rng.random_range(0..b.len());
                b[i] ^= 1 << rng.random_range(0..8);
            }
            1 if !b.is_empty() => {
                let i = rng.random_range(0..b.len());
                b[i] = rng.random();
            }
            2 => b.truncate(rng.random_range(0..=b.len())),
            3 => {
                let n = rng.random_range(1..40);
                b.extend((0..n).map(|_| rng.random::<u8>()));
            }
            4 if b.len() >= 4 => {
                // Plant an interesting length at a random offset.
                let interesting = [
                    0u32,
                    1,
                    15,
                    16,
                    17,
                    255,
                    256,
                    65_535,
                    MAX_PAYLOAD_CIPHERTEXT as u32,
                    MAX_PAYLOAD_CIPHERTEXT as u32 + 1,
                    MAX_MESSAGE as u32,
                    u32::MAX,
                    u32::MAX - 1,
                    1 << 31,
                ];
                let v = interesting[rng.random_range(0..interesting.len())].to_be_bytes();
                let i = rng.random_range(0..=b.len() - 4);
                b[i..i + 4].copy_from_slice(&v);
            }
            5 if !b.is_empty() => b[0] = rng.random_range(0..12),
            6 if !b.is_empty() => {
                let (i, j) = (rng.random_range(0..b.len()), rng.random_range(0..b.len()));
                let chunk: Vec<u8> = b[i.min(j)..i.max(j)].to_vec();
                b.extend(chunk);
            }
            7 if !b.is_empty() => {
                let i = rng.random_range(0..b.len());
                b.remove(i);
            }
            _ => {}
        }
    }
    b
}

#[test]
fn mutation_fuzzing_finds_no_panics_and_no_oversized_allocations() {
    // The tracker must be able to see a large allocation, or the limit checks below prove nothing.
    LARGEST.store(0, Ordering::Relaxed);
    drop(std::hint::black_box(Vec::<u8>::with_capacity(4 * MAX_MESSAGE)));
    assert!(LARGEST.load(Ordering::Relaxed) >= 4 * MAX_MESSAGE, "allocation tracker is not working");

    let (mut recv, _clock) = new_receiver();
    recv.allow_any_authenticated_sender();
    let alice = Identity::generate();
    let (sid, keys) = handshake(&mut recv, &alice).unwrap();
    let me = recv.public().0;

    // Corpus: a valid message of every kind for a live session.
    let probe_id = [5u8; 16];
    let body = b"pgprobe:1234".to_vec();
    let pmac = crypto::mac(&keys.probe, &[b"probe", &sid, &probe_id, &[0u8], &9u64.to_be_bytes(), &body]);
    let ct = crypto::seal(&keys.payload, &crypto::seq_nonce(1), &payload_aad(&sid, &me, 1), b"hello world").unwrap();
    let hello = common::make_hello(&alice, &recv.public()).bytes;
    let corpus: Vec<Vec<u8>> = vec![
        hello,
        Message::Probe { session_id: sid, probe_id, kind: ProbeKind::Interception, seq: 9, body, mac: pmac }.encode(),
        Message::Payload { session_id: sid, seq: 1, ciphertext: ct }.encode(),
        Message::Close { session_id: sid, mac: close_mac(&keys.probe, &sid) }.encode(),
        Message::Reject { code: pathguard::message::RejectCode::Busy }.encode(),
        vec![],
    ];

    let mut rng = StdRng::seed_from_u64(0x00F0_221E);
    let n = iterations();

    // 1. Wire messages against a live receiver.
    LARGEST.store(0, Ordering::Relaxed);
    for i in 0..n {
        let input = mutate(&mut rng, &corpus[(i as usize) % corpus.len()]);
        let reply = recv.handle(&input);
        assert!(Message::decode(&reply).is_ok(), "malformed reply to {input:02x?}");
        assert!(recv.session_count() <= recv.config().max_sessions);
    }
    let largest = LARGEST.load(Ordering::Relaxed);
    assert!(largest <= 2 * MAX_MESSAGE, "a mutated message caused a {largest} byte allocation");

    // 2. Hostile HTTP against the canary service.
    let svc = CanaryService::new(ServiceConfig::new([1; 32]), Arc::new(ManualClock::new(1_700_000_000)));
    let http_corpus: Vec<Vec<u8>> = vec![
        b"GET /c/pg-canary-0123456789abcdef01234567 HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        b"GET /events?nonce=00112233445566778899aabbccddeeff&tokens=pg-canary-0123456789abcdef01234567 HTTP/1.1\r\n\r\n".to_vec(),
        b"POST /register HTTP/1.1\r\nContent-Length: 20\r\n\r\nnonce abc\nnow 1\ntag 00".to_vec(),
    ];
    LARGEST.store(0, Ordering::Relaxed);
    for i in 0..n {
        let input = mutate(&mut rng, &http_corpus[(i as usize) % http_corpus.len()]);
        let out = svc.handle_request(&input, Some("peer"));
        assert!(out.starts_with(b"HTTP/1.1 "));
    }
    assert!(
        LARGEST.load(Ordering::Relaxed) <= 2 * MAX_MESSAGE,
        "service allocated {} bytes",
        LARGEST.load(Ordering::Relaxed)
    );

    // 3. Mutated policy files.
    let toml = Policy::paranoid().to_toml().into_bytes();
    for _ in 0..n / 5 {
        let input = mutate(&mut rng, &toml);
        if let Ok(text) = std::str::from_utf8(&input) {
            if let Ok(p) = Policy::from_toml_str(text) {
                p.validate().expect("an accepted policy is always valid");
            }
        }
    }
}
