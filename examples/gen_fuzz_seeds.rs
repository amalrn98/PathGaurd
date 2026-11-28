//! Writes a small seed corpus for the cargo-fuzz targets.
//!
//! Run with: `cargo run --example gen_fuzz_seeds`

use pathguard::message::{Message, ProbeKind, RejectCode};
use pathguard::Policy;
use std::fs;
use std::path::Path;

fn write(dir: &str, name: &str, data: &[u8]) {
    let d = Path::new("fuzz/corpus").join(dir);
    fs::create_dir_all(&d).expect("create corpus dir");
    fs::write(d.join(name), data).expect("write seed");
}

fn main() {
    let messages = [
        (
            "hello",
            Message::Hello {
                session_id: [1; 16],
                timestamp: 1_700_000_000,
                sender_eph: [2; 32],
                sender_id: [3; 32],
                recipient: [4; 32],
                sig: [5; 64],
            },
        ),
        ("hello_ack", Message::HelloAck { session_id: [1; 16], recv_eph: [2; 32], recv_id: [3; 32], sig: [5; 64] }),
        (
            "probe",
            Message::Probe {
                session_id: [1; 16],
                probe_id: [2; 16],
                kind: ProbeKind::Bait,
                seq: 1,
                body: b"pgprobe:00".to_vec(),
                mac: [7; 32],
            },
        ),
        ("probe_reply", Message::ProbeReply { session_id: [1; 16], probe_id: [2; 16], seq: 1, mac: [7; 32] }),
        ("payload", Message::Payload { session_id: [1; 16], seq: 1, ciphertext: vec![9; 48] }),
        ("payload_ack", Message::PayloadAck { session_id: [1; 16], seq: 1, mac: [7; 32] }),
        ("close", Message::Close { session_id: [1; 16], mac: [7; 32] }),
        ("reject", Message::Reject { code: RejectCode::Stale }),
    ];
    for (name, m) in &messages {
        write("message_decode", name, &m.encode());
        write("receiver_handle", name, &m.encode());
    }
    for p in ["baseline", "balanced", "paranoid"] {
        write("policy_toml", p, Policy::preset(p).expect("preset").to_toml().as_bytes());
    }
    let http: [(&str, &str); 4] = [
        ("bait", "GET /c/pg-canary-0123456789abcdef01234567 HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("events", "GET /events?nonce=00112233445566778899aabbccddeeff&tokens=pg-canary-0123456789abcdef01234567 HTTP/1.1\r\n\r\n"),
        ("register", "POST /register HTTP/1.1\r\nContent-Length: 40\r\n\r\nnonce 00\nnow 1\ntoken pg-canary-0123456789abcdef01234567\ntag 00\n"),
        ("health", "GET /healthz HTTP/1.1\r\n\r\n"),
    ];
    for (name, req) in http {
        write("canary_service_request", name, req.as_bytes());
    }
    write("canary_scan", "token", b"x pg-canary-0123456789abcdef01234567 y");
}
