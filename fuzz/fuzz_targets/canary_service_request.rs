#![no_main]
use libfuzzer_sys::fuzz_target;
use pathguard::canary_service::{CanaryService, ServiceConfig};
use pathguard::clock::ManualClock;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let svc = CanaryService::new(ServiceConfig::new([1; 32]), Arc::new(ManualClock::new(1_700_000_000)));
    let out = svc.handle_request(data, Some("fuzz"));
    assert!(out.starts_with(b"HTTP/1.1 "));
});
