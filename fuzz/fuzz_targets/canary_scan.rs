#![no_main]
use libfuzzer_sys::fuzz_target;
use pathguard::canary;

fuzz_target!(|data: &[u8]| {
    for t in canary::scan(data) {
        assert!(canary::is_valid_token(&t));
    }
});
