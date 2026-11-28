#![no_main]
use libfuzzer_sys::fuzz_target;
use pathguard::message::Message;

// Decoding must never panic, and anything it accepts must be canonical.
fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Message::decode(data) {
        assert_eq!(m.encode(), data);
    }
});
