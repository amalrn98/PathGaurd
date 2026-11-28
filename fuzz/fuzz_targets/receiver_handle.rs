#![no_main]
use libfuzzer_sys::fuzz_target;
use pathguard::clock::ManualClock;
use pathguard::message::Message;
use pathguard::{Identity, Receiver};
use std::sync::Arc;

// A fresh, permissive receiver per input: every byte string must yield a well-formed reply.
fuzz_target!(|data: &[u8]| {
    let mut recv = Receiver::new(Identity::from_seed([7; 32])).with_clock(Arc::new(ManualClock::new(1_700_000_000)));
    recv.allow_any_authenticated_sender();
    let reply = recv.handle(data);
    assert!(Message::decode(&reply).is_ok());
});
