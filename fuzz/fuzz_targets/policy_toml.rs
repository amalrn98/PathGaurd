#![no_main]
use libfuzzer_sys::fuzz_target;
use pathguard::Policy;

// Parsing arbitrary text must not panic, and an accepted policy must validate and round-trip.
fuzz_target!(|text: &str| {
    if let Ok(p) = Policy::from_toml_str(text) {
        p.validate().unwrap();
        assert_eq!(Policy::from_toml_str(&p.to_toml()).unwrap(), p);
    }
});
