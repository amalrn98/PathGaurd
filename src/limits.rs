//! Protocol-wide size and count limits.
//!
//! Sender, receiver and decoder all read these constants, so the three cannot
//! drift apart. Anything the network controls is bounded by one of them before
//! memory is allocated for it.

/// Largest plaintext payload in one message.
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
/// Poly1305 tag appended by the AEAD.
pub const AEAD_TAG_LEN: usize = 16;
/// Largest payload ciphertext on the wire.
pub const MAX_PAYLOAD_CIPHERTEXT: usize = MAX_PAYLOAD_BYTES + AEAD_TAG_LEN;
/// Largest plaintext of a payload-like decoy.
pub const MAX_PROBE_PLAINTEXT: usize = 16 * 1024;
/// Largest probe body on the wire (an encrypted decoy of maximum size).
pub const MAX_PROBE_BODY: usize = MAX_PROBE_PLAINTEXT + AEAD_TAG_LEN;
/// Largest encoded message. Payload plus generous room for headers.
pub const MAX_MESSAGE: usize = MAX_PAYLOAD_CIPHERTEXT + 1024;
/// Most paths one `send` accepts.
pub const MAX_PATHS: usize = 16;
/// Most probes per path.
pub const MAX_PROBES_PER_PATH: u32 = 64;
/// Most probes a receiver accepts in one session (every path at the per-path maximum).
pub const MAX_PROBES_PER_SESSION: usize = MAX_PATHS * MAX_PROBES_PER_PATH as usize;

// Compile-time consistency checks.
const _: () = assert!(MAX_PAYLOAD_CIPHERTEXT == MAX_PAYLOAD_BYTES + AEAD_TAG_LEN);
const _: () = assert!(MAX_MESSAGE > MAX_PAYLOAD_CIPHERTEXT);
const _: () = assert!(MAX_PROBE_BODY < MAX_PAYLOAD_CIPHERTEXT);
