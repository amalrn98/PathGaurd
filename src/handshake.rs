//! Authenticated key agreement transcripts.
//!
//! The sender signs a hello that names the intended recipient, so a hello
//! cannot be replayed to a different receiver. The receiver signs an ack that
//! binds the hello digest and its own ephemeral key. Session keys are derived
//! from the DH secret and the hash of both signed inputs.

use crate::crypto::sha256;

/// Bytes signed by the sender in the hello message.
pub fn hello_input(
    session_id: &[u8; 16],
    timestamp: u64,
    sender_eph: &[u8; 32],
    sender_id: &[u8; 32],
    recipient: &[u8; 32],
) -> Vec<u8> {
    let mut v = b"pathguard/v1/hello".to_vec();
    v.extend_from_slice(session_id);
    v.extend_from_slice(&timestamp.to_be_bytes());
    v.extend_from_slice(sender_eph);
    v.extend_from_slice(sender_id);
    v.extend_from_slice(recipient);
    v
}

/// Bytes signed by the receiver in the hello acknowledgement.
pub fn ack_input(hello_digest: &[u8; 32], session_id: &[u8; 16], recv_eph: &[u8; 32], recv_id: &[u8; 32]) -> Vec<u8> {
    let mut v = b"pathguard/v1/ack".to_vec();
    v.extend_from_slice(hello_digest);
    v.extend_from_slice(session_id);
    v.extend_from_slice(recv_eph);
    v.extend_from_slice(recv_id);
    v
}

/// Transcript hash used as the HKDF salt.
pub fn transcript(hello_in: &[u8], ack_in: &[u8]) -> [u8; 32] {
    sha256(&[hello_in, ack_in])
}
