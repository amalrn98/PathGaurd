//! Cryptographic building blocks.
//!
//! Only well-reviewed primitives from the RustCrypto and dalek projects are
//! used: Ed25519 signatures, X25519 key agreement, HKDF-SHA256, HMAC-SHA256
//! and ChaCha20-Poly1305. No custom primitives are implemented here.

use crate::error::{Error, Result};
use crate::util;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Long-term Ed25519 identity (private).
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }
    /// Rebuild an identity from a 32 byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }
    /// The 32 byte seed. Treat as secret.
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }
    /// Public half of the identity.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity(self.signing.verifying_key().to_bytes())
    }
    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}

/// Public Ed25519 identity. Receivers are identified (pinned) by this value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicIdentity(pub [u8; 32]);

impl PublicIdentity {
    /// Verify a signature (strict mode, rejects malleable signatures).
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        let sig = Signature::from_bytes(sig);
        vk.verify_strict(msg, &sig).is_ok()
    }
    /// Hex form of the key.
    pub fn to_hex(&self) -> String {
        util::hex(&self.0)
    }
    /// Parse from hex.
    pub fn from_hex(s: &str) -> Option<Self> {
        util::from_hex::<32>(s).map(Self)
    }
    /// Short fingerprint for display (first 8 bytes of SHA-256).
    pub fn fingerprint(&self) -> String {
        util::hex(&sha256(&[&self.0])[..8])
    }
}

/// One-shot X25519 key pair.
pub struct Ephemeral {
    secret: EphemeralSecret,
    /// Public key to send to the peer.
    pub public: [u8; 32],
}

impl Ephemeral {
    /// Generate a fresh key pair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }
    /// Complete the key agreement. Rejects non-contributory (low-order) peer keys.
    pub fn agree(self, peer: &[u8; 32]) -> Result<[u8; 32]> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer));
        if !shared.was_contributory() {
            return Err(Error::Crypto("non-contributory key agreement"));
        }
        Ok(shared.to_bytes())
    }
}

/// Independent keys derived for one session. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// AEAD key for the real payload.
    pub payload: [u8; 32],
    /// MAC key for probes, replies, acks and close messages.
    pub probe: [u8; 32],
    /// AEAD key for payload-like decoys. Never reused for real data.
    pub decoy: [u8; 32],
    /// MAC key for deriving canary tokens.
    pub canary: [u8; 32],
}

/// Derive session keys from the DH output and the handshake transcript hash.
pub fn derive_session_keys(shared: &[u8; 32], transcript: &[u8; 32]) -> SessionKeys {
    let hk = Hkdf::<Sha256>::new(Some(transcript), shared);
    let mut k = SessionKeys {
        payload: [0; 32],
        probe: [0; 32],
        decoy: [0; 32],
        canary: [0; 32],
    };
    hk.expand(b"pathguard/v1/payload", &mut k.payload)
        .expect("32 bytes is a valid HKDF output length");
    hk.expand(b"pathguard/v1/probe", &mut k.probe)
        .expect("32 bytes is a valid HKDF output length");
    hk.expand(b"pathguard/v1/decoy", &mut k.decoy)
        .expect("32 bytes is a valid HKDF output length");
    hk.expand(b"pathguard/v1/canary", &mut k.canary)
        .expect("32 bytes is a valid HKDF output length");
    k
}

/// SHA-256 over length-prefixed parts.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-SHA256 over length-prefixed parts (no ambiguity between part boundaries).
pub fn mac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(&(p.len() as u32).to_be_bytes());
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Constant-time MAC verification.
pub fn mac_verify(key: &[u8; 32], parts: &[&[u8]], tag: &[u8; 32]) -> bool {
    util::ct_eq(&mac(key, parts), tag)
}

/// 96-bit nonce from a sequence number. Safe because each key is used with a
/// strictly increasing sequence (payload) or a unique probe id (decoys).
pub fn seq_nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// ChaCha20-Poly1305 encrypt.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto("encryption failed"))
}

/// ChaCha20-Poly1305 decrypt.
pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Auth("decryption failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let id = Identity::generate();
        let sig = id.sign(b"msg");
        assert!(id.public().verify(b"msg", &sig));
        assert!(!id.public().verify(b"other", &sig));
        let other = Identity::generate();
        assert!(!other.public().verify(b"msg", &sig));
    }

    #[test]
    fn key_agreement_matches() {
        let a = Ephemeral::generate();
        let b = Ephemeral::generate();
        let (ap, bp) = (a.public, b.public);
        assert_eq!(a.agree(&bp).unwrap(), b.agree(&ap).unwrap());
    }

    #[test]
    fn rejects_low_order_point() {
        let a = Ephemeral::generate();
        assert!(a.agree(&[0u8; 32]).is_err());
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let key = [9u8; 32];
        let n = seq_nonce(1);
        let mut ct = seal(&key, &n, b"aad", b"secret").unwrap();
        assert_eq!(open(&key, &n, b"aad", &ct).unwrap(), b"secret");
        assert!(open(&key, &n, b"other", &ct).is_err());
        ct[0] ^= 1;
        assert!(open(&key, &n, b"aad", &ct).is_err());
    }

    #[test]
    fn mac_binds_part_boundaries() {
        let k = [1u8; 32];
        assert_ne!(mac(&k, &[b"ab", b"c"]), mac(&k, &[b"a", b"bc"]));
    }
}
