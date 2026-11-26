//! Small helpers: hex, randomness, constant-time comparison.

use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;

/// Lowercase hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a fixed-size array from hex.
pub fn from_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Fill a fixed-size array from the operating system CSPRNG.
pub fn random<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    OsRng.fill_bytes(&mut a);
    a
}

/// Constant-time equality for byte slices.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
