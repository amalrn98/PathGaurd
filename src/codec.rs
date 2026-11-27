//! Minimal, bounds-checked binary codec used by the wire format.

use crate::error::{Error, Result};

pub use crate::limits::MAX_MESSAGE;

/// Append-only writer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// New empty writer.
    pub fn new() -> Self {
        Self::default()
    }
    /// Write one byte.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    /// Write a big-endian u64.
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    /// Write raw bytes with no length prefix (fixed-size fields).
    pub fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    /// Write a u32 length prefix followed by the bytes.
    pub fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(&(v.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(v);
    }
    /// Take the encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Bounds-checked reader.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// New reader over a buffer.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Malformed("length overflow"))?;
        if end > self.buf.len() {
            return Err(Error::Malformed("truncated"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    /// Read a big-endian u64.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }
    /// Read a fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    /// Read a length-prefixed byte string. The declared length is checked
    /// against `max` **before** anything is allocated or copied, so a hostile
    /// length field cannot cause a large allocation.
    pub fn bytes_max(&mut self, max: usize) -> Result<Vec<u8>> {
        let n = u32::from_be_bytes(self.array::<4>()?) as usize;
        if n > max {
            return Err(Error::TooLarge);
        }
        Ok(self.take(n)?.to_vec())
    }
    /// Require that the whole buffer was consumed.
    pub fn finish(self) -> Result<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut w = Writer::new();
        w.u8(7);
        w.u64(42);
        w.bytes(b"hello");
        let buf = w.finish();
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u64().unwrap(), 42);
        assert_eq!(r.bytes_max(16).unwrap(), b"hello");
        r.finish().unwrap();
    }

    #[test]
    fn rejects_truncated_and_oversized() {
        let mut r = Reader::new(&[0, 0, 0, 9, 1]);
        assert!(matches!(r.bytes_max(100), Err(Error::Malformed(_))));
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(r.bytes_max(100), Err(Error::TooLarge)));
        let mut r = Reader::new(&[0, 0, 0, 5, 1, 2, 3, 4, 5]);
        assert!(matches!(r.bytes_max(4), Err(Error::TooLarge)), "limit is exclusive of length 5");
        let r = Reader::new(&[1]);
        assert!(r.finish().is_err());
    }
}
