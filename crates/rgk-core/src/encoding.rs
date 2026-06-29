//! Canonical byte encoder/decoder.
//!
//! RGK never relies on `borsh` or `serde` for the *canonical* byte form. Both
//! of those libraries can change layouts across versions and neither gives a
//! byte-stable spec we can publish. Instead we hand-roll a tiny length-prefixed
//! binary format whose every field is documented in `docs/RECEIPT-SPEC.md`.
//!
//! Rules:
//! * Every struct encodes a domain-separation prefix first (see [`crate::commit`]).
//! * Fixed-width integers are little-endian.
//! * Variable byte blobs are length-prefixed with a `u32` LE length, checked
//!   against caller-supplied maximums to bound decode cost (DoS protection).
//! * `Bytes32` / `Bytes20` encode as raw bytes (no length prefix) — their width
//!   is fixed by type.
//! * Decoding is total: every read that runs past EOF returns
//!   [`DecodeError::Eof`], and the public decode entrypoints consume the whole
//!   buffer (trailing bytes ⇒ [`DecodeError::TrailingBytes`]).

use alloc::string::String;
use alloc::vec::Vec;

use crate::bytes::{Bytes20, Bytes32};
use crate::error::DecodeError;

/// Canonical RGK encoding version. Bumped on any breaking byte-layout change.
pub const ENCODING_VERSION: u16 = 1;

/// Maximum size of any length-prefixed variable blob. Anything larger fails
/// decoding — this is a hard DoS budget (see `VERIFICATION-BUDGET.md`).
pub const MAX_BLOB_BYTES: u32 = 1 << 20; // 1 MiB

/// The domain-separation magic prefix used by every canonical struct:
/// ASCII `rgk:v0\0` (8 bytes). Pinned at compile time.
pub const DOMAIN_MAGIC: &[u8; 8] = b"rgk:v0\x00\x00";

/// A trait implemented by every canonical RGK type. Implementations must be
/// byte-deterministic and must round-trip through [`encode`] / [`decode_full`].
pub trait Canonical: Sized {
    fn encode(&self, w: &mut Writer);
    fn decode(r: &mut Reader) -> Result<Self, DecodeError>;

    /// Convenience: encode to a fresh `Vec<u8>`, writing the domain magic +
    /// version header first.
    fn encode_canonical(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_bytes(DOMAIN_MAGIC);
        w.write_u16(ENCODING_VERSION);
        self.encode(&mut w);
        w.into_vec()
    }

    /// Convenience: decode, enforcing the domain magic + version header and that
    /// the entire buffer is consumed.
    fn decode_canonical(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let magic = r.read_array::<8>()?;
        if magic != *DOMAIN_MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let version = r.read_u16()?;
        if version != ENCODING_VERSION {
            return Err(DecodeError::UnknownVersion(version));
        }
        let value = Self::decode(&mut r)?;
        r.ensure_consumed()?;
        Ok(value)
    }
}

/// Append-only canonical writer.
pub struct Writer {
    buf: Vec<u8>,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn write_bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    pub fn write_bytes20(&mut self, b: &Bytes20) {
        self.buf.extend_from_slice(b);
    }
    pub fn write_bytes32(&mut self, b: &Bytes32) {
        self.buf.extend_from_slice(b);
    }
    /// Length-prefixed (u32 LE) variable blob.
    pub fn write_blob(&mut self, b: &[u8]) {
        self.write_u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }
    /// Length-prefixed (u32 LE) UTF-8 string.
    pub fn write_str(&mut self, s: &str) {
        self.write_blob(s.as_bytes());
    }
    pub fn write_bool(&mut self, b: bool) {
        self.write_u8(if b { 1 } else { 0 });
    }
}

/// Cursor over an input buffer with explicit bounds checking.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }
    pub fn read_bytes20(&mut self) -> Result<Bytes20, DecodeError> {
        self.read_array::<20>()
    }
    pub fn read_bytes32(&mut self) -> Result<Bytes32, DecodeError> {
        self.read_array::<32>()
    }
    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.read_u8()? != 0)
    }

    /// Read a length-prefixed variable blob, enforcing [`MAX_BLOB_BYTES`].
    pub fn read_blob(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.read_u32()? as usize;
        if len > MAX_BLOB_BYTES as usize {
            return Err(DecodeError::BlobTooLong {
                len,
                max: MAX_BLOB_BYTES as usize,
            });
        }
        self.take(len)
    }

    /// Read a length-prefixed UTF-8 string with the same cap as [`Self::read_blob`].
    pub fn read_str(&mut self) -> Result<String, DecodeError> {
        let blob = self.read_blob()?;
        core::str::from_utf8(blob)
            .map(String::from)
            .map_err(|_| DecodeError::InvalidUtf8)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self
            .pos
            .checked_add(n)
            .map_or(true, |end| end > self.buf.len())
        {
            return Err(DecodeError::Eof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Fail if the buffer was not fully consumed. Prevents silent acceptance of
    /// trailing garbage / malleated encodings.
    pub fn ensure_consumed(&self) -> Result<(), DecodeError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes {
                remaining: self.buf.len() - self.pos,
            })
        }
    }
}
