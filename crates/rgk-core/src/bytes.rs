//! Fixed-width byte aliases used by canonical RGK types.
//!
//! These are thin wrappers over `[u8; N]` (not newtypes) so they stay trivially
//! interoperable with upstream 32-byte hash types (`kaspa_hashes::Hash`,
//! etc.) via `TryFrom`/`Into`. Encoding is always the raw
//! little-endian-or-big-endian order chosen per-field in [`crate::encoding`];
//! here we only define storage.

use alloc::format;
use alloc::string::String;
use core::fmt;
use core::ops::Deref;

use crate::error::DecodeError;

/// A 20-byte digest (used for some Kaspa script hashes / short commitments).
pub type Bytes20 = [u8; 20];

/// A 32-byte digest. This is the dominant RGK width: it matches
/// `kaspa_hashes::Hash`, SHA-256 outputs, and native RGK commitment ids.
pub type Bytes32 = [u8; 32];

/// A 64-byte blob (e.g. a Schnorr signature or a concatenated pair of 32-byte
/// commitments).
pub type Bytes64 = [u8; 64];

/// Display wrapper around a 32-byte value.
///
/// This is intentionally defined in `rgk-core` so every crate uses the same
/// public error-display type instead of exposing crate-local lookalikes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Hex32(pub Bytes32);

impl fmt::Display for Hex32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        f.write_str(&to_hex(&self.0))
    }
}

impl From<Bytes32> for Hex32 {
    fn from(bytes: Bytes32) -> Self {
        Self(bytes)
    }
}

impl From<Hex32> for Bytes32 {
    fn from(value: Hex32) -> Self {
        value.0
    }
}

impl AsRef<Bytes32> for Hex32 {
    fn as_ref(&self) -> &Bytes32 {
        &self.0
    }
}

impl Deref for Hex32 {
    type Target = Bytes32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Parse exactly `N` lowercase-hex characters into a fixed byte array.
///
/// Used by tests and by fixture loaders; never on any untrusted/fast path. Hex
/// must be lowercase to keep canonical textual representations deterministic.
pub fn from_hex<const N: usize>(s: &str) -> Result<[u8; N], DecodeError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let expected = N * 2;
    let bytes = s.as_bytes();
    if bytes.len() != expected {
        return Err(DecodeError::HexBadLength {
            expected,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = HEX
            .iter()
            .position(|&c| c == chunk[0])
            .ok_or(DecodeError::HexBadChar(chunk[0] as char))?;
        let lo = HEX
            .iter()
            .position(|&c| c == chunk[1])
            .ok_or(DecodeError::HexBadChar(chunk[1] as char))?;
        out[i] = (hi as u8) << 4 | (lo as u8);
    }
    Ok(out)
}

/// Lowercase hex of a byte slice.
pub fn to_hex<const N: usize>(bytes: &[u8; N]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(N * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Debug-render a 32-byte digest as `0x` + lowercase hex.
pub fn fmt_hex<const N: usize>(bytes: &[u8; N], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "0x{}", to_hex(bytes))
}

/// Re-exported so other crates can build user-facing error strings without
/// depending on `alloc::format` quirks.
pub fn hex_display<const N: usize>(bytes: &[u8; N]) -> String {
    format!("0x{}", to_hex(bytes))
}
