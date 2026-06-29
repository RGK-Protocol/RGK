//! Typed RGK-core errors. All decoding failures are explicit and non-malleable.

use alloc::string::String;
use thiserror::Error;

/// Errors that can occur while *decoding* a canonical RGK object.
///
/// Every variant maps to a hard rejection in the verifier — there is no
/// "lenient" decode. The variants are intentionally fine-grained so the
/// verifier / resolver can surface *why* a receipt was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("unexpected end of canonical buffer")]
    Eof,
    #[error("trailing {remaining} byte(s) after canonical object")]
    TrailingBytes { remaining: usize },
    #[error("bad domain magic prefix")]
    BadMagic,
    #[error("unknown canonical encoding version {0}")]
    UnknownVersion(u16),
    #[error("unknown Kaspa chain id tag {0:#04x}")]
    UnknownChain(u8),
    #[error("unknown receipt policy tag {0:#04x}")]
    UnknownReceiptPolicy(u8),
    #[error("unknown proof mode tag {0:#04x}")]
    UnknownProofMode(u8),
    #[error("bad domain tag byte: expected {expected:#04x}, got {got:#04x}")]
    BadDomainTag { expected: u8, got: u8 },
    #[error("variable blob length {len} exceeds max {max}")]
    BlobTooLong { len: usize, max: usize },
    #[error("canonical object contained invalid UTF-8")]
    InvalidUtf8,
    #[error("hex decode: expected {expected} chars, got {got}")]
    HexBadLength { expected: usize, got: usize },
    #[error("hex decode: bad char {0:?}")]
    HexBadChar(char),
    #[error("structural invariant violated: {0}")]
    Structural(String),
}

/// Errors that can occur while *encoding*. Encoding only fails on programmer
/// error (e.g. an oversized domain string), so this is kept minimal.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeError {
    #[error("canonical buffer overflowed a size budget: {0}")]
    Overflow(&'static str),
}
