//! Receipt policy + proof mode enums.
//!
//! These two enums encode the **trust model** of a receipt and are part of the
//! canonical wire format. They are also the security-critical knobs the verifier
//! checks against its configured policy: a `VerifierReceipt` is *not* accepted
//! by a resolver configured for `ZkReceipt` and vice-versa.

use crate::encoding::{Canonical, Reader, Writer};
use crate::error::DecodeError;

/// How a RGK receipt may be authorised.
///
/// * `VerifierReceipt` — an RGK verifier (trusted by the resolver) attests the
///   transition. This is the always-available baseline mode. It does **not**
///   prove anything on-chain beyond covenant lineage.
/// * `ZkReceipt` — a ZK proof carries the receipt's claim (see `ZK-BOUNDARY.md`).
///   Only meaningful where a usable KIP16 verifier exists; otherwise rejected.
/// * `P2mrRet` — optional native Kaspa P2MR-ret commitment mode. **Not
///   available** in the current rusty-kaspa Toccata branch; decoding/acceptance
///   is gated and reserved for a future KIP. See `COVENANT-SPEC.md`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ProofMode {
    VerifierReceipt = 0x01,
    ZkReceipt = 0x02,
    /// Reserved: a future native P2MR-ret mode. Not implemented by Kaspa today.
    P2mrRet = 0x03,
}

impl ProofMode {
    pub const TAG: u8 = 0x50; // 'P'

    pub const fn from_tag(tag: u8) -> Option<ProofMode> {
        match tag {
            0x01 => Some(ProofMode::VerifierReceipt),
            0x02 => Some(ProofMode::ZkReceipt),
            0x03 => Some(ProofMode::P2mrRet),
            _ => None,
        }
    }

    /// Stable textual identifier for the domain-separation string.
    pub const fn as_domain_str(self) -> &'static str {
        match self {
            ProofMode::VerifierReceipt => "verifier-receipt",
            ProofMode::ZkReceipt => "zk-receipt",
            ProofMode::P2mrRet => "p2mr-ret",
        }
    }

    /// Human-readable name.
    pub const fn as_str(self) -> &'static str {
        self.as_domain_str()
    }
}

impl Canonical for ProofMode {
    fn encode(&self, w: &mut Writer) {
        w.write_u8(ProofMode::TAG);
        w.write_u8(*self as u8);
    }
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_u8()?;
        if tag != ProofMode::TAG {
            return Err(DecodeError::BadDomainTag {
                expected: ProofMode::TAG,
                got: tag,
            });
        }
        let val = r.read_u8()?;
        ProofMode::from_tag(val).ok_or(DecodeError::UnknownProofMode(val))
    }
}

/// A coarse receipt policy that the covenant commits to at genesis and that the
/// resolver enforces on every spend. It is deliberately coarser than
/// [`ProofMode`]: it constrains *which* proof modes are acceptable for a given
/// covenant lineage, not the mode of a single receipt.
///
/// * `Any` — accept any proof mode the receipt carries (subject to the resolver
///   also accepting it).
/// * `VerifierOnly` — only `ProofMode::VerifierReceipt` is allowed. Rejects ZK
///   receipts even if otherwise valid.
/// * `ZkOrVerifier` — accept either `VerifierReceipt` or `ZkReceipt`. Never
///   `P2mrRet`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ReceiptPolicy {
    Any = 0x01,
    VerifierOnly = 0x02,
    ZkOrVerifier = 0x03,
}

impl ReceiptPolicy {
    pub const TAG: u8 = 0x52; // 'R'

    pub const fn from_tag(tag: u8) -> Option<ReceiptPolicy> {
        match tag {
            0x01 => Some(ReceiptPolicy::Any),
            0x02 => Some(ReceiptPolicy::VerifierOnly),
            0x03 => Some(ReceiptPolicy::ZkOrVerifier),
            _ => None,
        }
    }

    /// Whether a given proof mode satisfies this policy.
    pub const fn admits(self, mode: ProofMode) -> bool {
        match (self, mode) {
            (ReceiptPolicy::Any, _) => true,
            (ReceiptPolicy::VerifierOnly, ProofMode::VerifierReceipt) => true,
            (ReceiptPolicy::VerifierOnly, _) => false,
            (ReceiptPolicy::ZkOrVerifier, ProofMode::VerifierReceipt | ProofMode::ZkReceipt) => {
                true
            }
            (ReceiptPolicy::ZkOrVerifier, ProofMode::P2mrRet) => false,
        }
    }

    /// Stable textual identifier for the domain-separation string.
    pub const fn as_domain_str(self) -> &'static str {
        match self {
            ReceiptPolicy::Any => "any",
            ReceiptPolicy::VerifierOnly => "verifier-only",
            ReceiptPolicy::ZkOrVerifier => "zk-or-verifier",
        }
    }
}

impl Canonical for ReceiptPolicy {
    fn encode(&self, w: &mut Writer) {
        w.write_u8(ReceiptPolicy::TAG);
        w.write_u8(*self as u8);
    }
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_u8()?;
        if tag != ReceiptPolicy::TAG {
            return Err(DecodeError::BadDomainTag {
                expected: ReceiptPolicy::TAG,
                got: tag,
            });
        }
        let val = r.read_u8()?;
        ReceiptPolicy::from_tag(val).ok_or(DecodeError::UnknownReceiptPolicy(val))
    }
}
