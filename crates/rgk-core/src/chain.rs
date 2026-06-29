//! Kaspa chain identification for RGK.
//!
//! The chain id is a first-class domain-separation input: a receipt minted on
//! `KaspaLocalToccata` is **never** acceptable as evidence on `KaspaMainnet`,
//! and the decoder rejects unknown chain ids. This is the single most important
//! anti-confusion control in the substrate — see `SECURITY.md`.

use crate::encoding::{Reader, Writer};
use crate::error::DecodeError;

/// A 4-byte discriminant identifying a Kaspa network.
///
/// The wire encoding is a single `u8` tag (see [`KaspaChainId::TAG`]); we keep a
/// 4-byte in-memory representation only so it composes cleanly with future
/// per-network salts. The tag values are part of the stable spec.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum KaspaChainId {
    /// Kaspa mainnet. Toccata activates ~2026-06-30 at DAA score 474_165_565.
    KaspaMainnet = 0x01,
    /// Kaspa public testnet (currently testnet-10 / testnet-12).
    KaspaTestnet = 0x02,
    /// Kaspa simnet — Toccata active from genesis, PoW skipped.
    KaspaSimnet = 0x03,
    /// Kaspa devnet — Toccata OFF by default, overridable.
    KaspaDevnet = 0x04,
    /// The canonical RGK local Toccata e2e network. This is the chain the
    /// local `kaspad --simnet` e2e harness runs against. Receipts minted here
    /// must never cross to other chains.
    KaspaLocalToccata = 0x05,
}

/// Convenience alias used across docs and the e2e harness.
pub const KASPA_LOCAL_TOCCATA: KaspaChainId = KaspaChainId::KaspaLocalToccata;

impl KaspaChainId {
    /// Stable wire tag (single byte).
    pub const TAG: u8 = 0x4b; // 'K'

    /// All currently-known chains, in spec order.
    pub const ALL: [KaspaChainId; 5] = [
        KaspaChainId::KaspaMainnet,
        KaspaChainId::KaspaTestnet,
        KaspaChainId::KaspaSimnet,
        KaspaChainId::KaspaDevnet,
        KaspaChainId::KaspaLocalToccata,
    ];

    /// Stable textual identifier used inside the domain-separation string. Do
    /// **not** change these — they are part of the canonical commitment domain.
    pub const fn as_domain_str(self) -> &'static str {
        match self {
            KaspaChainId::KaspaMainnet => "kaspa-mainnet",
            KaspaChainId::KaspaTestnet => "kaspa-testnet",
            KaspaChainId::KaspaSimnet => "kaspa-simnet",
            KaspaChainId::KaspaDevnet => "kaspa-devnet",
            KaspaChainId::KaspaLocalToccata => "kaspa-local-toccata",
        }
    }

    /// Whether Toccata (covenants + tx v1 + ZK opcodes) is active on this chain
    /// *by default*, per the rusty-kaspa `Params` presets.
    pub const fn toccata_active_by_default(self) -> bool {
        match self {
            // Simnet + LocalToccata activate from genesis. Mainnet activates at
            // a fixed DAA score; Testnet-10 is already past activation. We
            // conservatively report `true` for mainnet/testnet too because the
            // *protocol* supports it; runtime checks confirm actual activation.
            KaspaChainId::KaspaMainnet
            | KaspaChainId::KaspaTestnet
            | KaspaChainId::KaspaSimnet
            | KaspaChainId::KaspaLocalToccata => true,
            KaspaChainId::KaspaDevnet => false,
        }
    }

    pub const fn from_tag(tag: u8) -> Option<KaspaChainId> {
        match tag {
            0x01 => Some(KaspaChainId::KaspaMainnet),
            0x02 => Some(KaspaChainId::KaspaTestnet),
            0x03 => Some(KaspaChainId::KaspaSimnet),
            0x04 => Some(KaspaChainId::KaspaDevnet),
            0x05 => Some(KaspaChainId::KaspaLocalToccata),
            _ => None,
        }
    }
}

impl crate::encoding::Canonical for KaspaChainId {
    fn encode(&self, w: &mut Writer) {
        w.write_u8(KaspaChainId::TAG);
        w.write_u8(*self as u8);
    }
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_u8()?;
        if tag != KaspaChainId::TAG {
            return Err(DecodeError::BadDomainTag {
                expected: KaspaChainId::TAG,
                got: tag,
            });
        }
        let val = r.read_u8()?;
        KaspaChainId::from_tag(val).ok_or(DecodeError::UnknownChain(val))
    }
}
