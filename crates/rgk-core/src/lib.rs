#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-core
//!
//! Canonical, dependency-free types and **domain-separated deterministic
//! encoding** for the RGK substrate.
//!
//! ## What lives here
//!
//! * The wire-canonical byte types: [`RgkAssetRef`], [`RgkStateCommitment`],
//!   [`RgkReceipt`], and their supporting enums ([`KaspaChainId`],
//!   [`ReceiptPolicy`], [`ProofMode`], [`ReceiptId`]).
//! * A hand-rolled [`Writer`] / [`Reader`] pair over `Vec<u8>` slices. We do
//!   **not** use `borsh` or `serde` for canonical encoding on purpose: the RGK
//!   encoding is a *specification* (see `docs/RECEIPT-SPEC.md`) that must be
//!   byte-stable forever and must not drift if a downstream crate bumps its
//!   serialization library. Both `borsh` and `serde`/bincode can change byte
//!   layouts across versions; a fixed hand-rolled encoder cannot.
//! * SHA-256-based commitments with explicit domain separation tags.
//!
//! ## What does NOT live here
//!
//! No external chain or non-RGK asset-model types, no async, no I/O. This crate
//! only defines the *canonical boundary objects* and the rules for encoding
//! them. The integration crates adapt upstream chain types into these canonical
//! forms.
//!
//! ## Stability promise
//!
//! The encoding version is [`ENCODING_VERSION`]. Any change to the byte layout
//! requires bumping that version and is a breaking change. Decoding rejects
//! unknown versions, unknown chains, unknown proof modes and malformed input
//! (see [`DecodeError`]).

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(dead_code, unused_imports, unused_variables)]
#![allow(clippy::unnecessary_map_or)]

extern crate alloc;

mod bytes;
mod chain;
mod commit;
mod encoding;
mod error;
mod policy;
#[cfg(test)]
mod tests;
mod types;

pub use bytes::{from_hex, to_hex, Bytes20, Bytes32, Bytes64, Hex32};
pub use chain::{KaspaChainId, KASPA_LOCAL_TOCCATA};
pub use commit::{
    build_policy_migration_proof, domain_hash, domain_hash_str, lineage_id,
    policy_migration_commitment, receipt_commitment, replay_nonce, state_commitment, DomainTag,
};
pub use encoding::{Canonical, Reader, Writer, ENCODING_VERSION, MAX_BLOB_BYTES};
pub use error::{DecodeError, EncodeError};
pub use policy::{ProofMode, ReceiptPolicy};
pub use types::{
    ContinuationCommitment, CovenantLineageId, KaspaCovenantId, KaspaOutpoint,
    PolicyMigrationCommitment, PolicyMigrationInput, PolicyMigrationProof, ReceiptId, RgkAssetId,
    RgkAssetRef, RgkReceipt, RgkSchemaId, RgkStateCommitment, TransitionDigest,
};
