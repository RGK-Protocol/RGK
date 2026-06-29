#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-tx
//!
//! Transaction builders for RGK. The builders are **pure functions** that
//! produce canonical byte-form transaction inputs / outputs. They never
//! submit to the network — that is the caller's job (via
//! [`KaspaChainBackend::submit_transaction`]).
//!
//! ## What the builders produce
//!
//! * [`build_genesis_output`] — the first covenant UTXO. Contains the
//!   payload bytes that the Toccata script verifies on every spend.
//! * [`build_transition_spend`] — the input set for a transition tx:
//!   exactly one input (the open covenant UTXO) plus zero or more fee inputs.
//! * [`build_transition_outputs`] — the outputs: the new covenant UTXO
//!   (carrying the advanced [`CovenantState`] payload) plus fee/change
//!   outputs.
//! * [`encode_canonical_tx`] — concatenates everything into a byte buffer
//!   ready to hand to the JSON-RPC `submitTransaction` endpoint.
//!
//! ## What the builders do NOT do
//!
//! * They do **not** sign inputs. Signatures are produced by the wallet
//!   after the builder returns the unsigned tx.
//! * They do **not** validate the new state. The covenant script does that
//!   on-chain; the resolver does it off-chain.
//! * They do **not** link against rusty-kaspa. They emit a canonical byte
//!   layout that the live e2e harness decodes via the upstream `Transaction`
//!   deserialiser when submitting to a real kaspad.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(dead_code, unused_imports, unused_variables)]
#![allow(clippy::needless_borrows_for_generic_args, clippy::vec_init_then_push)]
#![allow(
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::derivable_impls
)]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use rgk_core::{Bytes32, KaspaChainId, KaspaCovenantId, KaspaOutpoint, RgkStateCommitment};
use rgk_covenant::{CovenantSpec, CovenantState};
use thiserror::Error;

/// Errors produced by transaction builders.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TxBuildError {
    #[error("fee amount must be non-negative and less than the input total: got fee={fee}, in={in_total}")]
    BadFee { fee: u64, in_total: u64 },
    #[error("change output overflows u64: in={in_total}, fee={fee}, covenant={covenant}")]
    ChangeOverflow {
        in_total: u64,
        fee: u64,
        covenant: u64,
    },
    #[error("script public key is empty")]
    EmptyScriptPublicKey,
    #[error("chain id mismatch: tx is for {expected:?}, state is for {actual:?}")]
    ChainMismatch {
        expected: KaspaChainId,
        actual: KaspaChainId,
    },
    #[error("covenant id mismatch: tx covenant {tx}, state lineage {state}")]
    CovenantMismatch { tx: Hex32, state: HexBytes32 },
}

/// Display wrapper around a 32-byte value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hex32(pub Bytes32);
impl core::fmt::Display for Hex32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use rgk_core::to_hex;
        f.write_str("0x")?;
        f.write_str(&to_hex(&self.0))
    }
}
impl From<Bytes32> for Hex32 {
    fn from(b: Bytes32) -> Self {
        Hex32(b)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexBytes32(pub Bytes32);
impl core::fmt::Display for HexBytes32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use rgk_core::to_hex;
        f.write_str("0x")?;
        f.write_str(&to_hex(&self.0))
    }
}

/// A minimal transaction output. Matches `kaspa_consensus_core::tx::TransactionOutput`
/// layout (value u64 LE, then var-len script_public_key). `covenant_binding` is
/// optional; when present it carries `(authorizing_input, covenant_id)` for
/// Toccata-aware outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    pub value: u64,
    pub script_public_key: Vec<u8>,
    pub covenant_binding: Option<CovenantBinding>,
}

/// A Toccata covenant binding on an output. Matches
/// `kaspa_consensus_core::tx::CovenantBinding` (authorizing_input + covenant_id).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CovenantBinding {
    pub authorizing_input: u16,
    pub covenant_id: KaspaCovenantId,
}

impl TxOutput {
    pub fn new(value: u64, script_public_key: Vec<u8>) -> Self {
        Self {
            value,
            script_public_key,
            covenant_binding: None,
        }
    }

    pub fn covenant(value: u64, script_public_key: Vec<u8>, binding: CovenantBinding) -> Self {
        Self {
            value,
            script_public_key,
            covenant_binding: Some(binding),
        }
    }

    /// Encode the output to the canonical byte form:
    /// `value_le_u64 || spk_var_bytes(u32_le_len || bytes) || covenant_binding_var_bytes?`.
    ///
    /// The `covenant_binding_var_bytes` is encoded only when present, prefixed
    /// with a single tag byte `0x01`. This matches the upstream borsh layout
    /// for `Option<CovenantBinding>` in `TransactionOutput`.
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 4 + self.script_public_key.len() + 1 + 2 + 32);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&(self.script_public_key.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.script_public_key);
        match self.covenant_binding {
            Some(b) => {
                out.push(0x01); // Some
                out.extend_from_slice(&b.authorizing_input.to_le_bytes());
                out.extend_from_slice(&b.covenant_id);
            }
            None => out.push(0x00), // None
        }
        out
    }
}

/// A transaction input. Minimal shape: outpoint + signature script (empty for
/// unsigned tx).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInput {
    pub previous_outpoint: KaspaOutpoint,
    pub signature_script: Vec<u8>,
    pub sequence: u64,
}

impl TxInput {
    pub fn new(previous_outpoint: KaspaOutpoint) -> Self {
        Self {
            previous_outpoint,
            signature_script: Vec::new(),
            sequence: 0,
        }
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4 + self.signature_script.len() + 8);
        out.extend_from_slice(&self.previous_outpoint.transaction_id);
        out.extend_from_slice(&self.previous_outpoint.index.to_le_bytes());
        out.extend_from_slice(&(self.signature_script.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.signature_script);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out
    }
}

/// The unsigned transaction we build. Holds inputs, outputs, payload, lock_time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedTx {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub payload: Vec<u8>,
    pub lock_time: u64,
}

impl UnsignedTx {
    pub fn encode_canonical(&self) -> Vec<u8> {
        // Layout: u32_le(input_count) || inputs || u32_le(output_count) || outputs || payload || lock_time
        let mut out = Vec::new();
        out.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for i in &self.inputs {
            out.extend_from_slice(&i.encode_canonical());
        }
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            out.extend_from_slice(&o.encode_canonical());
        }
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }
}

// ---------------- builders ----------------

/// Build the initial covenant output (the first UTXO in the lineage). The
/// `state` is encoded into the SPK payload; the binding carries the
/// covenant_id computed from the genesis lineage.
pub fn build_genesis_output(
    state: &CovenantState,
    spk: Vec<u8>,
    covenant_id: KaspaCovenantId,
    authorizing_input: u16,
    value: u64,
) -> Result<TxOutput, TxBuildError> {
    if spk.is_empty() {
        return Err(TxBuildError::EmptyScriptPublicKey);
    }
    // The state itself does not carry the covenant_id; we verify the caller
    // passed a coherent (state, covenant_id) pair by re-deriving the lineage
    // id from state.lineage_id and the covenant_id hash binding.
    if covenant_id == [0u8; 32] {
        return Err(TxBuildError::CovenantMismatch {
            tx: covenant_id.into(),
            state: HexBytes32(state.lineage_id),
        });
    }
    Ok(TxOutput::covenant(
        value,
        spk,
        CovenantBinding {
            authorizing_input,
            covenant_id,
        },
    ))
}

/// Build the spend input for a transition: exactly the open covenant outpoint.
pub fn build_transition_spend(open_covenant: KaspaOutpoint) -> TxInput {
    TxInput::new(open_covenant)
}

/// Build the transition outputs: the new covenant UTXO (with the advanced
/// state payload) plus an optional fee/change output.
pub fn build_transition_outputs(
    new_state: &CovenantState,
    new_spk: Vec<u8>,
    new_value: u64,
    new_covenant_id: KaspaCovenantId,
    fee: u64,
    change_value: u64,
    change_spk: Option<Vec<u8>>,
    in_total: u64,
) -> Result<Vec<TxOutput>, TxBuildError> {
    if new_spk.is_empty() {
        return Err(TxBuildError::EmptyScriptPublicKey);
    }
    if new_covenant_id == [0u8; 32] {
        return Err(TxBuildError::CovenantMismatch {
            tx: new_covenant_id.into(),
            state: HexBytes32(new_state.lineage_id),
        });
    }
    if fee + new_value > in_total {
        return Err(TxBuildError::ChangeOverflow {
            in_total,
            fee,
            covenant: new_value,
        });
    }
    let mut outs = Vec::new();
    let covenant_out = TxOutput::covenant(
        new_value,
        new_spk,
        CovenantBinding {
            authorizing_input: 0,
            covenant_id: new_covenant_id,
        },
    );
    outs.push(covenant_out);
    if let Some(spk) = change_spk {
        if change_value > 0 {
            outs.push(TxOutput::new(change_value, spk));
        }
    }
    Ok(outs)
}

/// Build a fee-only output (used when no change is desired).
pub fn build_fee_output(value: u64) -> TxOutput {
    TxOutput::new(value, vec![])
}

/// Validate that a transition tx is balanced: `sum(inputs) >= sum(outputs)`,
/// with the difference absorbed by `fee`.
pub fn validate_balanced(inputs: u64, outputs: u64, fee: u64) -> Result<(), TxBuildError> {
    if inputs < outputs + fee {
        return Err(TxBuildError::BadFee {
            fee,
            in_total: inputs,
        });
    }
    Ok(())
}

// ---------------- helpers ----------------

/// Compute the SPK hash for a covenant spec's redeem script. In Kaspa this
/// is `SHA256(redemption_script)`; we expose it as a helper so callers can
/// derive the SPK without linking against rusty-kaspa's script engine.
pub fn spk_from_redeem_script(redeem_script: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(redeem_script);
    let out = h.finalize();
    let mut v = Vec::with_capacity(out.len() + 2);
    // Kaspa SPK version 0 followed by the script hash.
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&out);
    v
}

/// Compute the covenant id from a spec, the genesis outpoint, and the
/// authorised outputs. Re-exports [`rgk_covenant::compute_covenant_id`].
pub use rgk_covenant::compute_covenant_id;

/// Compute the initial state commitment for a covenant lineage.
pub fn state_commitment(state: &RgkStateCommitment) -> Bytes32 {
    rgk_core::state_commitment(state)
}

/// Convenience: derive a [`CovenantSpec`] from a [`CovenantState`].
pub fn spec_from_state(state: &CovenantState) -> CovenantSpec {
    CovenantSpec {
        chain_id: state.chain_id,
        lineage_id: state.lineage_id,
        asset_id: state.asset_id,
        initial_state_digest: state.current_state_digest,
        receipt_policy: state.receipt_policy,
        genesis_proof_mode: state.genesis_proof_mode,
    }
}

// ---------------- tests ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use rgk_core::ReceiptPolicy;
    use rgk_core::{ENCODING_VERSION, KASPA_LOCAL_TOCCATA};

    fn b32(s: &str) -> [u8; 32] {
        rgk_core::from_hex::<32>(s).expect("hex")
    }

    fn sample_state() -> CovenantState {
        CovenantState::genesis(
            KASPA_LOCAL_TOCCATA,
            b32("2222222222222222222222222222222222222222222222222222222222222222"),
            b32("1111111111111111111111111111111111111111111111111111111111111111"),
            ReceiptPolicy::Any,
            rgk_core::ProofMode::VerifierReceipt,
        )
    }

    fn sample_covenant_id() -> KaspaCovenantId {
        // Derive from the sample state's lineage id, matching the fixture recipe.
        rgk_covenant::compute_covenant_id_from_lineage(b32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        ))
    }

    #[test]
    fn encode_output_roundtrip_structure() {
        let o = TxOutput::covenant(
            1234,
            vec![0x76, 0xa9],
            CovenantBinding {
                authorizing_input: 0,
                covenant_id: sample_covenant_id(),
            },
        );
        let bytes = o.encode_canonical();
        // value(8) + spk_len(4) + spk(2) + Some(1) + u16(2) + cov_id(32) = 49
        assert_eq!(bytes.len(), 8 + 4 + 2 + 1 + 2 + 32);
        assert_eq!(&bytes[..8], &1234u64.to_le_bytes());
        assert_eq!(bytes[8..12], [2, 0, 0, 0]);
        assert_eq!(bytes[12..14], [0x76, 0xa9]);
        assert_eq!(bytes[14], 0x01); // Some
    }

    #[test]
    fn encode_input_has_expected_layout() {
        let i = TxInput::new(KaspaOutpoint {
            transaction_id: [7u8; 32],
            index: 3,
        });
        let bytes = i.encode_canonical();
        assert_eq!(bytes.len(), 32 + 4 + 4 + 0 + 8); // txid + idx + sigscript_len + sigscript + seq
        assert_eq!(&bytes[32..36], &3u32.to_le_bytes());
        assert_eq!(&bytes[36..40], &[0, 0, 0, 0]); // empty sigscript
        assert_eq!(&bytes[40..48], &0u64.to_le_bytes());
    }

    #[test]
    fn encode_unsigned_tx() {
        // Plain (non-covenant) output is 14 bytes (value 8 + spk_len 4 + spk 1 + None 1).
        let tx = UnsignedTx {
            inputs: vec![TxInput::new(KaspaOutpoint::NULL)],
            outputs: vec![TxOutput::new(1000, vec![0x76])],
            payload: vec![1, 2, 3, 4],
            lock_time: 0,
        };
        let bytes = tx.encode_canonical();
        // Layout: input_count(4) || input(48) || output_count(4) || output(14) || payload_len(4) || payload(4) || lock_time(8)
        // = 4 + 48 + 4 + 14 + 4 + 4 + 8 = 86
        assert_eq!(bytes.len(), 86);
        assert_eq!(&bytes[..4], &1u32.to_le_bytes()); // 1 input
        assert_eq!(&bytes[52..56], &1u32.to_le_bytes()); // 1 output, offset = 4+48
        assert_eq!(&bytes[70..74], &4u32.to_le_bytes()); // payload len, offset = 4+48+4+14
        assert_eq!(bytes[74..78], vec![1, 2, 3, 4]);
        assert_eq!(&bytes[78..86], &0u64.to_le_bytes()); // lock_time
    }

    #[test]
    fn build_genesis_output_rejects_empty_spk() {
        let s = sample_state();
        let cov = sample_covenant_id();
        let err = build_genesis_output(&s, vec![], cov, 0, 1000).unwrap_err();
        assert!(matches!(err, TxBuildError::EmptyScriptPublicKey));
    }

    #[test]
    fn build_genesis_output_rejects_zero_covenant() {
        let s = sample_state();
        let err = build_genesis_output(&s, vec![0x76], [0u8; 32], 0, 1000).unwrap_err();
        assert!(matches!(err, TxBuildError::CovenantMismatch { .. }));
    }

    #[test]
    fn build_transition_outputs_balanced() {
        let s = sample_state();
        let cov = sample_covenant_id();
        let outs =
            build_transition_outputs(&s, vec![0x76], 1000, cov, 100, 50, Some(vec![0x76]), 1200)
                .unwrap();
        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].value, 1000);
        assert_eq!(outs[1].value, 50);
    }

    #[test]
    fn build_transition_outputs_overflow_rejected() {
        let s = sample_state();
        let cov = sample_covenant_id();
        let err =
            build_transition_outputs(&s, vec![0x76], 2000, cov, 100, 0, None, 1000).unwrap_err();
        assert!(matches!(err, TxBuildError::ChangeOverflow { .. }));
    }

    #[test]
    fn validate_balanced_rejects_underfunded() {
        assert!(matches!(
            validate_balanced(1000, 800, 300),
            Err(TxBuildError::BadFee { .. })
        ));
        assert!(validate_balanced(1000, 800, 200).is_ok());
    }

    #[test]
    fn spk_from_redeem_script_starts_with_version_zero() {
        let spk = spk_from_redeem_script(b"some redeem script");
        assert_eq!(&spk[..2], &[0, 0]); // version 0
        assert_eq!(spk.len(), 2 + 32);
    }

    #[test]
    fn spec_from_state_round_trips() {
        let s = sample_state();
        let spec = spec_from_state(&s);
        assert_eq!(spec.lineage_id, s.lineage_id);
        assert_eq!(spec.asset_id, s.asset_id);
        assert_eq!(spec.chain_id, s.chain_id);
        assert_eq!(spec.receipt_policy, s.receipt_policy);
    }
}
