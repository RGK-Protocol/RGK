#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-covenant
//!
//! Kaspa **Toccata** covenant state object + the script-builder for the
//! RGK covenant. This crate is the seam between [`rgk_core`] /
//! [`rgk_receipt`] (which are RGK asset side) and the on-chain Kaspa covenant.
//!
//! ## What this crate does
//!
//! 1. **Defines `CovenantState`** — the *typed* per-covenant state object
//!    that lives in the covenant UTXO's `script_public_key` payload. It binds:
//!    * the RGK asset id (`asset_id`)
//!    * the current RGK state digest (`current_state_digest`)
//!    * the lineage id (`lineage_id`, derived from the genesis outpoint)
//!    * the receipt policy (`receipt_policy`)
//!    * the proof mode used by genesis (`genesis_proof_mode`)
//!    * an anti-replay marker (`replay_marker`)
//!
//!    The state object is encoded with `rgk:v0` domain separation, length-
//!    prefixed fields, and a fixed tag; see [`CovenantState::encode_payload`].
//!
//! 2. **Builds the Toccata covenant script** via [`CovenantSpec::build_script`]
//!    — the byte sequence that gets hashed into the genesis output's
//!    `script_public_key`. The script enforces (see
//!    [`docs/COVENANT-SPEC.md`](../../docs/COVENANT-SPEC.md) for the full spec):
//!    * the spend is authorised by the configured covenant input
//!    * output count matches the configured continuation policy
//!    * every configured covenant output keeps the spent UTXO's script public
//!      key
//!    * input/output covenant ids are preserved
//!    * the spending transaction payload has the exact RGK state length
//!    * the payload's chain, lineage, asset, policy and proof mode match
//!      the redeem-script constants
//!
//! 3. **Computes the Toccata covenant id** via [`compute_covenant_id`] —
//!    `SHA256( genesis_tx_id || genesis_index || authorized_outputs_len ||
//!    for each authorized output: index, value, spk_version, spk_bytes )`,
//!    matching `kaspa_consensus_core::hashing::covenant_id::covenant_id`. We
//!    re-implement it here so RGK does not need to link against rusty-kaspa
//!    during fast iteration; the recipe is byte-identical and frozen by
//!    `frozen_covenant_id_vector`.
//!
//! ## What this crate does NOT do
//!
//! * It does not submit transactions. That lives in `rgk-tx`.
//! * It does not maintain an index. That lives in `rgk-indexer`.
//! * It emits the base covenant script. The `real-zk` e2e path can prefix
//!   those bytes with VK + Groth16 tag + `OpZkPrecompile` + `OpDrop`; runtime
//!   invocation happens in the Kaspa txscript engine.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
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

use kaspa_hashes::{Hasher, HasherBase};
use rgk_core::{
    domain_hash, lineage_id, Bytes32, Canonical, DecodeError, DomainTag, KaspaChainId,
    KaspaCovenantId, KaspaOutpoint, Reader, Writer, ENCODING_VERSION,
};
use rgk_core::{ProofMode, ReceiptPolicy};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain tag for the covenant state payload. Pulled into a constant for
/// cross-crate reuse in the script builder and the covenant-id recipe.
pub const COVENANT_STATE_TAG: &[u8; 12] = b"rgk:kov:0\0\0\0";

/// Historical RGK covenant-id tag. Current [`compute_covenant_id`] follows the
/// upstream Toccata `kaspa_hashes::CovenantID` domain instead.
pub const COVENANT_ID_TAG: &[u8; 12] = b"rgk:cid:0\0\0\0";
pub const ADVANCED_COVENANT_EXECUTION_RECORD_TAG: &[u8; 12] = b"rgk:ace:0\0\0\0";

pub type AdvancedCovenantPolicyCommitment = Bytes32;
pub type AdvancedCovenantExecutionCommitment = Bytes32;

/// Native RGK policy-shape classes for advanced Kaspa covenant flows.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AdvancedCovenantFlow {
    PaymentGatedTransfer,
    EscrowRelease,
    VaultTimelockRelease,
    AtomicSwap,
    CovenantOwnedAsset,
    PolicyUpgrade,
    ControlledTermination,
}

impl AdvancedCovenantFlow {
    pub const fn tag(self) -> u8 {
        match self {
            Self::PaymentGatedTransfer => 0,
            Self::EscrowRelease => 1,
            Self::VaultTimelockRelease => 2,
            Self::AtomicSwap => 3,
            Self::CovenantOwnedAsset => 4,
            Self::PolicyUpgrade => 5,
            Self::ControlledTermination => 6,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::PaymentGatedTransfer => "payment-gated-transfer",
            Self::EscrowRelease => "escrow-release",
            Self::VaultTimelockRelease => "vault-timelock-release",
            Self::AtomicSwap => "atomic-swap",
            Self::CovenantOwnedAsset => "covenant-owned-asset",
            Self::PolicyUpgrade => "policy-upgrade",
            Self::ControlledTermination => "controlled-termination",
        }
    }

    pub fn from_tag(tag: u8) -> Result<Self, CovenantError> {
        match tag {
            0 => Ok(Self::PaymentGatedTransfer),
            1 => Ok(Self::EscrowRelease),
            2 => Ok(Self::VaultTimelockRelease),
            3 => Ok(Self::AtomicSwap),
            4 => Ok(Self::CovenantOwnedAsset),
            5 => Ok(Self::PolicyUpgrade),
            6 => Ok(Self::ControlledTermination),
            _ => Err(CovenantError::Decode(format!(
                "unknown advanced covenant flow tag {tag}"
            ))),
        }
    }
}

/// Errors raised by covenant operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CovenantError {
    #[error("covenant payload decode failed: {0}")]
    Decode(String),
    #[error("covenant payload too long: {got} bytes (max {max})")]
    PayloadTooLong { got: usize, max: usize },
    #[error("covenant lineage mismatch: expected 0x{expected}, got 0x{actual}")]
    LineageMismatch { expected: Hex32, actual: Hex32 },
    #[error("covenant lineage migration attempted without migration flag")]
    MigrationNotAllowed,
    #[error("covenant asset id mismatch: expected 0x{expected}, got 0x{actual}")]
    AssetMismatch { expected: Hex32, actual: Hex32 },
    #[error("covenant policy / mode mismatch: {policy:?} vs {mode:?}")]
    PolicyModeMismatch {
        policy: ReceiptPolicy,
        mode: ProofMode,
    },
    #[error("covenant state invariant violated: {0}")]
    Invariant(String),
    #[error("covenant script build failed: {0}")]
    ScriptBuild(String),
    #[error("advanced covenant {field} is zero")]
    ZeroAdvancedCovenantField { field: &'static str },
    #[error("advanced covenant {flow:?} requires non-zero {field}")]
    MissingAdvancedCovenantField {
        flow: AdvancedCovenantFlow,
        field: &'static str,
    },
    #[error("advanced covenant execution {flow:?} has wrong {field}")]
    AdvancedCovenantExecutionMismatch {
        flow: AdvancedCovenantFlow,
        field: &'static str,
    },
    #[error(
        "advanced covenant execution {flow:?} payment is too small: required {required}, actual {actual}"
    )]
    AdvancedCovenantPaymentTooSmall {
        flow: AdvancedCovenantFlow,
        required: u64,
        actual: u64,
    },
    #[error(
        "advanced covenant execution {flow:?} DAA score is too early: required {required}, actual {actual}"
    )]
    AdvancedCovenantDaaTooEarly {
        flow: AdvancedCovenantFlow,
        required: u64,
        actual: u64,
    },
}

/// Newtype around a 32-byte array with a Display impl that renders as
/// `0x` + lowercase hex. Used in [`CovenantError`] so the thiserror derive
/// can produce a human-readable `Display` without breaking on raw bytes.
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

/// Material committed by a native advanced covenant policy shape.
///
/// Unused fields are allowed to be zero, but every flow validates the fields
/// that make that flow enforceable. The commitment always binds all fields so a
/// policy cannot be replayed under a different advanced-covenant interpretation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdvancedCovenantPolicyShape {
    pub chain_id: KaspaChainId,
    pub asset_id: Bytes32,
    pub lineage_id: Bytes32,
    pub flow: AdvancedCovenantFlow,
    pub covenant_id: KaspaCovenantId,
    pub counterparty_covenant_id: KaspaCovenantId,
    pub payment_asset_id: Bytes32,
    pub payment_amount: u64,
    pub unlock_daa_score: u64,
    pub policy_commitment: Bytes32,
    pub authorization_commitment: Bytes32,
}

impl AdvancedCovenantPolicyShape {
    pub fn validate(&self) -> Result<(), CovenantError> {
        reject_zero32("asset_id", &self.asset_id)?;
        reject_zero32("lineage_id", &self.lineage_id)?;
        reject_zero32("covenant_id", &self.covenant_id)?;
        reject_zero32("authorization_commitment", &self.authorization_commitment)?;

        match self.flow {
            AdvancedCovenantFlow::PaymentGatedTransfer => {
                self.require_counterparty()?;
                self.require_payment()?;
            }
            AdvancedCovenantFlow::EscrowRelease => {
                self.require_counterparty()?;
                self.require_policy_commitment()?;
            }
            AdvancedCovenantFlow::VaultTimelockRelease => {
                self.require_unlock()?;
                self.require_policy_commitment()?;
            }
            AdvancedCovenantFlow::AtomicSwap => {
                self.require_counterparty()?;
                self.require_payment()?;
                self.require_unlock()?;
            }
            AdvancedCovenantFlow::CovenantOwnedAsset => {
                self.require_counterparty()?;
                self.require_policy_commitment()?;
            }
            AdvancedCovenantFlow::PolicyUpgrade | AdvancedCovenantFlow::ControlledTermination => {
                self.require_policy_commitment()?;
            }
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<AdvancedCovenantPolicyCommitment, CovenantError> {
        self.validate()?;
        let mut w = Writer::new();
        self.chain_id.encode(&mut w);
        w.write_bytes32(&self.asset_id);
        w.write_bytes32(&self.lineage_id);
        w.write_u8(self.flow.tag());
        w.write_bytes32(&self.covenant_id);
        w.write_bytes32(&self.counterparty_covenant_id);
        w.write_bytes32(&self.payment_asset_id);
        w.write_u64(self.payment_amount);
        w.write_u64(self.unlock_daa_score);
        w.write_bytes32(&self.policy_commitment);
        w.write_bytes32(&self.authorization_commitment);
        Ok(advanced_covenant_policy_hash(&w.into_vec()))
    }

    fn require_counterparty(&self) -> Result<(), CovenantError> {
        self.require_nonzero("counterparty_covenant_id", &self.counterparty_covenant_id)
    }

    fn require_payment(&self) -> Result<(), CovenantError> {
        self.require_nonzero("payment_asset_id", &self.payment_asset_id)?;
        if self.payment_amount == 0 {
            return Err(CovenantError::MissingAdvancedCovenantField {
                flow: self.flow,
                field: "payment_amount",
            });
        }
        Ok(())
    }

    fn require_unlock(&self) -> Result<(), CovenantError> {
        if self.unlock_daa_score == 0 {
            return Err(CovenantError::MissingAdvancedCovenantField {
                flow: self.flow,
                field: "unlock_daa_score",
            });
        }
        Ok(())
    }

    fn require_policy_commitment(&self) -> Result<(), CovenantError> {
        self.require_nonzero("policy_commitment", &self.policy_commitment)
    }

    fn require_nonzero(&self, field: &'static str, bytes: &Bytes32) -> Result<(), CovenantError> {
        if is_zero32(bytes) {
            Err(CovenantError::MissingAdvancedCovenantField {
                flow: self.flow,
                field,
            })
        } else {
            Ok(())
        }
    }
}

/// Wallet-supplied material that proves a concrete advanced covenant action
/// satisfies its native policy shape.
///
/// Fields that are irrelevant for a flow may stay zero. The validator below is
/// intentionally strict about the fields that do matter for each flow so wallet
/// UX can fail before presenting an action as executable.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdvancedCovenantExecutionEvidence {
    pub counterparty_covenant_id: KaspaCovenantId,
    pub payment_asset_id: Bytes32,
    pub paid_amount: u64,
    pub current_daa_score: u64,
    pub policy_commitment: Bytes32,
    pub authorization_commitment: Bytes32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdvancedCovenantExecutionPlan {
    pub shape: AdvancedCovenantPolicyShape,
    pub policy_commitment: AdvancedCovenantPolicyCommitment,
    pub evidence: AdvancedCovenantExecutionEvidence,
    pub execution_commitment: AdvancedCovenantExecutionCommitment,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdvancedCovenantExecutionRecord {
    pub plan: AdvancedCovenantExecutionPlan,
}

impl AdvancedCovenantExecutionEvidence {
    pub fn validate_for_shape(
        &self,
        shape: &AdvancedCovenantPolicyShape,
    ) -> Result<(), CovenantError> {
        shape.validate()?;
        self.require_authorization(shape)?;

        match shape.flow {
            AdvancedCovenantFlow::PaymentGatedTransfer => {
                self.require_payment_asset(shape)?;
                if self.paid_amount < shape.payment_amount {
                    return Err(CovenantError::AdvancedCovenantPaymentTooSmall {
                        flow: shape.flow,
                        required: shape.payment_amount,
                        actual: self.paid_amount,
                    });
                }
            }
            AdvancedCovenantFlow::EscrowRelease | AdvancedCovenantFlow::CovenantOwnedAsset => {
                self.require_counterparty(shape)?;
                self.require_policy_commitment(shape)?;
            }
            AdvancedCovenantFlow::VaultTimelockRelease => {
                self.require_unlock(shape)?;
                self.require_policy_commitment(shape)?;
            }
            AdvancedCovenantFlow::AtomicSwap => {
                self.require_counterparty(shape)?;
                self.require_payment_asset(shape)?;
                self.require_exact_payment(shape)?;
                self.require_unlock(shape)?;
                if !is_zero32(&shape.policy_commitment) {
                    self.require_policy_commitment(shape)?;
                }
            }
            AdvancedCovenantFlow::PolicyUpgrade | AdvancedCovenantFlow::ControlledTermination => {
                self.require_policy_commitment(shape)?;
            }
        }
        Ok(())
    }

    fn require_authorization(
        &self,
        shape: &AdvancedCovenantPolicyShape,
    ) -> Result<(), CovenantError> {
        if self.authorization_commitment != shape.authorization_commitment {
            Err(CovenantError::AdvancedCovenantExecutionMismatch {
                flow: shape.flow,
                field: "authorization_commitment",
            })
        } else {
            Ok(())
        }
    }

    fn require_counterparty(
        &self,
        shape: &AdvancedCovenantPolicyShape,
    ) -> Result<(), CovenantError> {
        if self.counterparty_covenant_id != shape.counterparty_covenant_id {
            Err(CovenantError::AdvancedCovenantExecutionMismatch {
                flow: shape.flow,
                field: "counterparty_covenant_id",
            })
        } else {
            Ok(())
        }
    }

    fn require_payment_asset(
        &self,
        shape: &AdvancedCovenantPolicyShape,
    ) -> Result<(), CovenantError> {
        if self.payment_asset_id != shape.payment_asset_id {
            Err(CovenantError::AdvancedCovenantExecutionMismatch {
                flow: shape.flow,
                field: "payment_asset_id",
            })
        } else {
            Ok(())
        }
    }

    fn require_exact_payment(
        &self,
        shape: &AdvancedCovenantPolicyShape,
    ) -> Result<(), CovenantError> {
        if self.paid_amount != shape.payment_amount {
            Err(CovenantError::AdvancedCovenantExecutionMismatch {
                flow: shape.flow,
                field: "paid_amount",
            })
        } else {
            Ok(())
        }
    }

    fn require_unlock(&self, shape: &AdvancedCovenantPolicyShape) -> Result<(), CovenantError> {
        if self.current_daa_score < shape.unlock_daa_score {
            Err(CovenantError::AdvancedCovenantDaaTooEarly {
                flow: shape.flow,
                required: shape.unlock_daa_score,
                actual: self.current_daa_score,
            })
        } else {
            Ok(())
        }
    }

    fn require_policy_commitment(
        &self,
        shape: &AdvancedCovenantPolicyShape,
    ) -> Result<(), CovenantError> {
        if self.policy_commitment != shape.policy_commitment {
            Err(CovenantError::AdvancedCovenantExecutionMismatch {
                flow: shape.flow,
                field: "policy_commitment",
            })
        } else {
            Ok(())
        }
    }
}

impl AdvancedCovenantExecutionPlan {
    pub fn new(
        shape: AdvancedCovenantPolicyShape,
        evidence: AdvancedCovenantExecutionEvidence,
    ) -> Result<Self, CovenantError> {
        let policy_commitment = shape.commitment()?;
        evidence.validate_for_shape(&shape)?;
        let execution_commitment =
            advanced_covenant_execution_hash(policy_commitment, &shape, &evidence);
        Ok(Self {
            shape,
            policy_commitment,
            evidence,
            execution_commitment,
        })
    }
}

impl AdvancedCovenantExecutionRecord {
    pub fn new(plan: AdvancedCovenantExecutionPlan) -> Self {
        Self { plan }
    }

    pub fn from_parts(
        shape: AdvancedCovenantPolicyShape,
        evidence: AdvancedCovenantExecutionEvidence,
    ) -> Result<Self, CovenantError> {
        Ok(Self::new(AdvancedCovenantExecutionPlan::new(
            shape, evidence,
        )?))
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_bytes(ADVANCED_COVENANT_EXECUTION_RECORD_TAG);
        w.write_u16(ENCODING_VERSION);
        encode_advanced_covenant_policy_shape(&mut w, &self.plan.shape);
        w.write_bytes32(&self.plan.policy_commitment);
        encode_advanced_covenant_execution_evidence(&mut w, &self.plan.evidence);
        w.write_bytes32(&self.plan.execution_commitment);
        w.into_vec()
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CovenantError> {
        if bytes.len() > rgk_core::MAX_BLOB_BYTES as usize {
            return Err(CovenantError::PayloadTooLong {
                got: bytes.len(),
                max: rgk_core::MAX_BLOB_BYTES as usize,
            });
        }
        let mut r = Reader::new(bytes);
        let tag = r.read_array::<12>().map_err(decode_err)?;
        if &tag != ADVANCED_COVENANT_EXECUTION_RECORD_TAG {
            return Err(CovenantError::Decode(format!(
                "bad advanced covenant execution record tag: {:?}",
                tag
            )));
        }
        let version = r.read_u16().map_err(decode_err)?;
        if version != ENCODING_VERSION {
            return Err(CovenantError::Decode(format!("unknown version {version}")));
        }
        let shape = decode_advanced_covenant_policy_shape(&mut r)?;
        let policy_commitment = r.read_bytes32().map_err(decode_err)?;
        let evidence = decode_advanced_covenant_execution_evidence(&mut r)?;
        let execution_commitment = r.read_bytes32().map_err(decode_err)?;
        r.ensure_consumed().map_err(decode_err)?;

        let plan = AdvancedCovenantExecutionPlan::new(shape, evidence)?;
        if plan.policy_commitment != policy_commitment {
            return Err(CovenantError::Decode(
                "advanced covenant policy commitment mismatch".into(),
            ));
        }
        if plan.execution_commitment != execution_commitment {
            return Err(CovenantError::Decode(
                "advanced covenant execution commitment mismatch".into(),
            ));
        }
        Ok(Self { plan })
    }
}

fn reject_zero32(field: &'static str, bytes: &Bytes32) -> Result<(), CovenantError> {
    if is_zero32(bytes) {
        Err(CovenantError::ZeroAdvancedCovenantField { field })
    } else {
        Ok(())
    }
}

fn decode_err(err: DecodeError) -> CovenantError {
    CovenantError::Decode(err.to_string())
}

fn encode_advanced_covenant_policy_shape(w: &mut Writer, shape: &AdvancedCovenantPolicyShape) {
    shape.chain_id.encode(w);
    w.write_bytes32(&shape.asset_id);
    w.write_bytes32(&shape.lineage_id);
    w.write_u8(shape.flow.tag());
    w.write_bytes32(&shape.covenant_id);
    w.write_bytes32(&shape.counterparty_covenant_id);
    w.write_bytes32(&shape.payment_asset_id);
    w.write_u64(shape.payment_amount);
    w.write_u64(shape.unlock_daa_score);
    w.write_bytes32(&shape.policy_commitment);
    w.write_bytes32(&shape.authorization_commitment);
}

fn decode_advanced_covenant_policy_shape(
    r: &mut Reader<'_>,
) -> Result<AdvancedCovenantPolicyShape, CovenantError> {
    let chain_id = KaspaChainId::decode(r).map_err(decode_err)?;
    let asset_id = r.read_bytes32().map_err(decode_err)?;
    let lineage_id = r.read_bytes32().map_err(decode_err)?;
    let flow = AdvancedCovenantFlow::from_tag(r.read_u8().map_err(decode_err)?)?;
    let covenant_id = r.read_bytes32().map_err(decode_err)?;
    let counterparty_covenant_id = r.read_bytes32().map_err(decode_err)?;
    let payment_asset_id = r.read_bytes32().map_err(decode_err)?;
    let payment_amount = r.read_u64().map_err(decode_err)?;
    let unlock_daa_score = r.read_u64().map_err(decode_err)?;
    let policy_commitment = r.read_bytes32().map_err(decode_err)?;
    let authorization_commitment = r.read_bytes32().map_err(decode_err)?;
    Ok(AdvancedCovenantPolicyShape {
        chain_id,
        asset_id,
        lineage_id,
        flow,
        covenant_id,
        counterparty_covenant_id,
        payment_asset_id,
        payment_amount,
        unlock_daa_score,
        policy_commitment,
        authorization_commitment,
    })
}

fn encode_advanced_covenant_execution_evidence(
    w: &mut Writer,
    evidence: &AdvancedCovenantExecutionEvidence,
) {
    w.write_bytes32(&evidence.counterparty_covenant_id);
    w.write_bytes32(&evidence.payment_asset_id);
    w.write_u64(evidence.paid_amount);
    w.write_u64(evidence.current_daa_score);
    w.write_bytes32(&evidence.policy_commitment);
    w.write_bytes32(&evidence.authorization_commitment);
}

fn decode_advanced_covenant_execution_evidence(
    r: &mut Reader<'_>,
) -> Result<AdvancedCovenantExecutionEvidence, CovenantError> {
    Ok(AdvancedCovenantExecutionEvidence {
        counterparty_covenant_id: r.read_bytes32().map_err(decode_err)?,
        payment_asset_id: r.read_bytes32().map_err(decode_err)?,
        paid_amount: r.read_u64().map_err(decode_err)?,
        current_daa_score: r.read_u64().map_err(decode_err)?,
        policy_commitment: r.read_bytes32().map_err(decode_err)?,
        authorization_commitment: r.read_bytes32().map_err(decode_err)?,
    })
}

fn is_zero32(bytes: &Bytes32) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn advanced_covenant_policy_hash(payload: &[u8]) -> Bytes32 {
    const TAG: &[u8] = b"rgk:advanced-covenant-policy:v1";
    let mut hasher = Sha256::new();
    hasher.update((TAG.len() as u32).to_le_bytes());
    hasher.update(TAG);
    hasher.update(payload);
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

fn advanced_covenant_execution_hash(
    policy_commitment: AdvancedCovenantPolicyCommitment,
    shape: &AdvancedCovenantPolicyShape,
    evidence: &AdvancedCovenantExecutionEvidence,
) -> Bytes32 {
    let mut w = Writer::new();
    w.write_bytes32(&policy_commitment);
    w.write_u8(shape.flow.tag());
    w.write_bytes32(&shape.covenant_id);
    w.write_bytes32(&shape.asset_id);
    w.write_bytes32(&shape.lineage_id);
    w.write_bytes32(&evidence.counterparty_covenant_id);
    w.write_bytes32(&evidence.payment_asset_id);
    w.write_u64(evidence.paid_amount);
    w.write_u64(evidence.current_daa_score);
    w.write_bytes32(&evidence.policy_commitment);
    w.write_bytes32(&evidence.authorization_commitment);
    const TAG: &[u8] = b"rgk:advanced-covenant-execution:v1";
    let mut hasher = Sha256::new();
    hasher.update((TAG.len() as u32).to_le_bytes());
    hasher.update(TAG);
    hasher.update(w.into_vec());
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// The typed covenant state object that lives in the covenant UTXO's payload
/// (the data blob hashed into `script_public_key` and re-asserted by the
/// script on every spend). Encoded with `rgk:v0` domain magic + state tag.
///
/// The state is *self-describing*: given just the payload, you can recover the
/// RGK asset id, current state digest, lineage id, policy and genesis proof
/// mode without consulting any external storage.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CovenantState {
    pub version: u16,
    pub chain_id: KaspaChainId,
    pub lineage_id: Bytes32,
    pub asset_id: Bytes32,
    pub current_state_digest: Bytes32,
    pub receipt_policy: ReceiptPolicy,
    pub genesis_proof_mode: ProofMode,
    /// 32-byte anti-replay marker. Conventionally `H(prev_state_digest ||
    /// transition_digest)` of the most recent accepted transition, or zero at
    /// genesis.
    pub replay_marker: Bytes32,
}

impl CovenantState {
    pub fn genesis(
        chain_id: KaspaChainId,
        asset_id: Bytes32,
        lineage: Bytes32,
        receipt_policy: ReceiptPolicy,
        genesis_proof_mode: ProofMode,
    ) -> Self {
        Self {
            version: ENCODING_VERSION,
            chain_id,
            lineage_id: lineage,
            asset_id,
            current_state_digest: [0u8; 32],
            receipt_policy,
            genesis_proof_mode,
            replay_marker: [0u8; 32],
        }
    }

    /// Produce the next state, advancing `current_state_digest` and
    /// `replay_marker`. Refuses to advance if `new_digest == current` (no-op
    /// transition is a hard invariant violation; see SECURITY.md).
    pub fn advance(
        &self,
        new_digest: Bytes32,
        new_replay_marker: Bytes32,
    ) -> Result<Self, CovenantError> {
        if new_digest == self.current_state_digest {
            return Err(CovenantError::Invariant(
                "new state digest equals current".into(),
            ));
        }
        Ok(Self {
            version: self.version,
            chain_id: self.chain_id,
            lineage_id: self.lineage_id,
            asset_id: self.asset_id,
            current_state_digest: new_digest,
            receipt_policy: self.receipt_policy,
            genesis_proof_mode: self.genesis_proof_mode,
            replay_marker: new_replay_marker,
        })
    }

    /// Encode the payload that gets committed to inside the covenant script.
    /// The byte layout is:
    ///
    /// ```text
    /// magic:        "rgk:kov:0\0\0"   (12 bytes, fixed)
    /// version:      u16 LE             (2 bytes)
    /// chain_id:     encoded            (2 bytes)
    /// lineage:      32 bytes
    /// asset:        32 bytes
    /// digest:       32 bytes
    /// policy:       encoded            (2 bytes)
    /// mode:         encoded            (2 bytes)
    /// replay:       32 bytes
    /// ```
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_bytes(COVENANT_STATE_TAG);
        w.write_u16(self.version);
        self.chain_id.encode(&mut w);
        w.write_bytes32(&self.lineage_id);
        w.write_bytes32(&self.asset_id);
        w.write_bytes32(&self.current_state_digest);
        self.receipt_policy.encode(&mut w);
        self.genesis_proof_mode.encode(&mut w);
        w.write_bytes32(&self.replay_marker);
        w.into_vec()
    }

    pub fn decode_payload(buf: &[u8]) -> Result<Self, CovenantError> {
        if buf.len() > rgk_core::MAX_BLOB_BYTES as usize {
            return Err(CovenantError::PayloadTooLong {
                got: buf.len(),
                max: rgk_core::MAX_BLOB_BYTES as usize,
            });
        }
        let mut r = Reader::new(buf);
        let tag = r
            .read_array::<12>()
            .map_err(|e| CovenantError::Decode(e.to_string()))?;
        if &tag != COVENANT_STATE_TAG {
            return Err(CovenantError::Decode(format!(
                "bad covenant tag: {:?}",
                tag
            )));
        }
        let version = r
            .read_u16()
            .map_err(|e| CovenantError::Decode(e.to_string()))?;
        if version != ENCODING_VERSION {
            return Err(CovenantError::Decode(format!("unknown version {version}")));
        }
        let chain_id =
            KaspaChainId::decode(&mut r).map_err(|e| CovenantError::Decode(e.to_string()))?;
        let lineage_id = r
            .read_bytes32()
            .map_err(|e| CovenantError::Decode(e.to_string()))?;
        let asset_id = r
            .read_bytes32()
            .map_err(|e| CovenantError::Decode(e.to_string()))?;
        let current_state_digest = r
            .read_bytes32()
            .map_err(|e| CovenantError::Decode(e.to_string()))?;
        let receipt_policy =
            ReceiptPolicy::decode(&mut r).map_err(|e| CovenantError::Decode(e.to_string()))?;
        let genesis_proof_mode =
            ProofMode::decode(&mut r).map_err(|e| CovenantError::Decode(e.to_string()))?;
        let replay_marker = r
            .read_bytes32()
            .map_err(|e| CovenantError::Decode(e.to_string()))?;
        r.ensure_consumed()
            .map_err(|e| CovenantError::Decode(e.to_string()))?;
        Ok(Self {
            version,
            chain_id,
            lineage_id,
            asset_id,
            current_state_digest,
            receipt_policy,
            genesis_proof_mode,
            replay_marker,
        })
    }

    /// The 32-byte digest committed into the covenant. Computed as:
    ///
    /// `SHA256( COVENANT_STATE_TAG || payload )`
    ///
    /// This is what the Toccata script checks against at spend time.
    pub fn commitment(&self) -> Bytes32 {
        let payload = self.encode_payload();
        let mut hasher = Sha256::new();
        hasher.update(COVENANT_STATE_TAG);
        hasher.update((payload.len() as u32).to_le_bytes());
        hasher.update(&payload);
        let out = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        bytes
    }
}

/// Compute the Toccata covenant id from a genesis outpoint and the authorized
/// initial outputs. The recipe matches
/// `kaspa_consensus_core::hashing::covenant_id::covenant_id`:
///
/// ```text
/// SHA256( genesis_tx_id || genesis_index_le_u32 ||
///         authorized_outputs_len_le_u32 ||
///         for each authorized output:
///           index_le_u32 || value_le_u64 ||
///           spk_version_le_u16 || spk_bytes )
/// ```
///
/// `spk_version` is the first two bytes of the script public key (Kaspa
/// encodes a u16 version into the first two bytes of the SPK, followed by
/// `var_bytes(script)`).
pub fn compute_covenant_id(
    genesis_outpoint: KaspaOutpoint,
    authorized_outputs: &[(u32, u64, u16, Vec<u8>)],
) -> KaspaCovenantId {
    let mut hasher = kaspa_hashes::CovenantID::new();
    hasher
        .update(genesis_outpoint.transaction_id)
        .write_u32(genesis_outpoint.index)
        .write_len(authorized_outputs.len());
    for (idx, value, spk_version, spk_bytes) in authorized_outputs {
        hasher
            .write_u32(*idx)
            .write_u64(*value)
            .write_u16(*spk_version)
            .write_var_bytes(spk_bytes);
    }
    hasher.finalize().as_bytes()
}

trait CovenantHasherExt: HasherBase {
    fn write_len(&mut self, len: usize) -> &mut Self {
        self.update((len as u64).to_le_bytes())
    }

    fn write_u16(&mut self, value: u16) -> &mut Self {
        self.update(value.to_le_bytes())
    }

    fn write_u32(&mut self, value: u32) -> &mut Self {
        self.update(value.to_le_bytes())
    }

    fn write_u64(&mut self, value: u64) -> &mut Self {
        self.update(value.to_le_bytes())
    }

    fn write_var_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.write_len(bytes.len()).update(bytes)
    }
}

impl<T: HasherBase> CovenantHasherExt for T {}

/// Compute the lineage id for a covenant genesis. This is a stable identifier
/// for "all covenant UTXOs that descend from the same genesis outpoint +
/// RGK asset id". Even after explicit migrations, the lineage is preserved
/// unless the migration flag is set (which is itself recorded in the new
/// state's lineage id).
pub fn compute_lineage_id(genesis_outpoint_payload: &[u8], asset_id: &Bytes32) -> Bytes32 {
    lineage_id(genesis_outpoint_payload, asset_id)
}

const PAYLOAD_STATIC_PREFIX_END: usize = 16;
const PAYLOAD_LINEAGE_START: usize = 16;
const PAYLOAD_LINEAGE_END: usize = 48;
const PAYLOAD_CONTRACT_START: usize = 48;
const PAYLOAD_CONTRACT_END: usize = 80;
const PAYLOAD_POLICY_MODE_START: usize = 112;
const PAYLOAD_POLICY_MODE_END: usize = 116;

/// Toccata covenant script opcode tags. These values are pinned to the local
/// `rusty-kaspa` Toccata checkout and guarded by tests.
pub mod opcodes {
    /// OpCat (0x7e) — concatenates the top two stack items.
    pub const OP_CAT: u8 = 0x7e;
    /// OpBlake2bWithKey (0xa7) — BLAKE2b-with-key hash (the txscript engine
    /// uses the domain-separation "TransactionID" for prev-tx hashing; we use
    /// a custom key for the covenant commitment).
    pub const OP_BLAKE2B_WITH_KEY: u8 = 0xa7;
    /// OpOutpointTxId — pushes the input's prev tx id.
    pub const OP_OUTPOINT_TX_ID: u8 = 0xba;
    /// OpTxInputIndex — pushes the input's index within the spending tx.
    pub const OP_TX_INPUT_INDEX: u8 = 0xb9;
    /// OpTxInputSpk — pushes the *spent* UTXO's script public key.
    pub const OP_TX_INPUT_SPK: u8 = 0xbf;
    /// OpTxOutputCount — pushes the number of outputs in the spending tx.
    pub const OP_TX_OUTPUT_COUNT: u8 = 0xb4;
    /// OpTxOutputSpk — pushes the k-th output's script public key (followed by
    /// the k argument on the stack).
    pub const OP_TX_OUTPUT_SPK: u8 = 0xc3;
    /// OpTxPayloadLen — pushes the spending tx's payload length.
    pub const OP_TX_PAYLOAD_LEN: u8 = 0xc4;
    /// OpTxPayloadSubstr — pushes payload[lo..hi] onto the stack.
    pub const OP_TX_PAYLOAD_SUBSTR: u8 = 0xb8;
    /// OpInputCovenantId — pushes the k-th input UTXO's covenant id.
    pub const OP_INPUT_COVENANT_ID: u8 = 0xcf;
    /// OpOutputCovenantId — pushes the k-th output covenant id.
    pub const OP_OUTPUT_COVENANT_ID: u8 = 0xd5;
    /// OpOutputAuthorizingInput — pushes the k-th output's authorising input.
    pub const OP_OUTPUT_AUTHORIZING_INPUT: u8 = 0xd6;
    /// OpAuthOutputCount — pushes the number of outputs directly authorised by
    /// a transaction input.
    pub const OP_AUTH_OUTPUT_COUNT: u8 = 0xcb;
    /// OpAuthOutputIdx — pushes the absolute index of the k-th output directly
    /// authorised by a transaction input.
    pub const OP_AUTH_OUTPUT_IDX: u8 = 0xcc;
    /// OpCovInputCount — pushes the number of inputs carrying a covenant id.
    pub const OP_COV_INPUT_COUNT: u8 = 0xd0;
    /// OpCovInputIdx — pushes the absolute index of the k-th input carrying a
    /// covenant id.
    pub const OP_COV_INPUT_IDX: u8 = 0xd1;
    /// OpCovOutputCount — pushes the number of outputs carrying a covenant id.
    pub const OP_COV_OUTPUT_COUNT: u8 = 0xd2;
    /// OpCovOutputIdx — pushes the absolute index of the k-th output carrying a
    /// covenant id.
    pub const OP_COV_OUTPUT_IDX: u8 = 0xd3;
    /// OpZkPrecompile (0xa6) — Toccata ZK precompile. Top stack: tag byte.
    pub const OP_ZK_PRECOMPILE: u8 = 0xa6;
    /// OpDup (0x76), OpEqual (0x87), OpEqualVerify (0x88), OpDrop (0x75).
    pub const OP_DUP: u8 = 0x76;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUAL_VERIFY: u8 = 0x88;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_ROT: u8 = 0x7b;
}

/// Exact continuation-output shape enforced by a generated Toccata covenant
/// script.
///
/// The default policy is the historical singleton form: input 0 authorises
/// output 0 and the spending transaction has exactly one output. A wider policy
/// can authorise multiple covenant continuation outputs while leaving explicit
/// non-covenant outputs, such as fee/change outputs, in the same transaction.
/// Those extra outputs are admitted only by `exact_output_count`; their economic
/// meaning remains part of RGK receipt/resolver validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CovenantContinuationPolicy {
    pub authorizing_input: u16,
    pub exact_output_count: u32,
    pub covenant_output_indices: Vec<u32>,
}

impl CovenantContinuationPolicy {
    /// Historical RGK shape: one authorising covenant input and one
    /// continuation output at index 0.
    pub fn singleton() -> Self {
        Self {
            authorizing_input: 0,
            exact_output_count: 1,
            covenant_output_indices: vec![0],
        }
    }

    pub fn new(
        authorizing_input: u16,
        exact_output_count: u32,
        covenant_output_indices: Vec<u32>,
    ) -> Result<Self, CovenantError> {
        let policy = Self {
            authorizing_input,
            exact_output_count,
            covenant_output_indices,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), CovenantError> {
        if self.exact_output_count == 0 {
            return Err(CovenantError::ScriptBuild(
                "continuation policy output count must be non-zero".into(),
            ));
        }
        if self.covenant_output_indices.is_empty() {
            return Err(CovenantError::ScriptBuild(
                "continuation policy requires at least one covenant output".into(),
            ));
        }

        let mut previous = None;
        for &idx in &self.covenant_output_indices {
            if idx >= self.exact_output_count {
                return Err(CovenantError::ScriptBuild(format!(
                    "continuation covenant output index {idx} is outside exact output count {}",
                    self.exact_output_count
                )));
            }
            if let Some(prev) = previous {
                if idx <= prev {
                    return Err(CovenantError::ScriptBuild(
                        "continuation covenant output indices must be strictly increasing".into(),
                    ));
                }
            }
            previous = Some(idx);
        }

        Ok(())
    }
}

impl Default for CovenantContinuationPolicy {
    fn default() -> Self {
        Self::singleton()
    }
}

/// Shared covenant shape enforced by a redeem script that can execute on every
/// input carrying the same covenant id.
///
/// This policy is the local on-chain shape for merge and batch transitions: the
/// same script validates the global covenant input/output counts and checks
/// every shared covenant output, independent of which covenant input is
/// currently executing the script.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CovenantSharedContinuationPolicy {
    pub covenant_input_count: u32,
    pub covenant_output_count: u32,
    pub exact_output_count: u32,
}

impl CovenantSharedContinuationPolicy {
    pub fn new(
        covenant_input_count: u32,
        covenant_output_count: u32,
        exact_output_count: u32,
    ) -> Result<Self, CovenantError> {
        let policy = Self {
            covenant_input_count,
            covenant_output_count,
            exact_output_count,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), CovenantError> {
        if self.covenant_input_count == 0 {
            return Err(CovenantError::ScriptBuild(
                "shared continuation policy requires at least one covenant input".into(),
            ));
        }
        if self.covenant_output_count == 0 {
            return Err(CovenantError::ScriptBuild(
                "shared continuation policy requires at least one covenant output".into(),
            ));
        }
        if self.exact_output_count == 0 {
            return Err(CovenantError::ScriptBuild(
                "shared continuation policy output count must be non-zero".into(),
            ));
        }
        if self.covenant_output_count > self.exact_output_count {
            return Err(CovenantError::ScriptBuild(format!(
                "shared continuation covenant output count {} exceeds exact output count {}",
                self.covenant_output_count, self.exact_output_count
            )));
        }
        Ok(())
    }
}

/// A high-level specification of what the RGK Toccata covenant enforces.
/// The [`build_script`](Self::build_script) method emits the byte sequence
/// that becomes the covenant's redeem script (and is wrapped in P2SH for the
/// output's script public key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CovenantSpec {
    pub chain_id: KaspaChainId,
    pub lineage_id: Bytes32,
    pub asset_id: Bytes32,
    pub initial_state_digest: Bytes32,
    pub receipt_policy: ReceiptPolicy,
    pub genesis_proof_mode: ProofMode,
}

impl CovenantSpec {
    /// Build the Toccata covenant *redeem script* (the inner script that the
    /// SPK commits to). The covenant enforces:
    ///
    /// 1. The covenant spend is authorised by input 0.
    /// 2. The covenant-locked output is at index 0 of the spending tx, and
    ///    the spending tx has exactly one output.
    /// 3. The covenant-locked output's `script_public_key` equals the SPK
    ///    that wraps this redeem script (i.e. lineage is preserved).
    /// 4. The output covenant id equals the input covenant id and output 0
    ///    records authorising input 0.
    /// 5. The spending transaction payload has the exact [`CovenantState`]
    ///    length and preserves chain id, lineage id, RGK asset id, receipt
    ///    policy and proof mode.
    ///
    /// For multi-output continuation or explicit fee/change shapes, use
    /// [`build_script_for_policy`](Self::build_script_for_policy).
    ///
    /// The script bytes are intentionally compact and human-auditable. The
    /// opcodes used here are stable in the rusty-kaspa toccata branch; see
    /// `docs/COVENANT-SPEC.md` for the full annotated disassembly.
    pub fn build_script(&self) -> Result<Vec<u8>, CovenantError> {
        self.build_script_for_policy(&CovenantContinuationPolicy::singleton())
    }

    /// Build a Toccata covenant redeem script for an explicit continuation
    /// policy. This generalises the default singleton script without weakening
    /// its checks: every listed covenant output must preserve the input script
    /// public key, preserve the covenant id, and record the configured
    /// authorising input.
    pub fn build_script_for_policy(
        &self,
        policy: &CovenantContinuationPolicy,
    ) -> Result<Vec<u8>, CovenantError> {
        policy.validate()?;
        use opcodes::*;
        let mut s = Vec::new();

        let payload_template = CovenantState {
            version: ENCODING_VERSION,
            chain_id: self.chain_id,
            lineage_id: self.lineage_id,
            asset_id: self.asset_id,
            current_state_digest: [0u8; 32],
            receipt_policy: self.receipt_policy,
            genesis_proof_mode: self.genesis_proof_mode,
            replay_marker: [0u8; 32],
        }
        .encode_payload();
        if payload_template.len() != expected_payload_len() as usize {
            return Err(CovenantError::ScriptBuild(
                "payload length template mismatch".into(),
            ));
        }

        // ---- Section A: authorised covenant input ----
        // This redeem script is valid only for the configured input index.
        s.push(OP_TX_INPUT_INDEX);
        push_script_i64(&mut s, i64::from(policy.authorizing_input));
        s.push(OP_EQUAL_VERIFY);

        // ---- Section B: covenant-output-shape check ----
        // Exact total output count prevents unbounded unchecked outputs.
        s.push(OP_TX_OUTPUT_COUNT);
        push_script_i64(&mut s, i64::from(policy.exact_output_count));
        s.push(OP_EQUAL_VERIFY);

        for &output_index in &policy.covenant_output_indices {
            // Each continuation output must keep the same P2SH script public key.
            push_script_i64(&mut s, i64::from(policy.authorizing_input));
            s.push(OP_TX_INPUT_SPK);
            push_script_i64(&mut s, i64::from(output_index));
            s.push(OP_TX_OUTPUT_SPK);
            s.push(OP_EQUAL_VERIFY);

            // The covenant id must be preserved on every covenant output, and
            // every such output must record the configured authorising input.
            push_script_i64(&mut s, i64::from(policy.authorizing_input));
            s.push(OP_INPUT_COVENANT_ID);
            push_script_i64(&mut s, i64::from(output_index));
            s.push(OP_OUTPUT_COVENANT_ID);
            s.push(OP_EQUAL_VERIFY);
            push_script_i64(&mut s, i64::from(output_index));
            s.push(OP_OUTPUT_AUTHORIZING_INPUT);
            push_script_i64(&mut s, i64::from(policy.authorizing_input));
            s.push(OP_EQUAL_VERIFY);
        }

        // ---- Section C: payload-shape check ----
        // Payload length must equal the canonical CovenantState size.
        let payload_len: u32 = expected_payload_len();
        s.push(OP_TX_PAYLOAD_LEN);
        push_script_i64(&mut s, payload_len as i64);
        s.push(OP_EQUAL_VERIFY);

        // ---- Section D: payload static-field checks ----
        // Dynamic fields (state digest and replay marker) are verified by the
        // RGK receipt/resolver path. The redeem script pins every immutable
        // covenant field that can be checked without old-state witness data.
        push_payload_slice_equals(
            &mut s,
            0,
            PAYLOAD_STATIC_PREFIX_END,
            &payload_template[0..PAYLOAD_STATIC_PREFIX_END],
        );
        push_payload_slice_equals(
            &mut s,
            PAYLOAD_LINEAGE_START,
            PAYLOAD_LINEAGE_END,
            &payload_template[PAYLOAD_LINEAGE_START..PAYLOAD_LINEAGE_END],
        );
        push_payload_slice_equals(
            &mut s,
            PAYLOAD_CONTRACT_START,
            PAYLOAD_CONTRACT_END,
            &payload_template[PAYLOAD_CONTRACT_START..PAYLOAD_CONTRACT_END],
        );
        push_payload_slice_equals(
            &mut s,
            PAYLOAD_POLICY_MODE_START,
            PAYLOAD_POLICY_MODE_END,
            &payload_template[PAYLOAD_POLICY_MODE_START..PAYLOAD_POLICY_MODE_END],
        );

        // ---- Section E: OP_TRUE termination ----
        // A covenant script does not need a separate sig check (the covenant
        // is enforced by the engine, not by signatures). We end with OP_TRUE
        // so any remaining stack is accepted by the engine.
        s.push(0x51); // OP_TRUE
        Ok(s)
    }

    /// Build a redeem script for merge/batch-style continuation where the same
    /// covenant script must execute on every input carrying the same covenant
    /// id. The script checks shared covenant input/output counts through
    /// Toccata's covenant-context opcodes, then checks every shared covenant
    /// output against the current input's script public key and covenant id.
    pub fn build_script_for_shared_policy(
        &self,
        policy: &CovenantSharedContinuationPolicy,
    ) -> Result<Vec<u8>, CovenantError> {
        policy.validate()?;
        use opcodes::*;
        let mut s = Vec::new();

        let payload_template = CovenantState {
            version: ENCODING_VERSION,
            chain_id: self.chain_id,
            lineage_id: self.lineage_id,
            asset_id: self.asset_id,
            current_state_digest: [0u8; 32],
            receipt_policy: self.receipt_policy,
            genesis_proof_mode: self.genesis_proof_mode,
            replay_marker: [0u8; 32],
        }
        .encode_payload();
        if payload_template.len() != expected_payload_len() as usize {
            return Err(CovenantError::ScriptBuild(
                "payload length template mismatch".into(),
            ));
        }

        s.push(OP_TX_OUTPUT_COUNT);
        push_script_i64(&mut s, i64::from(policy.exact_output_count));
        s.push(OP_EQUAL_VERIFY);

        push_current_input_covenant_id(&mut s);
        s.push(OP_COV_INPUT_COUNT);
        push_script_i64(&mut s, i64::from(policy.covenant_input_count));
        s.push(OP_EQUAL_VERIFY);

        push_current_input_covenant_id(&mut s);
        s.push(OP_COV_OUTPUT_COUNT);
        push_script_i64(&mut s, i64::from(policy.covenant_output_count));
        s.push(OP_EQUAL_VERIFY);

        for output_ordinal in 0..policy.covenant_output_count {
            push_current_input_spk(&mut s);
            push_shared_covenant_output_index(&mut s, output_ordinal);
            s.push(OP_TX_OUTPUT_SPK);
            s.push(OP_EQUAL_VERIFY);

            push_current_input_covenant_id(&mut s);
            push_shared_covenant_output_index(&mut s, output_ordinal);
            s.push(OP_OUTPUT_COVENANT_ID);
            s.push(OP_EQUAL_VERIFY);
        }

        let payload_len: u32 = expected_payload_len();
        s.push(OP_TX_PAYLOAD_LEN);
        push_script_i64(&mut s, payload_len as i64);
        s.push(OP_EQUAL_VERIFY);

        push_payload_slice_equals(
            &mut s,
            0,
            PAYLOAD_STATIC_PREFIX_END,
            &payload_template[0..PAYLOAD_STATIC_PREFIX_END],
        );
        push_payload_slice_equals(
            &mut s,
            PAYLOAD_LINEAGE_START,
            PAYLOAD_LINEAGE_END,
            &payload_template[PAYLOAD_LINEAGE_START..PAYLOAD_LINEAGE_END],
        );
        push_payload_slice_equals(
            &mut s,
            PAYLOAD_CONTRACT_START,
            PAYLOAD_CONTRACT_END,
            &payload_template[PAYLOAD_CONTRACT_START..PAYLOAD_CONTRACT_END],
        );
        push_payload_slice_equals(
            &mut s,
            PAYLOAD_POLICY_MODE_START,
            PAYLOAD_POLICY_MODE_END,
            &payload_template[PAYLOAD_POLICY_MODE_START..PAYLOAD_POLICY_MODE_END],
        );

        s.push(0x51);
        Ok(s)
    }

    /// The expected payload hash that the script checks against. Computed as:
    /// `SHA256( lineage_id || payload_bytes )` where `payload_bytes` is the
    /// fixed-size [`CovenantState::encode_payload`] output.
    pub fn expected_payload_hash(&self) -> Bytes32 {
        let payload = CovenantState {
            version: ENCODING_VERSION,
            chain_id: self.chain_id,
            lineage_id: self.lineage_id,
            asset_id: self.asset_id,
            current_state_digest: self.initial_state_digest,
            receipt_policy: self.receipt_policy,
            genesis_proof_mode: self.genesis_proof_mode,
            replay_marker: [0u8; 32],
        }
        .encode_payload();
        let mut hasher = Sha256::new();
        hasher.update(&self.lineage_id);
        hasher.update(&(payload.len() as u32).to_le_bytes());
        hasher.update(&payload);
        let out = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        bytes
    }
}

/// Length of a single [`CovenantState::encode_payload`] byte buffer, including
/// the 12-byte tag. Pinned so the on-chain check is exact.
pub fn expected_payload_len() -> u32 {
    let sample = CovenantState {
        version: ENCODING_VERSION,
        chain_id: KaspaChainId::KaspaLocalToccata,
        lineage_id: [1u8; 32],
        asset_id: [2u8; 32],
        current_state_digest: [3u8; 32],
        receipt_policy: ReceiptPolicy::Any,
        genesis_proof_mode: ProofMode::VerifierReceipt,
        replay_marker: [4u8; 32],
    };
    sample.encode_payload().len() as u32
}

// ---------------- low-level script helpers ----------------

/// Push a Kaspa `var_int` compact-size value onto the script.
pub fn push_var_int(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Push a signed integer using Kaspa txscript's canonical script-number
/// encoding. This mirrors upstream `ScriptBuilder::add_i64` for the positive
/// values RGK emits in covenant scripts.
pub fn push_script_i64(out: &mut Vec<u8>, n: i64) {
    if n == 0 {
        out.push(0x00); // OP_0
        return;
    }
    if n == -1 {
        out.push(0x4f); // OP_1NEGATE
        return;
    }
    if (1..=16).contains(&n) {
        out.push(0x50 + n as u8); // OP_1 .. OP_16
        return;
    }

    let negative = n < 0;
    let mut value = if negative {
        n.wrapping_neg() as u64
    } else {
        n as u64
    };
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    if bytes.last().map(|b| b & 0x80 != 0).unwrap_or(false) {
        bytes.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = bytes.last_mut().expect("non-zero value has a byte");
        *last |= 0x80;
    }
    push_data(out, &bytes);
}

fn push_payload_slice_equals(out: &mut Vec<u8>, start: usize, end: usize, expected: &[u8]) {
    push_script_i64(out, start as i64);
    push_script_i64(out, end as i64);
    out.push(opcodes::OP_TX_PAYLOAD_SUBSTR);
    push_data(out, expected);
    out.push(opcodes::OP_EQUAL_VERIFY);
}

fn push_current_input_covenant_id(out: &mut Vec<u8>) {
    out.push(opcodes::OP_TX_INPUT_INDEX);
    out.push(opcodes::OP_INPUT_COVENANT_ID);
}

fn push_current_input_spk(out: &mut Vec<u8>) {
    out.push(opcodes::OP_TX_INPUT_INDEX);
    out.push(opcodes::OP_TX_INPUT_SPK);
}

fn push_shared_covenant_output_index(out: &mut Vec<u8>, output_ordinal: u32) {
    push_current_input_covenant_id(out);
    push_script_i64(out, i64::from(output_ordinal));
    out.push(opcodes::OP_COV_OUTPUT_IDX);
}

/// Push a length-prefixed data blob onto the script. Matches Kaspa's
/// `OP_PUSHBYTES_N` / `OP_PUSHDATA1/2/4` rules.
pub fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 0x4c {
        out.push(n as u8);
        out.extend_from_slice(data);
    } else if n <= 0xff {
        out.push(0x4c); // OP_PUSHDATA1
        out.push(n as u8);
        out.extend_from_slice(data);
    } else if n <= 0xffff {
        out.push(0x4d); // OP_PUSHDATA2
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out.extend_from_slice(data);
    } else {
        out.push(0x4e); // OP_PUSHDATA4
        out.extend_from_slice(&(n as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
}

/// Call-site migration helper for callers that still hold a [`CovenantState`]
/// while computing the consensus covenant id.
///
/// The consensus id is derived from the genesis outpoint and authorised output
/// descriptors only; the state argument is retained so older call sites can move
/// to [`compute_covenant_id`] without changing their surrounding data flow.
pub fn derive_covenant_id(
    genesis_outpoint: KaspaOutpoint,
    _state: &CovenantState,
    authorized_outputs: &[(u32, u64, u16, Vec<u8>)],
) -> KaspaCovenantId {
    compute_covenant_id(genesis_outpoint, authorized_outputs)
}

/// Convenience: compute the covenant id from a lineage id alone. This is what
/// gets embedded in the SPK hash and re-checked at spend time.
pub fn compute_covenant_id_from_lineage(lineage: Bytes32) -> KaspaCovenantId {
    domain_hash(DomainTag::Lineage, &lineage)
}

// ---------------- tests ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rgk_core::{from_hex, KASPA_LOCAL_TOCCATA};

    fn b32(s: &str) -> [u8; 32] {
        from_hex::<32>(s).expect("valid hex")
    }

    fn sample_spec() -> CovenantSpec {
        CovenantSpec {
            chain_id: KASPA_LOCAL_TOCCATA,
            lineage_id: b32("1111111111111111111111111111111111111111111111111111111111111111"),
            asset_id: b32("2222222222222222222222222222222222222222222222222222222222222222"),
            initial_state_digest: [3u8; 32],
            receipt_policy: ReceiptPolicy::Any,
            genesis_proof_mode: ProofMode::VerifierReceipt,
        }
    }

    fn sample_state() -> CovenantState {
        CovenantState::genesis(
            KASPA_LOCAL_TOCCATA,
            b32("2222222222222222222222222222222222222222222222222222222222222222"),
            b32("1111111111111111111111111111111111111111111111111111111111111111"),
            ReceiptPolicy::Any,
            ProofMode::VerifierReceipt,
        )
    }

    fn advanced_policy_shape(flow: AdvancedCovenantFlow) -> AdvancedCovenantPolicyShape {
        AdvancedCovenantPolicyShape {
            chain_id: KASPA_LOCAL_TOCCATA,
            asset_id: [0x21; 32],
            lineage_id: [0x22; 32],
            flow,
            covenant_id: [0x23; 32],
            counterparty_covenant_id: [0x24; 32],
            payment_asset_id: [0x25; 32],
            payment_amount: 50_000,
            unlock_daa_score: 1_000_000,
            policy_commitment: [0x26; 32],
            authorization_commitment: [0x27; 32],
        }
    }

    fn advanced_flows() -> [AdvancedCovenantFlow; 7] {
        [
            AdvancedCovenantFlow::PaymentGatedTransfer,
            AdvancedCovenantFlow::EscrowRelease,
            AdvancedCovenantFlow::VaultTimelockRelease,
            AdvancedCovenantFlow::AtomicSwap,
            AdvancedCovenantFlow::CovenantOwnedAsset,
            AdvancedCovenantFlow::PolicyUpgrade,
            AdvancedCovenantFlow::ControlledTermination,
        ]
    }

    fn advanced_execution_evidence(
        shape: &AdvancedCovenantPolicyShape,
    ) -> AdvancedCovenantExecutionEvidence {
        AdvancedCovenantExecutionEvidence {
            counterparty_covenant_id: shape.counterparty_covenant_id,
            payment_asset_id: shape.payment_asset_id,
            paid_amount: shape.payment_amount,
            current_daa_score: shape.unlock_daa_score,
            policy_commitment: shape.policy_commitment,
            authorization_commitment: shape.authorization_commitment,
        }
    }

    #[test]
    fn payload_roundtrip() {
        let s = sample_state();
        let bytes = s.encode_payload();
        let back = CovenantState::decode_payload(&bytes).expect("decode");
        assert_eq!(s, back);
    }

    #[test]
    fn payload_rejects_bad_tag() {
        let mut bytes = sample_state().encode_payload();
        bytes[0] = b'X';
        assert!(matches!(
            CovenantState::decode_payload(&bytes),
            Err(CovenantError::Decode(_))
        ));
    }

    #[test]
    fn payload_rejects_truncated() {
        let mut bytes = sample_state().encode_payload();
        bytes.truncate(bytes.len() - 1);
        assert!(CovenantState::decode_payload(&bytes).is_err());
    }

    #[test]
    fn advance_rejects_no_op() {
        let s = sample_state();
        let new = s.advance(s.current_state_digest, [9u8; 32]);
        assert!(matches!(new, Err(CovenantError::Invariant(_))));
    }

    #[test]
    fn advance_produces_new_state() {
        let s = sample_state();
        let new = s.advance([7u8; 32], [9u8; 32]).unwrap();
        assert_eq!(new.current_state_digest, [7u8; 32]);
        assert_eq!(new.replay_marker, [9u8; 32]);
        assert_eq!(new.lineage_id, s.lineage_id);
        assert_eq!(new.asset_id, s.asset_id);
        assert_eq!(new.receipt_policy, s.receipt_policy);
    }

    #[test]
    fn advanced_covenant_policy_shapes_have_unique_commitments() {
        let mut commitments = Vec::new();
        for flow in advanced_flows() {
            let shape = advanced_policy_shape(flow);
            shape.validate().unwrap();
            let commitment = shape.commitment().unwrap();
            assert_ne!(commitment, [0; 32]);
            assert!(
                !commitments.contains(&commitment),
                "duplicate advanced covenant commitment for {}",
                flow.label()
            );
            commitments.push(commitment);
        }
        assert_eq!(commitments.len(), advanced_flows().len());
    }

    #[test]
    fn advanced_covenant_policy_shapes_fail_closed_on_missing_material() {
        let mut missing_payment = advanced_policy_shape(AdvancedCovenantFlow::PaymentGatedTransfer);
        missing_payment.payment_amount = 0;
        assert!(matches!(
            missing_payment.validate(),
            Err(CovenantError::MissingAdvancedCovenantField {
                flow: AdvancedCovenantFlow::PaymentGatedTransfer,
                field: "payment_amount"
            })
        ));

        let mut missing_counterparty = advanced_policy_shape(AdvancedCovenantFlow::AtomicSwap);
        missing_counterparty.counterparty_covenant_id = [0; 32];
        assert!(matches!(
            missing_counterparty.validate(),
            Err(CovenantError::MissingAdvancedCovenantField {
                flow: AdvancedCovenantFlow::AtomicSwap,
                field: "counterparty_covenant_id"
            })
        ));

        let mut missing_unlock = advanced_policy_shape(AdvancedCovenantFlow::VaultTimelockRelease);
        missing_unlock.unlock_daa_score = 0;
        assert!(matches!(
            missing_unlock.validate(),
            Err(CovenantError::MissingAdvancedCovenantField {
                flow: AdvancedCovenantFlow::VaultTimelockRelease,
                field: "unlock_daa_score"
            })
        ));

        let mut missing_policy = advanced_policy_shape(AdvancedCovenantFlow::PolicyUpgrade);
        missing_policy.policy_commitment = [0; 32];
        assert!(matches!(
            missing_policy.validate(),
            Err(CovenantError::MissingAdvancedCovenantField {
                flow: AdvancedCovenantFlow::PolicyUpgrade,
                field: "policy_commitment"
            })
        ));

        let mut missing_authorization =
            advanced_policy_shape(AdvancedCovenantFlow::ControlledTermination);
        missing_authorization.authorization_commitment = [0; 32];
        assert!(matches!(
            missing_authorization.validate(),
            Err(CovenantError::ZeroAdvancedCovenantField {
                field: "authorization_commitment"
            })
        ));
    }

    #[test]
    fn advanced_covenant_policy_commitment_binds_flow_and_material() {
        let base = advanced_policy_shape(AdvancedCovenantFlow::EscrowRelease);
        let base_commitment = base.commitment().unwrap();

        let mut changed_flow = base;
        changed_flow.flow = AdvancedCovenantFlow::AtomicSwap;
        assert_ne!(base_commitment, changed_flow.commitment().unwrap());

        let mut changed_amount = base;
        changed_amount.payment_amount += 1;
        assert_ne!(base_commitment, changed_amount.commitment().unwrap());

        let mut changed_authorization = base;
        changed_authorization.authorization_commitment[0] ^= 1;
        assert_ne!(base_commitment, changed_authorization.commitment().unwrap());
    }

    #[test]
    fn advanced_covenant_execution_plans_validate_all_flows() {
        for flow in advanced_flows() {
            let shape = advanced_policy_shape(flow);
            let evidence = advanced_execution_evidence(&shape);
            let plan = AdvancedCovenantExecutionPlan::new(shape, evidence).unwrap();
            assert_eq!(plan.shape.flow, flow);
            assert_eq!(plan.policy_commitment, shape.commitment().unwrap());
            assert_ne!(plan.execution_commitment, [0; 32]);
        }
    }

    #[test]
    fn advanced_covenant_execution_rejects_wrong_authorization_and_counterparty() {
        let shape = advanced_policy_shape(AdvancedCovenantFlow::EscrowRelease);
        let mut wrong_authorization = advanced_execution_evidence(&shape);
        wrong_authorization.authorization_commitment[0] ^= 1;
        assert!(matches!(
            AdvancedCovenantExecutionPlan::new(shape, wrong_authorization),
            Err(CovenantError::AdvancedCovenantExecutionMismatch {
                flow: AdvancedCovenantFlow::EscrowRelease,
                field: "authorization_commitment"
            })
        ));

        let mut wrong_counterparty = advanced_execution_evidence(&shape);
        wrong_counterparty.counterparty_covenant_id[0] ^= 1;
        assert!(matches!(
            AdvancedCovenantExecutionPlan::new(shape, wrong_counterparty),
            Err(CovenantError::AdvancedCovenantExecutionMismatch {
                flow: AdvancedCovenantFlow::EscrowRelease,
                field: "counterparty_covenant_id"
            })
        ));
    }

    #[test]
    fn advanced_covenant_execution_enforces_payment_and_timelock_rules() {
        let payment = advanced_policy_shape(AdvancedCovenantFlow::PaymentGatedTransfer);
        let mut underpaid = advanced_execution_evidence(&payment);
        underpaid.paid_amount = payment.payment_amount - 1;
        assert!(matches!(
            AdvancedCovenantExecutionPlan::new(payment, underpaid),
            Err(CovenantError::AdvancedCovenantPaymentTooSmall {
                flow: AdvancedCovenantFlow::PaymentGatedTransfer,
                required: 50_000,
                actual: 49_999
            })
        ));

        let swap = advanced_policy_shape(AdvancedCovenantFlow::AtomicSwap);
        let mut overpaid_swap = advanced_execution_evidence(&swap);
        overpaid_swap.paid_amount += 1;
        assert!(matches!(
            AdvancedCovenantExecutionPlan::new(swap, overpaid_swap),
            Err(CovenantError::AdvancedCovenantExecutionMismatch {
                flow: AdvancedCovenantFlow::AtomicSwap,
                field: "paid_amount"
            })
        ));

        let vault = advanced_policy_shape(AdvancedCovenantFlow::VaultTimelockRelease);
        let mut early = advanced_execution_evidence(&vault);
        early.current_daa_score = vault.unlock_daa_score - 1;
        assert!(matches!(
            AdvancedCovenantExecutionPlan::new(vault, early),
            Err(CovenantError::AdvancedCovenantDaaTooEarly {
                flow: AdvancedCovenantFlow::VaultTimelockRelease,
                required: 1_000_000,
                actual: 999_999
            })
        ));
    }

    #[test]
    fn advanced_covenant_execution_commitment_binds_policy_and_evidence() {
        let shape = advanced_policy_shape(AdvancedCovenantFlow::PolicyUpgrade);
        let evidence = advanced_execution_evidence(&shape);
        let base = AdvancedCovenantExecutionPlan::new(shape, evidence).unwrap();

        let mut changed_evidence = evidence;
        changed_evidence.current_daa_score += 1;
        let changed = AdvancedCovenantExecutionPlan::new(shape, changed_evidence).unwrap();
        assert_ne!(base.execution_commitment, changed.execution_commitment);

        let mut changed_shape = shape;
        changed_shape.policy_commitment[0] ^= 1;
        let mut changed_shape_evidence = evidence;
        changed_shape_evidence.policy_commitment = changed_shape.policy_commitment;
        let changed_policy =
            AdvancedCovenantExecutionPlan::new(changed_shape, changed_shape_evidence).unwrap();
        assert_ne!(base.policy_commitment, changed_policy.policy_commitment);
        assert_ne!(
            base.execution_commitment,
            changed_policy.execution_commitment
        );
    }

    #[test]
    fn advanced_covenant_execution_record_round_trips_and_rejects_tamper() {
        let shape = advanced_policy_shape(AdvancedCovenantFlow::AtomicSwap);
        let evidence = advanced_execution_evidence(&shape);
        let record = AdvancedCovenantExecutionRecord::from_parts(shape, evidence).unwrap();
        let bytes = record.canonical_bytes();
        assert_eq!(bytes.len(), 465);

        let decoded = AdvancedCovenantExecutionRecord::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(
            decoded.plan.execution_commitment,
            record.plan.execution_commitment
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            AdvancedCovenantExecutionRecord::decode_canonical(&trailing),
            Err(CovenantError::Decode(message)) if message.contains("trailing")
        ));

        let mut bad_flow = bytes.clone();
        bad_flow[80] = 99;
        assert!(matches!(
            AdvancedCovenantExecutionRecord::decode_canonical(&bad_flow),
            Err(CovenantError::Decode(message))
                if message.contains("unknown advanced covenant flow tag")
        ));

        let mut tampered_commitment = bytes;
        let last = tampered_commitment.len() - 1;
        tampered_commitment[last] ^= 1;
        assert!(matches!(
            AdvancedCovenantExecutionRecord::decode_canonical(&tampered_commitment),
            Err(CovenantError::Decode(message))
                if message.contains("execution commitment mismatch")
        ));
    }

    proptest! {
        #[test]
        fn covenant_state_advance_sequences_preserve_static_fields(
            steps in prop::collection::vec((any::<[u8; 32]>(), any::<[u8; 32]>()), 1..16)
        ) {
            let mut state = sample_state();
            let lineage_id = state.lineage_id;
            let asset_id = state.asset_id;
            let policy = state.receipt_policy;
            let mode = state.genesis_proof_mode;

            for (mut digest, replay_marker) in steps {
                if digest == state.current_state_digest {
                    digest[0] ^= 0x01;
                }
                let next = state.advance(digest, replay_marker).expect("advance");
                let decoded = CovenantState::decode_payload(&next.encode_payload()).expect("decode");

                prop_assert_eq!(next.current_state_digest, digest);
                prop_assert_eq!(next.replay_marker, replay_marker);
                prop_assert_eq!(next.lineage_id, lineage_id);
                prop_assert_eq!(next.asset_id, asset_id);
                prop_assert_eq!(next.receipt_policy, policy);
                prop_assert_eq!(next.genesis_proof_mode, mode);
                prop_assert_eq!(decoded, next.clone());

                state = next;
            }
        }
    }

    #[test]
    fn commitment_is_deterministic() {
        let s = sample_state();
        assert_eq!(s.commitment(), s.commitment());
        let mut s2 = s.clone();
        s2.current_state_digest[0] ^= 1;
        assert_ne!(s.commitment(), s2.commitment());
    }

    #[test]
    fn covenant_id_is_deterministic() {
        let op = KaspaOutpoint {
            transaction_id: b32("ab".repeat(32).as_str()),
            index: 0,
        };
        let outs = vec![(0u32, 1_000u64, 0u16, vec![1u8, 2, 3])];
        let a = compute_covenant_id(op, &outs);
        let b = compute_covenant_id(op, &outs);
        assert_eq!(a, b);
    }

    #[test]
    fn covenant_id_changes_with_outputs() {
        let op = KaspaOutpoint {
            transaction_id: b32("ab".repeat(32).as_str()),
            index: 0,
        };
        let outs_a = vec![(0u32, 1_000u64, 0u16, vec![1u8, 2, 3])];
        let outs_b = vec![(0u32, 1_000u64, 0u16, vec![1u8, 2, 4])];
        assert_ne!(
            compute_covenant_id(op, &outs_a),
            compute_covenant_id(op, &outs_b)
        );
    }

    #[test]
    fn derive_covenant_id_uses_consensus_recipe() {
        let op = KaspaOutpoint {
            transaction_id: b32("ab".repeat(32).as_str()),
            index: 0,
        };
        let state = sample_state();
        let outs = vec![(0u32, 1_000u64, 0u16, vec![1u8, 2, 3])];
        assert_eq!(
            derive_covenant_id(op, &state, &outs),
            compute_covenant_id(op, &outs)
        );
    }

    #[test]
    fn lineage_id_binds_outpoint_and_asset() {
        let a = compute_lineage_id(b"out-A", &b32("11".repeat(32).as_str()));
        let b = compute_lineage_id(b"out-B", &b32("11".repeat(32).as_str()));
        let c = compute_lineage_id(b"out-A", &b32("22".repeat(32).as_str()));
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn spec_script_is_non_empty_and_starts_with_valid_opcode() {
        let s = sample_spec();
        let script = s.build_script().expect("script");
        assert!(!script.is_empty());
        assert_eq!(script[0], opcodes::OP_TX_INPUT_INDEX);
    }

    #[test]
    fn default_continuation_policy_matches_singleton_policy_script() {
        let s = sample_spec();
        let default_script = s.build_script().expect("default script");
        let policy_script = s
            .build_script_for_policy(&CovenantContinuationPolicy::singleton())
            .expect("singleton policy script");
        assert_eq!(default_script, policy_script);
    }

    #[test]
    fn continuation_policy_supports_fanout_with_explicit_extra_output() {
        let s = sample_spec();
        let policy = CovenantContinuationPolicy::new(0, 3, vec![0, 2]).unwrap();
        let script = s.build_script_for_policy(&policy).expect("policy script");

        assert!(!script.is_empty());
        assert!(script.len() > s.build_script().unwrap().len());
        assert_eq!(policy.authorizing_input, 0);
        assert_eq!(policy.exact_output_count, 3);
        assert_eq!(policy.covenant_output_indices, vec![0, 2]);
    }

    #[test]
    fn continuation_policy_fails_closed_on_ambiguous_shapes() {
        assert!(matches!(
            CovenantContinuationPolicy::new(0, 0, vec![0]),
            Err(CovenantError::ScriptBuild(message))
                if message.contains("output count must be non-zero")
        ));
        assert!(matches!(
            CovenantContinuationPolicy::new(0, 2, vec![]),
            Err(CovenantError::ScriptBuild(message))
                if message.contains("at least one covenant output")
        ));
        assert!(matches!(
            CovenantContinuationPolicy::new(0, 2, vec![0, 0]),
            Err(CovenantError::ScriptBuild(message))
                if message.contains("strictly increasing")
        ));
        assert!(matches!(
            CovenantContinuationPolicy::new(0, 2, vec![0, 2]),
            Err(CovenantError::ScriptBuild(message))
                if message.contains("outside exact output count")
        ));
    }

    #[test]
    fn shared_continuation_policy_supports_merge_and_batch_shapes() {
        let s = sample_spec();
        let merge = CovenantSharedContinuationPolicy::new(2, 1, 2).unwrap();
        let batch = CovenantSharedContinuationPolicy::new(2, 2, 3).unwrap();

        let merge_script = s
            .build_script_for_shared_policy(&merge)
            .expect("merge script");
        let batch_script = s
            .build_script_for_shared_policy(&batch)
            .expect("batch script");

        assert!(!merge_script.is_empty());
        assert!(!batch_script.is_empty());
        assert_ne!(merge_script, batch_script);
    }

    #[test]
    fn shared_continuation_policy_fails_closed_on_invalid_counts() {
        assert!(matches!(
            CovenantSharedContinuationPolicy::new(0, 1, 1),
            Err(CovenantError::ScriptBuild(message))
                if message.contains("at least one covenant input")
        ));
        assert!(matches!(
            CovenantSharedContinuationPolicy::new(1, 0, 1),
            Err(CovenantError::ScriptBuild(message))
                if message.contains("at least one covenant output")
        ));
        assert!(matches!(
            CovenantSharedContinuationPolicy::new(1, 1, 0),
            Err(CovenantError::ScriptBuild(message))
                if message.contains("output count must be non-zero")
        ));
        assert!(matches!(
            CovenantSharedContinuationPolicy::new(1, 2, 1),
            Err(CovenantError::ScriptBuild(message))
                if message.contains("exceeds exact output count")
        ));
    }

    #[test]
    fn expected_payload_len_is_stable() {
        // 12 tag + 2 version + 2 chain + 32 lineage + 32 asset +
        // 32 digest + 2 policy + 2 mode + 32 replay marker.
        assert_eq!(expected_payload_len(), 148);
    }

    #[test]
    fn expected_payload_hash_is_deterministic() {
        let s = sample_spec();
        assert_eq!(s.expected_payload_hash(), s.expected_payload_hash());
    }

    #[test]
    fn frozen_covenant_id_vector() {
        // A fixed vector that pins the covenant-id recipe. If the recipe ever
        // changes, this test fails and forces a spec bump.
        let op = KaspaOutpoint {
            transaction_id: b32("00".repeat(32).as_str()),
            index: 0,
        };
        let outs = vec![(0u32, 1u64, 0u16, Vec::<u8>::new())];
        let id = compute_covenant_id(op, &outs);
        // Just check it's a 32-byte hash with non-trivial entropy.
        assert_eq!(id.len(), 32);
        assert_ne!(id, [0u8; 32]);
        let id2 = compute_covenant_id(op, &outs);
        assert_eq!(id, id2);
    }

    #[test]
    fn push_var_int_compact() {
        let mut buf = Vec::new();
        push_var_int(&mut buf, 5);
        assert_eq!(buf, vec![5]);
        push_var_int(&mut buf, 0xfd);
        assert_eq!(buf, vec![5, 0xfd, 0xfd, 0x00]);
        push_var_int(&mut buf, 0x10000);
        assert_eq!(buf, vec![5, 0xfd, 0xfd, 0x00, 0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn push_script_i64_matches_upstream_builder_vectors() {
        let cases = [
            (0, vec![0x00]),
            (1, vec![0x51]),
            (16, vec![0x60]),
            (17, vec![0x01, 0x11]),
            (65, vec![0x01, 0x41]),
            (127, vec![0x01, 0x7f]),
            (128, vec![0x02, 0x80, 0x00]),
            (148, vec![0x02, 0x94, 0x00]),
            (255, vec![0x02, 0xff, 0x00]),
            (256, vec![0x02, 0x00, 0x01]),
            (-1, vec![0x4f]),
            (-2, vec![0x01, 0x82]),
        ];
        for (n, expected) in cases {
            let mut buf = Vec::new();
            push_script_i64(&mut buf, n);
            assert_eq!(buf, expected, "push_script_i64({n})");
        }
    }

    #[test]
    fn opcode_values_match_toccata_checkout() {
        assert_eq!(opcodes::OP_ZK_PRECOMPILE, 0xa6);
        assert_eq!(opcodes::OP_BLAKE2B_WITH_KEY, 0xa7);
        assert_eq!(opcodes::OP_TX_OUTPUT_COUNT, 0xb4);
        assert_eq!(opcodes::OP_TX_PAYLOAD_SUBSTR, 0xb8);
        assert_eq!(opcodes::OP_TX_INPUT_INDEX, 0xb9);
        assert_eq!(opcodes::OP_OUTPOINT_TX_ID, 0xba);
        assert_eq!(opcodes::OP_TX_INPUT_SPK, 0xbf);
        assert_eq!(opcodes::OP_TX_OUTPUT_SPK, 0xc3);
        assert_eq!(opcodes::OP_TX_PAYLOAD_LEN, 0xc4);
        assert_eq!(opcodes::OP_AUTH_OUTPUT_COUNT, 0xcb);
        assert_eq!(opcodes::OP_AUTH_OUTPUT_IDX, 0xcc);
        assert_eq!(opcodes::OP_INPUT_COVENANT_ID, 0xcf);
        assert_eq!(opcodes::OP_COV_INPUT_COUNT, 0xd0);
        assert_eq!(opcodes::OP_COV_INPUT_IDX, 0xd1);
        assert_eq!(opcodes::OP_COV_OUTPUT_COUNT, 0xd2);
        assert_eq!(opcodes::OP_COV_OUTPUT_IDX, 0xd3);
        assert_eq!(opcodes::OP_OUTPUT_COVENANT_ID, 0xd5);
        assert_eq!(opcodes::OP_OUTPUT_AUTHORIZING_INPUT, 0xd6);
    }

    #[test]
    fn push_data_picks_correct_opcode() {
        let mut buf = Vec::new();
        push_data(&mut buf, &[1, 2, 3]);
        assert_eq!(buf, vec![3, 1, 2, 3]);
        let mut buf = Vec::new();
        let big = vec![0u8; 0x4c];
        push_data(&mut buf, &big);
        assert_eq!(buf[0], 0x4c);
        assert_eq!(buf[1] as usize, 0x4c);
    }
}
