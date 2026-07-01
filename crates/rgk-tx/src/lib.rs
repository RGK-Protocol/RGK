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
//! * [`UnsignedTx::into_toccata_v1`] — promotes the lightweight builder output
//!   into a Toccata v1 transaction model with subnetwork, gas, compute-budget,
//!   storage-mass, Borsh wire bytes, txid, rest-digest, tx-hash, and Schnorr
//!   sighash projections tested against upstream `kaspa-consensus-core`.
//!
//! ## What the builders do NOT do
//!
//! * They do **not** sign inputs. Signatures are produced by the wallet
//!   after the builder returns the unsigned tx.
//! * They do **not** validate the new state. The covenant script enforces the
//!   chain-visible shape; the resolver checks the RGK asset semantics locally.
//! * They do **not** sign or submit through rusty-kaspa. The Toccata v1 hash
//!   boundary intentionally uses `kaspa-hashes` so RGK's local txid/hash
//!   projections stay byte-aligned with the parent rusty-kaspa checkout.

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

use kaspa_hashes::{Hasher, HasherBase};
use rgk_core::{Bytes32, KaspaChainId, KaspaCovenantId, KaspaOutpoint, RgkStateCommitment};
use rgk_covenant::{CovenantSpec, CovenantState};
use thiserror::Error;

pub const TX_VERSION_TOCCATA: u16 = 1;
pub const SUBNETWORK_ID_SIZE: usize = 20;
pub const SUBNETWORK_NAMESPACE_LEN: usize = 4;
pub const SUBNETWORK_ZERO_TAIL_LEN: usize = SUBNETWORK_ID_SIZE - SUBNETWORK_NAMESPACE_LEN;
pub const SUBNETWORK_ID_NATIVE: ToccataSubnetworkId = [0u8; SUBNETWORK_ID_SIZE];
pub const SUBNETWORK_ID_COINBASE: ToccataSubnetworkId = {
    let mut bytes = [0u8; SUBNETWORK_ID_SIZE];
    bytes[0] = 1;
    bytes
};

pub type ToccataSubnetworkId = [u8; SUBNETWORK_ID_SIZE];
pub const SIG_HASH_ALL: ToccataSigHashType = ToccataSigHashType(0b0000_0001);
pub const SIG_HASH_NONE: ToccataSigHashType = ToccataSigHashType(0b0000_0010);
pub const SIG_HASH_SINGLE: ToccataSigHashType = ToccataSigHashType(0b0000_0100);
pub const SIG_HASH_ANY_ONE_CAN_PAY: ToccataSigHashType = ToccataSigHashType(0b1000_0000);
pub const SIG_HASH_MASK: u8 = 0b0000_0111;
const ALLOWED_SIG_HASH_TYPE_VALUES: [u8; 6] = [
    SIG_HASH_ALL.0,
    SIG_HASH_NONE.0,
    SIG_HASH_SINGLE.0,
    SIG_HASH_ALL.0 | SIG_HASH_ANY_ONE_CAN_PAY.0,
    SIG_HASH_NONE.0 | SIG_HASH_ANY_ONE_CAN_PAY.0,
    SIG_HASH_SINGLE.0 | SIG_HASH_ANY_ONE_CAN_PAY.0,
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ToccataSigHashType(u8);

impl ToccataSigHashType {
    pub fn from_u8(value: u8) -> Result<Self, TxBuildError> {
        if !ALLOWED_SIG_HASH_TYPE_VALUES.contains(&value) {
            return Err(TxBuildError::InvalidToccataSigHashType(value));
        }
        Ok(Self(value))
    }

    pub fn to_u8(self) -> u8 {
        self.0
    }

    pub fn is_sighash_all(self) -> bool {
        self.0 & SIG_HASH_MASK == SIG_HASH_ALL.0
    }

    pub fn is_sighash_none(self) -> bool {
        self.0 & SIG_HASH_MASK == SIG_HASH_NONE.0
    }

    pub fn is_sighash_single(self) -> bool {
        self.0 & SIG_HASH_MASK == SIG_HASH_SINGLE.0
    }

    pub fn is_sighash_anyone_can_pay(self) -> bool {
        self.0 & SIG_HASH_ANY_ONE_CAN_PAY.0 == SIG_HASH_ANY_ONE_CAN_PAY.0
    }
}

impl core::ops::BitOr for ToccataSigHashType {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

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
    #[error("Toccata script public key must contain a 2-byte version prefix")]
    MalformedScriptPublicKey,
    #[error("Toccata subnetwork id is not native, coinbase, or a user-lane namespace")]
    InvalidToccataSubnetwork,
    #[error("gas is only allowed for Toccata user-lane subnetworks")]
    InvalidToccataGas,
    #[error("invalid Toccata sighash type: 0x{0:02x}")]
    InvalidToccataSigHashType(u8),
    #[error("Toccata sighash input index {input_index} is out of bounds for {input_count} inputs")]
    ToccataSigHashInputOutOfBounds {
        input_index: usize,
        input_count: usize,
    },
    #[error("Toccata sighash needs a previous UTXO entry for input {input_index}")]
    MissingToccataSigHashUtxo { input_index: usize },
    #[error("invalid Toccata covenant group: {reason}")]
    InvalidToccataCovenantGroup { reason: &'static str },
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToccataScriptPublicKey {
    pub version: u16,
    pub script: Vec<u8>,
}

impl ToccataScriptPublicKey {
    pub fn new(version: u16, script: Vec<u8>) -> Self {
        Self { version, script }
    }

    pub fn from_versioned_bytes(bytes: Vec<u8>) -> Result<Self, TxBuildError> {
        if bytes.len() < 2 {
            return Err(TxBuildError::MalformedScriptPublicKey);
        }
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        Ok(Self {
            version,
            script: bytes[2..].to_vec(),
        })
    }

    pub fn to_versioned_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.script.len());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.script);
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToccataTxInput {
    pub previous_outpoint: KaspaOutpoint,
    pub signature_script: Vec<u8>,
    pub sequence: u64,
    pub compute_budget: u16,
}

impl ToccataTxInput {
    pub fn new(previous_outpoint: KaspaOutpoint, compute_budget: u16) -> Self {
        Self {
            previous_outpoint,
            signature_script: Vec::new(),
            sequence: 0,
            compute_budget,
        }
    }

    pub fn from_unsigned(input: TxInput, compute_budget: u16) -> Self {
        Self {
            previous_outpoint: input.previous_outpoint,
            signature_script: input.signature_script,
            sequence: input.sequence,
            compute_budget,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToccataTxOutput {
    pub value: u64,
    pub script_public_key: ToccataScriptPublicKey,
    pub covenant_binding: Option<CovenantBinding>,
}

impl ToccataTxOutput {
    pub fn new(value: u64, script_public_key: ToccataScriptPublicKey) -> Self {
        Self {
            value,
            script_public_key,
            covenant_binding: None,
        }
    }

    pub fn covenant(
        value: u64,
        script_public_key: ToccataScriptPublicKey,
        covenant_binding: CovenantBinding,
    ) -> Self {
        Self {
            value,
            script_public_key,
            covenant_binding: Some(covenant_binding),
        }
    }
}

impl TryFrom<TxOutput> for ToccataTxOutput {
    type Error = TxBuildError;

    fn try_from(output: TxOutput) -> Result<Self, Self::Error> {
        Ok(Self {
            value: output.value,
            script_public_key: ToccataScriptPublicKey::from_versioned_bytes(
                output.script_public_key,
            )?,
            covenant_binding: output.covenant_binding,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToccataUtxoEntry {
    pub amount: u64,
    pub script_public_key: ToccataScriptPublicKey,
}

impl ToccataUtxoEntry {
    pub fn new(amount: u64, script_public_key: ToccataScriptPublicKey) -> Self {
        Self {
            amount,
            script_public_key,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToccataV1Tx {
    pub inputs: Vec<ToccataTxInput>,
    pub outputs: Vec<ToccataTxOutput>,
    pub lock_time: u64,
    pub subnetwork_id: ToccataSubnetworkId,
    pub gas: u64,
    pub payload: Vec<u8>,
    pub mass: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToccataGenesisCovenantGroup {
    pub authorizing_input: u16,
    pub outputs: Vec<u32>,
}

impl ToccataGenesisCovenantGroup {
    pub fn new(authorizing_input: u16, outputs: Vec<u32>) -> Self {
        Self {
            authorizing_input,
            outputs,
        }
    }
}

impl ToccataV1Tx {
    pub fn new(
        inputs: Vec<ToccataTxInput>,
        outputs: Vec<ToccataTxOutput>,
        lock_time: u64,
        subnetwork_id: ToccataSubnetworkId,
        gas: u64,
        payload: Vec<u8>,
    ) -> Result<Self, TxBuildError> {
        validate_toccata_subnetwork(subnetwork_id)?;
        validate_toccata_gas(subnetwork_id, gas)?;
        Ok(Self {
            inputs,
            outputs,
            lock_time,
            subnetwork_id,
            gas,
            payload,
            mass: 0,
        })
    }

    pub fn native(
        inputs: Vec<ToccataTxInput>,
        outputs: Vec<ToccataTxOutput>,
        payload: Vec<u8>,
    ) -> Result<Self, TxBuildError> {
        Self::new(inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, payload)
    }

    pub fn with_mass(mut self, mass: u64) -> Self {
        self.mass = mass;
        self
    }

    pub fn with_storage_mass(self, storage_mass: u64) -> Self {
        self.with_mass(storage_mass)
    }

    pub const fn version(&self) -> u16 {
        TX_VERSION_TOCCATA
    }

    pub const fn storage_mass(&self) -> u64 {
        self.mass
    }

    pub fn to_borsh_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_borsh_u16(&mut out, TX_VERSION_TOCCATA);
        write_borsh_len(&mut out, self.inputs.len());
        for input in &self.inputs {
            write_borsh_toccata_input(&mut out, input);
        }
        write_borsh_len(&mut out, self.outputs.len());
        for output in &self.outputs {
            write_borsh_toccata_output(&mut out, output);
        }
        write_borsh_u64(&mut out, self.lock_time);
        out.extend_from_slice(&self.subnetwork_id);
        write_borsh_u64(&mut out, self.gas);
        write_borsh_vec(&mut out, &self.payload);
        write_borsh_u64(&mut out, self.mass);
        out.extend_from_slice(&self.txid());
        out
    }

    pub fn rest_preimage(&self) -> Vec<u8> {
        let mut preimage = PreimageWriter::default();
        self.write_rest_preimage(&mut preimage);
        preimage.into_vec()
    }

    pub fn rest_digest(&self) -> Bytes32 {
        let mut hasher = kaspa_hashes::TransactionRest::new();
        self.write_rest_preimage(&mut hasher);
        hasher.finalize().as_bytes()
    }

    pub fn payload_digest(&self) -> Bytes32 {
        kaspa_hashes::PayloadDigest::hash(&self.payload).as_bytes()
    }

    pub fn txid(&self) -> Bytes32 {
        let mut hasher = kaspa_hashes::TransactionV1Id::new();
        hasher.update(self.payload_digest());
        hasher.update(self.rest_digest());
        hasher.finalize().as_bytes()
    }

    pub fn hash(&self) -> Bytes32 {
        let mut hasher = kaspa_hashes::TransactionHash::new();
        self.write_transaction(&mut hasher, ToccataEncodingFlags::FULL);
        hasher.finalize().as_bytes()
    }

    pub fn schnorr_signature_hash(
        &self,
        input_index: usize,
        previous_utxos: &[ToccataUtxoEntry],
        hash_type: ToccataSigHashType,
    ) -> Result<Bytes32, TxBuildError> {
        let hash_type = ToccataSigHashType::from_u8(hash_type.to_u8())?;
        let input =
            self.inputs
                .get(input_index)
                .ok_or(TxBuildError::ToccataSigHashInputOutOfBounds {
                    input_index,
                    input_count: self.inputs.len(),
                })?;
        let previous_utxo = previous_utxos
            .get(input_index)
            .ok_or(TxBuildError::MissingToccataSigHashUtxo { input_index })?;

        let mut hasher = kaspa_hashes::TransactionSigningHash::new();
        hasher
            .write_u16(TX_VERSION_TOCCATA)
            .update(self.sighash_previous_outputs_hash(hash_type))
            .update(self.sighash_sequences_hash(hash_type));

        hash_toccata_outpoint(&mut hasher, input.previous_outpoint);
        hash_toccata_script_public_key(&mut hasher, &previous_utxo.script_public_key);
        hasher
            .write_u64(previous_utxo.amount)
            .write_u64(input.sequence)
            .update(self.sighash_outputs_hash(hash_type, input_index))
            .write_u64(self.lock_time)
            .update(self.subnetwork_id)
            .write_u64(self.gas)
            .update(self.sighash_payload_hash())
            .write_u8(hash_type.to_u8());

        Ok(hasher.finalize().as_bytes())
    }

    pub fn populate_genesis_covenants(
        &mut self,
        groups: &[ToccataGenesisCovenantGroup],
    ) -> Result<(), TxBuildError> {
        let mut seen_outputs = vec![false; self.outputs.len()];
        for group in groups {
            let input_index = group.authorizing_input as usize;
            if input_index >= self.inputs.len() {
                return Err(TxBuildError::InvalidToccataCovenantGroup {
                    reason: "authorizing input does not exist",
                });
            }
            if group.outputs.is_empty() {
                return Err(TxBuildError::InvalidToccataCovenantGroup {
                    reason: "empty output group",
                });
            }
            if group.outputs.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(TxBuildError::InvalidToccataCovenantGroup {
                    reason: "outputs are not strictly ordered",
                });
            }
            for output_index in group.outputs.iter().copied() {
                let output_slot = output_index as usize;
                if output_slot >= self.outputs.len() {
                    return Err(TxBuildError::InvalidToccataCovenantGroup {
                        reason: "output does not exist",
                    });
                }
                if seen_outputs[output_slot] {
                    return Err(TxBuildError::InvalidToccataCovenantGroup {
                        reason: "output appears in more than one group",
                    });
                }
                if self.outputs[output_slot].covenant_binding.is_some() {
                    return Err(TxBuildError::InvalidToccataCovenantGroup {
                        reason: "output already has covenant binding",
                    });
                }
                seen_outputs[output_slot] = true;
            }
        }

        for group in groups {
            let genesis_outpoint = self.inputs[group.authorizing_input as usize].previous_outpoint;
            let authorized_outputs = group
                .outputs
                .iter()
                .map(|output_index| {
                    let output = &self.outputs[*output_index as usize];
                    (
                        *output_index,
                        output.value,
                        output.script_public_key.version,
                        output.script_public_key.script.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let covenant_id =
                rgk_covenant::compute_covenant_id(genesis_outpoint, authorized_outputs.as_slice());
            let binding = CovenantBinding {
                authorizing_input: group.authorizing_input,
                covenant_id,
            };
            for output_index in group.outputs.iter().copied() {
                self.outputs[output_index as usize].covenant_binding = Some(binding);
            }
        }
        Ok(())
    }

    fn sighash_previous_outputs_hash(&self, hash_type: ToccataSigHashType) -> Bytes32 {
        if hash_type.is_sighash_anyone_can_pay() {
            return [0u8; 32];
        }

        let mut hasher = kaspa_hashes::TransactionSigningHash::new();
        for input in &self.inputs {
            hash_toccata_outpoint(&mut hasher, input.previous_outpoint);
        }
        hasher.finalize().as_bytes()
    }

    fn sighash_sequences_hash(&self, hash_type: ToccataSigHashType) -> Bytes32 {
        if hash_type.is_sighash_single()
            || hash_type.is_sighash_anyone_can_pay()
            || hash_type.is_sighash_none()
        {
            return [0u8; 32];
        }

        let mut hasher = kaspa_hashes::TransactionSigningHash::new();
        for input in &self.inputs {
            hasher.write_u64(input.sequence);
        }
        hasher.finalize().as_bytes()
    }

    fn sighash_payload_hash(&self) -> Bytes32 {
        if self.subnetwork_id == SUBNETWORK_ID_NATIVE && self.payload.is_empty() {
            return [0u8; 32];
        }

        let mut hasher = kaspa_hashes::TransactionSigningHash::new();
        hasher.write_var_bytes(&self.payload);
        hasher.finalize().as_bytes()
    }

    fn sighash_outputs_hash(&self, hash_type: ToccataSigHashType, input_index: usize) -> Bytes32 {
        if hash_type.is_sighash_none() {
            return [0u8; 32];
        }

        let mut hasher = kaspa_hashes::TransactionSigningHash::new();
        if hash_type.is_sighash_single() {
            let Some(output) = self.outputs.get(input_index) else {
                return [0u8; 32];
            };
            hash_toccata_output_for_sighash(&mut hasher, output);
            return hasher.finalize().as_bytes();
        }

        for output in &self.outputs {
            hash_toccata_output_for_sighash(&mut hasher, output);
        }
        hasher.finalize().as_bytes()
    }

    fn write_rest_preimage<T: HasherBase>(&self, hasher: &mut T) {
        self.write_transaction(
            hasher,
            ToccataEncodingFlags::EXCLUDE_PAYLOAD
                | ToccataEncodingFlags::EXCLUDE_SIGNATURE_SCRIPT
                | ToccataEncodingFlags::EXCLUDE_MASS_COMMIT,
        );
    }

    fn write_transaction<T: HasherBase>(&self, hasher: &mut T, flags: ToccataEncodingFlags) {
        hasher
            .update(TX_VERSION_TOCCATA.to_le_bytes())
            .write_len(self.inputs.len());
        for input in &self.inputs {
            write_toccata_input(hasher, input, flags);
        }

        hasher.write_len(self.outputs.len());
        for output in &self.outputs {
            write_toccata_output(hasher, output);
        }

        hasher
            .update(self.lock_time.to_le_bytes())
            .update(self.subnetwork_id)
            .update(self.gas.to_le_bytes());
        if flags.contains(ToccataEncodingFlags::EXCLUDE_PAYLOAD) {
            hasher.write_var_bytes(&[]);
        } else {
            hasher.write_var_bytes(&self.payload);
        }

        if !flags.contains(ToccataEncodingFlags::EXCLUDE_MASS_COMMIT) {
            hasher.write_u64(self.mass);
        }
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ToccataEncodingFlags: u8 {
        const FULL = 0;
        const EXCLUDE_SIGNATURE_SCRIPT = 1 << 0;
        const EXCLUDE_MASS_COMMIT = 1 << 1;
        const EXCLUDE_PAYLOAD = 1 << 2;
    }
}

#[derive(Default)]
struct PreimageWriter {
    bytes: Vec<u8>,
}

impl PreimageWriter {
    fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

impl HasherBase for PreimageWriter {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self {
        self.bytes.extend_from_slice(data.as_ref());
        self
    }
}

trait ToccataHasherExt: HasherBase {
    fn write_len(&mut self, len: usize) -> &mut Self {
        self.update((len as u64).to_le_bytes())
    }

    fn write_bool(&mut self, value: bool) -> &mut Self {
        self.update([u8::from(value)])
    }

    fn write_u8(&mut self, value: u8) -> &mut Self {
        self.update([value])
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

impl<T: HasherBase> ToccataHasherExt for T {}

fn write_toccata_input<T: HasherBase>(
    hasher: &mut T,
    input: &ToccataTxInput,
    flags: ToccataEncodingFlags,
) {
    hash_toccata_outpoint(hasher, input.previous_outpoint);
    if flags.contains(ToccataEncodingFlags::EXCLUDE_SIGNATURE_SCRIPT) {
        hasher.write_var_bytes(&[]);
    } else {
        hasher.write_var_bytes(&input.signature_script);
    }
    hasher.update(input.sequence.to_le_bytes());

    if !flags.contains(ToccataEncodingFlags::EXCLUDE_MASS_COMMIT) {
        hasher.write_u16(input.compute_budget);
    }
}

fn hash_toccata_outpoint<T: HasherBase>(hasher: &mut T, outpoint: KaspaOutpoint) {
    hasher
        .update(outpoint.transaction_id)
        .write_u32(outpoint.index);
}

fn hash_toccata_script_public_key<T: HasherBase>(
    hasher: &mut T,
    script_public_key: &ToccataScriptPublicKey,
) {
    hasher
        .write_u16(script_public_key.version)
        .write_var_bytes(&script_public_key.script);
}

fn hash_toccata_output_for_sighash<T: HasherBase>(hasher: &mut T, output: &ToccataTxOutput) {
    hasher.write_u64(output.value);
    hash_toccata_script_public_key(hasher, &output.script_public_key);
    hasher.write_bool(output.covenant_binding.is_some());
    if let Some(binding) = output.covenant_binding {
        hasher
            .write_u16(binding.authorizing_input)
            .update(binding.covenant_id);
    }
}

fn write_toccata_output<T: HasherBase>(hasher: &mut T, output: &ToccataTxOutput) {
    hasher
        .update(output.value.to_le_bytes())
        .write_u16(output.script_public_key.version)
        .write_var_bytes(&output.script_public_key.script)
        .write_bool(output.covenant_binding.is_some());
    if let Some(binding) = output.covenant_binding {
        hasher
            .write_u16(binding.authorizing_input)
            .update(binding.covenant_id);
    }
}

fn write_borsh_len(out: &mut Vec<u8>, len: usize) {
    let len = u32::try_from(len).expect("Toccata v1 Borsh vector length exceeds u32");
    out.extend_from_slice(&len.to_le_bytes());
}

fn write_borsh_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_borsh_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_borsh_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_borsh_vec(out: &mut Vec<u8>, bytes: &[u8]) {
    write_borsh_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn write_borsh_toccata_input(out: &mut Vec<u8>, input: &ToccataTxInput) {
    out.extend_from_slice(&input.previous_outpoint.transaction_id);
    write_borsh_u32(out, input.previous_outpoint.index);
    write_borsh_vec(out, &input.signature_script);
    write_borsh_u64(out, input.sequence);
    out.push(1); // TxInputMass::ComputeBudget; v1 transactions cannot use SigopCount.
    write_borsh_u16(out, input.compute_budget);
}

fn write_borsh_toccata_output(out: &mut Vec<u8>, output: &ToccataTxOutput) {
    write_borsh_u64(out, output.value);
    write_borsh_u16(out, output.script_public_key.version);
    write_borsh_vec(out, &output.script_public_key.script);
    match output.covenant_binding {
        Some(binding) => {
            out.push(1);
            write_borsh_u16(out, binding.authorizing_input);
            out.extend_from_slice(&binding.covenant_id);
        }
        None => out.push(0),
    }
}

pub fn toccata_user_lane_subnetwork(
    namespace: [u8; SUBNETWORK_NAMESPACE_LEN],
) -> Result<ToccataSubnetworkId, TxBuildError> {
    let mut id = [0u8; SUBNETWORK_ID_SIZE];
    id[..SUBNETWORK_NAMESPACE_LEN].copy_from_slice(&namespace);
    if is_toccata_user_lane(id) {
        Ok(id)
    } else {
        Err(TxBuildError::InvalidToccataSubnetwork)
    }
}

pub fn validate_toccata_subnetwork(id: ToccataSubnetworkId) -> Result<(), TxBuildError> {
    if id == SUBNETWORK_ID_NATIVE || id == SUBNETWORK_ID_COINBASE || is_toccata_user_lane(id) {
        return Ok(());
    }
    Err(TxBuildError::InvalidToccataSubnetwork)
}

pub fn validate_toccata_gas(id: ToccataSubnetworkId, gas: u64) -> Result<(), TxBuildError> {
    if gas == 0 || is_toccata_user_lane(id) {
        return Ok(());
    }
    Err(TxBuildError::InvalidToccataGas)
}

pub fn is_toccata_user_lane(id: ToccataSubnetworkId) -> bool {
    id[SUBNETWORK_NAMESPACE_LEN..].iter().all(|byte| *byte == 0)
        && id[1..SUBNETWORK_NAMESPACE_LEN]
            .iter()
            .any(|byte| *byte != 0)
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

    pub fn into_toccata_v1(
        self,
        compute_budget: u16,
        subnetwork_id: ToccataSubnetworkId,
        gas: u64,
        mass: u64,
    ) -> Result<ToccataV1Tx, TxBuildError> {
        let inputs = self
            .inputs
            .into_iter()
            .map(|input| ToccataTxInput::from_unsigned(input, compute_budget))
            .collect();
        let outputs = self
            .outputs
            .into_iter()
            .map(ToccataTxOutput::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ToccataV1Tx::new(
            inputs,
            outputs,
            self.lock_time,
            subnetwork_id,
            gas,
            self.payload,
        )?
        .with_mass(mass))
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
    use kaspa_consensus_core::{
        constants::TX_VERSION_TOCCATA as UPSTREAM_TX_VERSION_TOCCATA,
        hashing::{
            sighash as upstream_sighash,
            sighash_type::{
                SIG_HASH_ALL as UPSTREAM_SIG_HASH_ALL,
                SIG_HASH_ANY_ONE_CAN_PAY as UPSTREAM_SIG_HASH_ANY_ONE_CAN_PAY,
                SIG_HASH_NONE as UPSTREAM_SIG_HASH_NONE,
                SIG_HASH_SINGLE as UPSTREAM_SIG_HASH_SINGLE,
            },
            tx as upstream_tx_hashing,
        },
        mass::ComputeBudget,
        subnets::SubnetworkId,
        tx::{
            CovenantBinding as UpstreamCovenantBinding,
            GenesisCovenantGroup as UpstreamGenesisCovenantGroup, PopulatedTransaction,
            ScriptPublicKey, Transaction as UpstreamTransaction,
            TransactionInput as UpstreamTransactionInput,
            TransactionOutpoint as UpstreamTransactionOutpoint,
            TransactionOutput as UpstreamTransactionOutput, TxInputMass as UpstreamTxInputMass,
            UtxoEntry as UpstreamUtxoEntry,
        },
    };
    use kaspa_hashes::Hash;
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

    fn sample_script_public_key() -> ToccataScriptPublicKey {
        ToccataScriptPublicKey::new(0, vec![0x51, 0x20, 0xaa])
    }

    fn sample_toccata_input(compute_budget: u16) -> ToccataTxInput {
        ToccataTxInput {
            previous_outpoint: KaspaOutpoint {
                transaction_id: [0x44; 32],
                index: 2,
            },
            signature_script: vec![0x01, 0x02],
            sequence: 7,
            compute_budget,
        }
    }

    fn sample_toccata_output() -> ToccataTxOutput {
        ToccataTxOutput::covenant(
            1_234,
            sample_script_public_key(),
            CovenantBinding {
                authorizing_input: 0,
                covenant_id: sample_covenant_id(),
            },
        )
    }

    fn sample_user_lane() -> ToccataSubnetworkId {
        toccata_user_lane_subnetwork([0, 0, 1, 0]).unwrap()
    }

    fn sample_toccata_v1() -> ToccataV1Tx {
        ToccataV1Tx::new(
            vec![sample_toccata_input(111)],
            vec![sample_toccata_output()],
            54,
            sample_user_lane(),
            3,
            vec![1, 2, 3],
        )
        .unwrap()
        .with_mass(5)
    }

    fn sample_toccata_previous_utxos() -> Vec<ToccataUtxoEntry> {
        vec![ToccataUtxoEntry::new(
            9_000,
            ToccataScriptPublicKey::new(0, vec![0x51, 0x20, 0xbb]),
        )]
    }

    fn to_upstream_tx(tx: &ToccataV1Tx) -> UpstreamTransaction {
        let inputs = tx
            .inputs
            .iter()
            .map(|input| {
                UpstreamTransactionInput::new_with_mass(
                    UpstreamTransactionOutpoint::new(
                        Hash::from_bytes(input.previous_outpoint.transaction_id),
                        input.previous_outpoint.index,
                    ),
                    input.signature_script.clone(),
                    input.sequence,
                    UpstreamTxInputMass::ComputeBudget(ComputeBudget(input.compute_budget)),
                )
            })
            .collect();
        let outputs = tx
            .outputs
            .iter()
            .map(|output| {
                UpstreamTransactionOutput::with_covenant(
                    output.value,
                    ScriptPublicKey::from_vec(
                        output.script_public_key.version,
                        output.script_public_key.script.clone(),
                    ),
                    output.covenant_binding.map(|binding| {
                        UpstreamCovenantBinding::new(
                            binding.authorizing_input,
                            Hash::from_bytes(binding.covenant_id),
                        )
                    }),
                )
            })
            .collect();
        UpstreamTransaction::new_with_mass(
            UPSTREAM_TX_VERSION_TOCCATA,
            inputs,
            outputs,
            tx.lock_time,
            SubnetworkId::from_bytes(tx.subnetwork_id),
            tx.gas,
            tx.payload.clone(),
            tx.mass,
        )
    }

    fn to_upstream_utxos(entries: &[ToccataUtxoEntry]) -> Vec<UpstreamUtxoEntry> {
        entries
            .iter()
            .map(|entry| {
                UpstreamUtxoEntry::new(
                    entry.amount,
                    ScriptPublicKey::from_vec(
                        entry.script_public_key.version,
                        entry.script_public_key.script.clone(),
                    ),
                    0,
                    false,
                    None,
                )
            })
            .collect()
    }

    #[test]
    fn toccata_v1_hashing_matches_upstream_consensus_core() {
        let tx = sample_toccata_v1();
        let upstream = to_upstream_tx(&tx);

        assert_eq!(tx.version(), UPSTREAM_TX_VERSION_TOCCATA);
        assert_eq!(tx.txid(), upstream.id().as_bytes());
        assert_eq!(tx.hash(), upstream_tx_hashing::hash(&upstream).as_bytes());
        assert_eq!(
            tx.rest_digest(),
            upstream_tx_hashing::v1_rest_digest(&upstream).as_bytes()
        );
        assert_eq!(
            tx.rest_preimage(),
            upstream_tx_hashing::transaction_v1_rest_preimage(&upstream)
        );
    }

    #[test]
    fn toccata_v1_borsh_wire_bytes_match_upstream_consensus_core() {
        let tx = sample_toccata_v1();
        let upstream = to_upstream_tx(&tx);

        assert_eq!(tx.storage_mass(), upstream.mass());
        assert_eq!(tx.to_borsh_bytes(), borsh::to_vec(&upstream).unwrap());
    }

    #[test]
    fn toccata_v1_borsh_wire_bytes_bind_unsigned_and_commitment_fields() {
        let base = sample_toccata_v1();
        let base_wire = base.to_borsh_bytes();

        let mut changed_signature = base.clone();
        changed_signature.inputs[0].signature_script.push(0xcc);
        assert_ne!(base_wire, changed_signature.to_borsh_bytes());
        assert_eq!(base.txid(), changed_signature.txid());

        let mut changed_compute_budget = base.clone();
        changed_compute_budget.inputs[0].compute_budget += 1;
        assert_ne!(base_wire, changed_compute_budget.to_borsh_bytes());
        assert_eq!(base.txid(), changed_compute_budget.txid());

        let changed_storage_mass = base.clone().with_storage_mass(base.storage_mass() + 1);
        assert_ne!(base_wire, changed_storage_mass.to_borsh_bytes());
        assert_eq!(base.txid(), changed_storage_mass.txid());

        let mut changed_payload = base.clone();
        changed_payload.payload.push(0xee);
        assert_ne!(base_wire, changed_payload.to_borsh_bytes());
        assert_ne!(base.txid(), changed_payload.txid());
    }

    #[test]
    fn toccata_v1_schnorr_sighash_matches_upstream_consensus_core() {
        let tx = sample_toccata_v1();
        let previous_utxos = sample_toccata_previous_utxos();
        let upstream_tx = to_upstream_tx(&tx);
        let upstream_utxos = to_upstream_utxos(&previous_utxos);
        let populated = PopulatedTransaction::new(&upstream_tx, upstream_utxos);

        let cases = [
            (SIG_HASH_ALL, UPSTREAM_SIG_HASH_ALL),
            (SIG_HASH_NONE, UPSTREAM_SIG_HASH_NONE),
            (SIG_HASH_SINGLE, UPSTREAM_SIG_HASH_SINGLE),
            (
                SIG_HASH_ALL | SIG_HASH_ANY_ONE_CAN_PAY,
                UPSTREAM_SIG_HASH_ALL | UPSTREAM_SIG_HASH_ANY_ONE_CAN_PAY,
            ),
        ];
        for (local_hash_type, upstream_hash_type) in cases {
            let local = tx
                .schnorr_signature_hash(0, &previous_utxos, local_hash_type)
                .unwrap();
            let reused_values = upstream_sighash::SigHashReusedValuesUnsync::new();
            let upstream = upstream_sighash::calc_schnorr_signature_hash(
                &populated,
                0,
                upstream_hash_type,
                &reused_values,
            );

            assert_eq!(local, upstream.as_bytes());
        }
    }

    #[test]
    fn toccata_v1_sighash_field_boundaries_are_fail_closed() {
        let base = sample_toccata_v1();
        let previous_utxos = sample_toccata_previous_utxos();
        let base_hash = base
            .schnorr_signature_hash(0, &previous_utxos, SIG_HASH_ALL)
            .unwrap();

        let mut unsigned_only_changes = base.clone();
        unsigned_only_changes.inputs[0].signature_script = vec![0xaa, 0xbb, 0xcc];
        unsigned_only_changes.inputs[0].compute_budget = 999;
        unsigned_only_changes.mass = 42;
        assert_eq!(
            base_hash,
            unsigned_only_changes
                .schnorr_signature_hash(0, &previous_utxos, SIG_HASH_ALL)
                .unwrap()
        );

        let mut changed_sequence = base.clone();
        changed_sequence.inputs[0].sequence += 1;
        assert_ne!(
            base_hash,
            changed_sequence
                .schnorr_signature_hash(0, &previous_utxos, SIG_HASH_ALL)
                .unwrap()
        );

        let mut changed_utxo = previous_utxos.clone();
        changed_utxo[0].amount += 1;
        assert_ne!(
            base_hash,
            base.schnorr_signature_hash(0, &changed_utxo, SIG_HASH_ALL)
                .unwrap()
        );

        let mut changed_covenant_output = base.clone();
        changed_covenant_output.outputs[0]
            .covenant_binding
            .as_mut()
            .unwrap()
            .covenant_id = [0x99; 32];
        assert_ne!(
            base_hash,
            changed_covenant_output
                .schnorr_signature_hash(0, &previous_utxos, SIG_HASH_ALL)
                .unwrap()
        );

        assert!(matches!(
            ToccataSigHashType::from_u8(0x7f),
            Err(TxBuildError::InvalidToccataSigHashType(0x7f))
        ));
        assert!(matches!(
            base.schnorr_signature_hash(0, &previous_utxos, SIG_HASH_NONE | SIG_HASH_SINGLE),
            Err(TxBuildError::InvalidToccataSigHashType(0x06))
        ));
        assert!(matches!(
            base.schnorr_signature_hash(1, &previous_utxos, SIG_HASH_ALL),
            Err(TxBuildError::ToccataSigHashInputOutOfBounds {
                input_index: 1,
                input_count: 1
            })
        ));
        assert!(matches!(
            base.schnorr_signature_hash(0, &[], SIG_HASH_ALL),
            Err(TxBuildError::MissingToccataSigHashUtxo { input_index: 0 })
        ));
    }

    #[test]
    fn toccata_v1_txid_excludes_signature_compute_budget_and_mass() {
        let base = sample_toccata_v1();
        let mut changed = base.clone();
        changed.inputs[0].signature_script = vec![0xaa, 0xbb, 0xcc];
        changed.inputs[0].compute_budget = 999;
        changed.mass = 42;

        assert_eq!(base.txid(), changed.txid());
        assert_eq!(base.rest_digest(), changed.rest_digest());
        assert_ne!(base.hash(), changed.hash());

        let mut changed_payload = base.clone();
        changed_payload.payload.push(0xff);
        assert_ne!(base.txid(), changed_payload.txid());
        assert_eq!(base.rest_digest(), changed_payload.rest_digest());
        assert_ne!(base.hash(), changed_payload.hash());
    }

    #[test]
    fn toccata_genesis_covenant_groups_match_upstream_population() {
        let mut tx = ToccataV1Tx::new(
            vec![sample_toccata_input(111)],
            vec![
                ToccataTxOutput::new(1_000, sample_script_public_key()),
                ToccataTxOutput::new(2_000, ToccataScriptPublicKey::new(0, vec![0x52])),
                ToccataTxOutput::new(3_000, ToccataScriptPublicKey::new(0, vec![0x53])),
            ],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        )
        .unwrap();
        let mut upstream = to_upstream_tx(&tx);

        tx.populate_genesis_covenants(&[ToccataGenesisCovenantGroup::new(0, vec![0, 2])])
            .unwrap();
        upstream
            .populate_genesis_covenants(&[UpstreamGenesisCovenantGroup::new(0, vec![0, 2])])
            .unwrap();

        assert_eq!(
            tx.outputs[0].covenant_binding.unwrap().covenant_id,
            upstream.outputs[0].covenant.unwrap().covenant_id.as_bytes()
        );
        assert_eq!(
            tx.outputs[0].covenant_binding,
            tx.outputs[2].covenant_binding
        );
        assert_eq!(tx.outputs[1].covenant_binding, None);
        assert_eq!(
            tx.outputs[2].covenant_binding.unwrap().covenant_id,
            upstream.outputs[2].covenant.unwrap().covenant_id.as_bytes()
        );
        assert_eq!(upstream.outputs[1].covenant, None);
    }

    #[test]
    fn toccata_genesis_covenant_groups_fail_closed() {
        let mut tx = ToccataV1Tx::new(
            vec![sample_toccata_input(111)],
            vec![
                ToccataTxOutput::new(1_000, sample_script_public_key()),
                ToccataTxOutput::new(2_000, ToccataScriptPublicKey::new(0, vec![0x52])),
            ],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        )
        .unwrap();

        assert!(matches!(
            tx.populate_genesis_covenants(&[ToccataGenesisCovenantGroup::new(0, vec![])]),
            Err(TxBuildError::InvalidToccataCovenantGroup { .. })
        ));
        assert!(matches!(
            tx.populate_genesis_covenants(&[ToccataGenesisCovenantGroup::new(0, vec![1, 0])]),
            Err(TxBuildError::InvalidToccataCovenantGroup { .. })
        ));
        assert!(matches!(
            tx.populate_genesis_covenants(&[
                ToccataGenesisCovenantGroup::new(0, vec![0]),
                ToccataGenesisCovenantGroup::new(0, vec![0])
            ]),
            Err(TxBuildError::InvalidToccataCovenantGroup { .. })
        ));

        tx.populate_genesis_covenants(&[ToccataGenesisCovenantGroup::new(0, vec![0])])
            .unwrap();
        assert!(matches!(
            tx.populate_genesis_covenants(&[ToccataGenesisCovenantGroup::new(0, vec![0])]),
            Err(TxBuildError::InvalidToccataCovenantGroup { .. })
        ));
    }

    #[test]
    fn toccata_subnetwork_and_gas_rules_fail_closed() {
        assert!(toccata_user_lane_subnetwork([0, 0, 1, 0]).is_ok());
        assert!(matches!(
            toccata_user_lane_subnetwork([0, 0, 0, 0]),
            Err(TxBuildError::InvalidToccataSubnetwork)
        ));
        assert!(matches!(
            toccata_user_lane_subnetwork([2, 0, 0, 0]),
            Err(TxBuildError::InvalidToccataSubnetwork)
        ));
        assert!(matches!(
            ToccataV1Tx::new(
                vec![sample_toccata_input(1)],
                vec![sample_toccata_output()],
                0,
                SUBNETWORK_ID_NATIVE,
                1,
                vec![]
            ),
            Err(TxBuildError::InvalidToccataGas)
        ));
        assert!(ToccataV1Tx::new(
            vec![sample_toccata_input(1)],
            vec![sample_toccata_output()],
            0,
            sample_user_lane(),
            1,
            vec![]
        )
        .is_ok());
    }

    #[test]
    fn unsigned_tx_promotes_to_toccata_v1_with_compute_budget() {
        let output = TxOutput::covenant(
            1000,
            sample_script_public_key().to_versioned_bytes(),
            CovenantBinding {
                authorizing_input: 0,
                covenant_id: sample_covenant_id(),
            },
        );
        let tx = UnsignedTx {
            inputs: vec![TxInput::new(KaspaOutpoint {
                transaction_id: [0x55; 32],
                index: 1,
            })],
            outputs: vec![output],
            payload: vec![0x77],
            lock_time: 9,
        };
        let toccata = tx
            .into_toccata_v1(300, SUBNETWORK_ID_NATIVE, 0, 12_345)
            .unwrap();

        assert_eq!(toccata.version(), TX_VERSION_TOCCATA);
        assert_eq!(toccata.inputs[0].compute_budget, 300);
        assert_eq!(
            toccata.outputs[0].script_public_key,
            sample_script_public_key()
        );
        assert_eq!(toccata.payload, vec![0x77]);
        assert_eq!(toccata.mass, 12_345);
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
