#![cfg(feature = "live-kaspa-wrpc")]

use kaspa_consensus_core::{
    constants::TX_VERSION_TOCCATA,
    hashing::sighash::SigHashReusedValuesUnsync,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput,
        TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
#[cfg(feature = "real-zk")]
use kaspa_consensus_core::{mass::ComputeBudget, tx::TxInputMass};
use kaspa_hashes::Hash;
#[cfg(feature = "real-zk")]
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{
    caches::Cache, covenants::CovenantsContext, pay_to_script_hash_script,
    pay_to_script_hash_signature_script_with_flags, EngineCtx, EngineFlags, TxScriptEngine,
};

#[cfg(feature = "real-zk")]
use rgk_core::{receipt_commitment, RgkReceipt, RgkStateCommitment};
use rgk_core::{ProofMode, ReceiptPolicy, KASPA_LOCAL_TOCCATA};
use rgk_covenant::{
    compute_covenant_id_from_lineage, CovenantContinuationPolicy, CovenantSharedContinuationPolicy,
    CovenantSpec, CovenantState,
};

#[cfg(feature = "real-zk")]
use rgk_zk::real_zk::{self, Groth16PrecompileStack, ReceiptCircuit};

fn sample_spec() -> CovenantSpec {
    CovenantSpec {
        chain_id: KASPA_LOCAL_TOCCATA,
        lineage_id: [0x11; 32],
        asset_id: [0x22; 32],
        initial_state_digest: [0x33; 32],
        receipt_policy: ReceiptPolicy::VerifierOnly,
        genesis_proof_mode: ProofMode::VerifierReceipt,
    }
}

fn covenant_hash(spec: &CovenantSpec) -> Hash {
    Hash::from_bytes(compute_covenant_id_from_lineage(spec.lineage_id))
}

fn transition_payload(spec: &CovenantSpec) -> Vec<u8> {
    CovenantState {
        version: rgk_core::ENCODING_VERSION,
        chain_id: spec.chain_id,
        lineage_id: spec.lineage_id,
        asset_id: spec.asset_id,
        current_state_digest: [0x44; 32],
        receipt_policy: spec.receipt_policy,
        genesis_proof_mode: spec.genesis_proof_mode,
        replay_marker: [0x55; 32],
    }
    .encode_payload()
}

#[cfg(feature = "real-zk")]
fn zk_receipt_for_spec(spec: &CovenantSpec, covenant_id: [u8; 32]) -> RgkReceipt {
    RgkReceipt {
        version: rgk_core::ENCODING_VERSION,
        chain_id: spec.chain_id,
        covenant_id,
        old_state: RgkStateCommitment {
            version: rgk_core::ENCODING_VERSION,
            chain_id: spec.chain_id,
            covenant_id,
            asset_id: spec.asset_id,
            state_digest: spec.initial_state_digest,
            receipt_policy: spec.receipt_policy,
        },
        new_state: RgkStateCommitment {
            version: rgk_core::ENCODING_VERSION,
            chain_id: spec.chain_id,
            covenant_id,
            asset_id: spec.asset_id,
            state_digest: [0x44; 32],
            receipt_policy: spec.receipt_policy,
        },
        transition_digest: [0x66; 32],
        continuation_commitment: [0x88; 32],
        proof_mode: spec.genesis_proof_mode,
        replay_nonce: [0x77; 32],
    }
}

#[cfg(feature = "real-zk")]
fn fixture_zk_receipt_for_setup(spec: &CovenantSpec) -> RgkReceipt {
    zk_receipt_for_spec(spec, [0x99; 32])
}

#[cfg(feature = "real-zk")]
fn zk_precompile_stack_for_spec(
    spec: &CovenantSpec,
    covenant_id: [u8; 32],
) -> Groth16PrecompileStack {
    let setup_circuit = ReceiptCircuit::from_receipt(
        &fixture_zk_receipt_for_setup(spec),
        receipt_commitment(&fixture_zk_receipt_for_setup(spec)),
    );
    let setup = real_zk::setup(&setup_circuit).expect("fixture same-shape Groth16 setup");
    let receipt = zk_receipt_for_spec(spec, covenant_id);
    let receipt_id = receipt_commitment(&receipt);
    let circuit = ReceiptCircuit::from_receipt(&receipt, receipt_id);
    let proof = real_zk::prove(&setup.pk, circuit.clone()).expect("actual receipt proof");
    real_zk::groth16_precompile_stack(&setup.vk, &proof, &circuit.public_inputs)
        .expect("Toccata Groth16 stack")
}

#[cfg(feature = "real-zk")]
fn prepend_zk_to_redeem_script(covenant_script: &[u8], stack: &Groth16PrecompileStack) -> Vec<u8> {
    let mut redeem_script = Vec::new();
    rgk_covenant::push_data(&mut redeem_script, &stack.verifying_key);
    rgk_covenant::push_data(&mut redeem_script, &stack.tag);
    redeem_script.push(rgk_covenant::opcodes::OP_ZK_PRECOMPILE);
    redeem_script.push(rgk_covenant::opcodes::OP_DROP);
    redeem_script.extend_from_slice(covenant_script);
    redeem_script
}

#[cfg(feature = "real-zk")]
fn zk_signature_prefix(stack: &Groth16PrecompileStack, flags: EngineFlags) -> Vec<u8> {
    let mut signature = ScriptBuilder::with_flags(flags);
    for input in stack.public_inputs.iter().rev() {
        signature.add_data(input).expect("public input push");
    }
    signature
        .add_i64(stack.public_input_count() as i64)
        .expect("public input count push")
        .add_data(&stack.proof)
        .expect("proof push");
    signature.drain()
}

fn run_redeem_script(
    spec: &CovenantSpec,
    output: TransactionOutput,
    payload: Vec<u8>,
) -> Result<(), String> {
    run_redeem_script_with_policy(
        spec,
        &CovenantContinuationPolicy::singleton(),
        vec![output],
        payload,
    )
}

fn run_redeem_script_with_policy(
    spec: &CovenantSpec,
    policy: &CovenantContinuationPolicy,
    outputs: Vec<TransactionOutput>,
    payload: Vec<u8>,
) -> Result<(), String> {
    let redeem_script = spec
        .build_script_for_policy(policy)
        .expect("RGK covenant script");
    let spk = pay_to_script_hash_script(&redeem_script);
    let flags = EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    };
    let sig_script = pay_to_script_hash_signature_script_with_flags(redeem_script, vec![], flags)
        .expect("P2SH signature script");
    let previous_outpoint = TransactionOutpoint::new(Hash::from_u64_word(1), 0);
    let input = TransactionInput::new_with_compute_budget(previous_outpoint, sig_script, 0, 300);
    let tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![input],
        outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        payload,
    );
    let utxo = UtxoEntry::new(1_000_000, spk, 0, false, Some(covenant_hash(spec)));
    let populated = PopulatedTransaction::new(&tx, vec![utxo.clone()]);
    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);
    let mut vm =
        TxScriptEngine::from_transaction_input(&populated, &tx.inputs[0], 0, &utxo, ctx, flags);
    vm.execute().map_err(|e| format!("{e:?}"))
}

fn covenant_output(value: u64, spk: ScriptPublicKey, spec: &CovenantSpec) -> TransactionOutput {
    TransactionOutput::with_covenant(
        value,
        spk,
        Some(CovenantBinding::new(0, covenant_hash(spec))),
    )
}

fn run_shared_redeem_script_for_input(
    spec: &CovenantSpec,
    policy: &CovenantSharedContinuationPolicy,
    input_count: usize,
    input_index: usize,
    outputs: Vec<TransactionOutput>,
    payload: Vec<u8>,
) -> Result<(), String> {
    let redeem_script = spec
        .build_script_for_shared_policy(policy)
        .expect("RGK shared covenant script");
    let spk = pay_to_script_hash_script(&redeem_script);
    let flags = EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    };
    let sig_script = pay_to_script_hash_signature_script_with_flags(redeem_script, vec![], flags)
        .expect("P2SH signature script");
    let mut inputs = Vec::new();
    let mut utxos = Vec::new();
    for i in 0..input_count {
        let input = TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(Hash::from_u64_word((i + 1) as u64), 0),
            sig_script.clone(),
            0,
            500,
        );
        inputs.push(input);
        utxos.push(UtxoEntry::new(
            1_000_000,
            spk.clone(),
            0,
            false,
            Some(covenant_hash(spec)),
        ));
    }
    let tx = Transaction::new(
        TX_VERSION_TOCCATA,
        inputs,
        outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        payload,
    );
    let populated = PopulatedTransaction::new(&tx, utxos.clone());
    let covenants_ctx = CovenantsContext::from_tx(&populated).map_err(|e| format!("{e:?}"))?;
    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache)
        .with_reused(&reused_values)
        .with_covenants_ctx(&covenants_ctx);
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &tx.inputs[input_index],
        input_index,
        &utxos[input_index],
        ctx,
        flags,
    );
    vm.execute().map_err(|e| format!("{e:?}"))
}

#[cfg(feature = "real-zk")]
fn run_zk_redeem_script(
    spec: &CovenantSpec,
    output: TransactionOutput,
    payload: Vec<u8>,
) -> Result<u64, String> {
    let covenant_id = covenant_hash(spec);
    let stack = zk_precompile_stack_for_spec(spec, covenant_id.as_bytes());
    let covenant_script = spec.build_script().expect("RGK covenant script");
    let redeem_script = prepend_zk_to_redeem_script(&covenant_script, &stack);
    let spk = pay_to_script_hash_script(&redeem_script);
    let flags = EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    };
    let sig_script = pay_to_script_hash_signature_script_with_flags(
        redeem_script,
        zk_signature_prefix(&stack, flags),
        flags,
    )
    .expect("P2SH ZK signature script");
    let previous_outpoint = TransactionOutpoint::new(Hash::from_u64_word(1), 0);
    let input = TransactionInput::new_with_compute_budget(previous_outpoint, sig_script, 0, 2_500);
    let tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![input],
        vec![output],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        payload,
    );
    let utxo = UtxoEntry::new(1_000_000, spk, 0, false, Some(covenant_id));
    let populated = PopulatedTransaction::new(&tx, vec![utxo.clone()]);
    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);
    let limit = tx.inputs[0].mass.allowed_script_units();
    let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        &tx.inputs[0],
        0,
        &utxo,
        ctx,
        flags,
        limit,
    );
    vm.execute().map_err(|e| format!("{e:?}"))?;
    Ok(vm.used_script_units().0)
}

#[test]
fn covenant_spec_script_executes_in_upstream_vm() {
    let spec = sample_spec();
    let redeem_script = spec.build_script().expect("RGK covenant script");
    let spk = pay_to_script_hash_script(&redeem_script);
    let output = TransactionOutput::with_covenant(
        900_000,
        spk,
        Some(CovenantBinding::new(0, covenant_hash(&spec))),
    );

    run_redeem_script(&spec, output, transition_payload(&spec)).expect("VM accepts RGK script");
}

#[test]
fn covenant_spec_policy_script_accepts_fanout_with_explicit_change_output() {
    let spec = sample_spec();
    let policy = CovenantContinuationPolicy::new(0, 3, vec![0, 2]).unwrap();
    let redeem_script = spec
        .build_script_for_policy(&policy)
        .expect("RGK covenant script");
    let spk = pay_to_script_hash_script(&redeem_script);
    let change_spk = pay_to_script_hash_script(&[rgk_covenant::opcodes::OP_DROP, 0x51]);
    let outputs = vec![
        covenant_output(450_000, spk.clone(), &spec),
        TransactionOutput::new(50_000, change_spk),
        covenant_output(400_000, spk, &spec),
    ];

    run_redeem_script_with_policy(&spec, &policy, outputs, transition_payload(&spec))
        .expect("VM accepts explicit two-output continuation policy");
}

#[test]
fn covenant_spec_policy_script_rejects_missing_declared_continuation_output() {
    let spec = sample_spec();
    let policy = CovenantContinuationPolicy::new(0, 3, vec![0, 2]).unwrap();
    let redeem_script = spec
        .build_script_for_policy(&policy)
        .expect("RGK covenant script");
    let spk = pay_to_script_hash_script(&redeem_script);
    let change_spk = pay_to_script_hash_script(&[rgk_covenant::opcodes::OP_DROP, 0x51]);
    let outputs = vec![
        covenant_output(450_000, spk, &spec),
        TransactionOutput::new(50_000, change_spk.clone()),
        TransactionOutput::new(400_000, change_spk),
    ];

    let err = run_redeem_script_with_policy(&spec, &policy, outputs, transition_payload(&spec))
        .expect_err("VM rejects a declared continuation output without covenant binding");
    assert!(
        err.contains("VerifyError"),
        "unexpected txscript error: {err}"
    );
}

#[test]
fn covenant_shared_policy_script_accepts_two_input_merge_with_change_output() {
    let spec = sample_spec();
    let policy = CovenantSharedContinuationPolicy::new(2, 1, 2).unwrap();
    let redeem_script = spec
        .build_script_for_shared_policy(&policy)
        .expect("RGK shared covenant script");
    let spk = pay_to_script_hash_script(&redeem_script);
    let change_spk = pay_to_script_hash_script(&[rgk_covenant::opcodes::OP_DROP, 0x51]);
    let outputs = vec![
        covenant_output(1_700_000, spk, &spec),
        TransactionOutput::new(100_000, change_spk),
    ];

    for input_index in 0..2 {
        run_shared_redeem_script_for_input(
            &spec,
            &policy,
            2,
            input_index,
            outputs.clone(),
            transition_payload(&spec),
        )
        .expect("VM accepts shared two-input merge policy");
    }
}

#[test]
fn covenant_shared_policy_script_accepts_two_input_two_output_batch_with_change() {
    let spec = sample_spec();
    let policy = CovenantSharedContinuationPolicy::new(2, 2, 3).unwrap();
    let redeem_script = spec
        .build_script_for_shared_policy(&policy)
        .expect("RGK shared covenant script");
    let spk = pay_to_script_hash_script(&redeem_script);
    let change_spk = pay_to_script_hash_script(&[rgk_covenant::opcodes::OP_DROP, 0x51]);
    let outputs = vec![
        covenant_output(800_000, spk.clone(), &spec),
        TransactionOutput::new(100_000, change_spk),
        covenant_output(900_000, spk, &spec),
    ];

    for input_index in 0..2 {
        run_shared_redeem_script_for_input(
            &spec,
            &policy,
            2,
            input_index,
            outputs.clone(),
            transition_payload(&spec),
        )
        .expect("VM accepts shared two-input batch policy");
    }
}

#[test]
fn covenant_shared_policy_script_rejects_missing_shared_covenant_output() {
    let spec = sample_spec();
    let policy = CovenantSharedContinuationPolicy::new(2, 2, 3).unwrap();
    let redeem_script = spec
        .build_script_for_shared_policy(&policy)
        .expect("RGK shared covenant script");
    let spk = pay_to_script_hash_script(&redeem_script);
    let change_spk = pay_to_script_hash_script(&[rgk_covenant::opcodes::OP_DROP, 0x51]);
    let outputs = vec![
        covenant_output(800_000, spk, &spec),
        TransactionOutput::new(100_000, change_spk.clone()),
        TransactionOutput::new(900_000, change_spk),
    ];

    let err = run_shared_redeem_script_for_input(
        &spec,
        &policy,
        2,
        0,
        outputs,
        transition_payload(&spec),
    )
    .expect_err("VM rejects missing shared covenant output");
    assert!(
        err.contains("VerifyError"),
        "unexpected txscript error: {err}"
    );
}

#[test]
fn covenant_spec_script_rejects_wrong_contract_payload() {
    let spec = sample_spec();
    let redeem_script = spec.build_script().expect("RGK covenant script");
    let spk = pay_to_script_hash_script(&redeem_script);
    let output = TransactionOutput::with_covenant(
        900_000,
        spk,
        Some(CovenantBinding::new(0, covenant_hash(&spec))),
    );
    let mut bad_spec = spec.clone();
    bad_spec.asset_id = [0x99; 32];

    let err = run_redeem_script(&spec, output, transition_payload(&bad_spec))
        .expect_err("VM rejects payload with a different RGK asset id");
    assert!(
        err.contains("VerifyError"),
        "unexpected txscript error: {err}"
    );
}

#[cfg(feature = "real-zk")]
#[test]
fn covenant_spec_script_with_groth16_precompile_executes_in_upstream_vm() {
    let spec = CovenantSpec {
        receipt_policy: ReceiptPolicy::ZkOrVerifier,
        genesis_proof_mode: ProofMode::ZkReceipt,
        ..sample_spec()
    };
    let covenant_id = covenant_hash(&spec);
    let covenant_script = spec.build_script().expect("RGK covenant script");
    let stack = zk_precompile_stack_for_spec(&spec, covenant_id.as_bytes());
    let redeem_script = prepend_zk_to_redeem_script(&covenant_script, &stack);
    let spk = pay_to_script_hash_script(&redeem_script);
    let output =
        TransactionOutput::with_covenant(900_000, spk, Some(CovenantBinding::new(0, covenant_id)));

    let used = run_zk_redeem_script(&spec, output, transition_payload(&spec))
        .expect("VM accepts RGK covenant script prefixed by Groth16 precompile");
    eprintln!("[zk-covenant-vm] used_script_units={used}");
    let allowed = TxInputMass::from(ComputeBudget(2_500))
        .allowed_script_units()
        .0;
    assert!(used < allowed);
}
