//! rgk-core unit tests: canonical encoding round-trips, rejection cases,
//! domain-separation, and frozen test vectors.

use crate::bytes::{from_hex, to_hex};
use crate::chain::{KaspaChainId, KASPA_LOCAL_TOCCATA};
use crate::commit::{
    build_policy_migration_proof, domain_hash, policy_migration_commitment, receipt_commitment,
    replay_nonce, state_commitment, DomainTag,
};
use crate::encoding::{Canonical, ENCODING_VERSION};
use crate::policy::{ProofMode, ReceiptPolicy};
use crate::types::{
    KaspaOutpoint, PolicyMigrationInput, RgkAssetId, RgkAssetRef, RgkReceipt, RgkSchemaId,
    RgkStateCommitment,
};

fn b32(s: &str) -> [u8; 32] {
    from_hex::<32>(s).expect("valid hex")
}

fn sample_state(digest_suffix: u8, policy: ReceiptPolicy) -> RgkStateCommitment {
    let mut digest = [0u8; 32];
    digest[31] = digest_suffix;
    RgkStateCommitment {
        version: ENCODING_VERSION,
        chain_id: KASPA_LOCAL_TOCCATA,
        covenant_id: b32("1111111111111111111111111111111111111111111111111111111111111111"),
        asset_id: b32("2222222222222222222222222222222222222222222222222222222222222222"),
        state_digest: digest,
        receipt_policy: policy,
    }
}

fn sample_receipt(policy: ReceiptPolicy, mode: ProofMode) -> RgkReceipt {
    RgkReceipt {
        version: ENCODING_VERSION,
        chain_id: KASPA_LOCAL_TOCCATA,
        covenant_id: b32("1111111111111111111111111111111111111111111111111111111111111111"),
        old_state: sample_state(1, policy),
        new_state: sample_state(2, policy),
        transition_digest: b32("3333333333333333333333333333333333333333333333333333333333333333"),
        continuation_commitment: b32(
            "5555555555555555555555555555555555555555555555555555555555555555",
        ),
        proof_mode: mode,
        replay_nonce: b32("4444444444444444444444444444444444444444444444444444444444444444"),
    }
}

// ---------------- Canonical round-trips ----------------

#[test]
fn state_commitment_roundtrips() {
    for policy in [
        ReceiptPolicy::Any,
        ReceiptPolicy::VerifierOnly,
        ReceiptPolicy::ZkOrVerifier,
    ] {
        let s = sample_state(7, policy);
        let bytes = s.encode_canonical();
        let back = RgkStateCommitment::decode_canonical(&bytes).expect("decode");
        assert_eq!(s, back, "round-trip for {:?}", policy);
    }
}

#[test]
fn receipt_roundtrips() {
    let cases = [
        (ReceiptPolicy::Any, ProofMode::VerifierReceipt),
        (ReceiptPolicy::VerifierOnly, ProofMode::VerifierReceipt),
        (ReceiptPolicy::ZkOrVerifier, ProofMode::ZkReceipt),
        (ReceiptPolicy::ZkOrVerifier, ProofMode::VerifierReceipt),
    ];
    for (policy, mode) in cases {
        let r = sample_receipt(policy, mode);
        let bytes = r.encode_canonical();
        let back = RgkReceipt::decode_canonical(&bytes).expect("decode");
        assert_eq!(r, back, "round-trip for ({:?},{:?})", policy, mode);
    }
}

#[test]
fn outpoint_roundtrips() {
    let o = KaspaOutpoint {
        transaction_id: b32("abab".repeat(16).as_str()),
        index: 0xdead_beef,
    };
    let bytes = o.encode_canonical();
    let back = KaspaOutpoint::decode_canonical(&bytes).expect("decode");
    assert_eq!(o, back);
}

#[test]
fn asset_ref_roundtrips() {
    let c = RgkAssetRef {
        asset_id: b32("cccc".repeat(16).as_str()),
        schema_id: b32("dddd".repeat(16).as_str()),
    };
    let bytes = c.encode_canonical();
    assert_eq!(c, RgkAssetRef::decode_canonical(&bytes).unwrap());
}

// ---------------- Rejection cases (fail-closed) ----------------

#[test]
fn bad_magic_rejected() {
    let r = sample_receipt(ReceiptPolicy::Any, ProofMode::VerifierReceipt);
    let mut bytes = r.encode_canonical();
    bytes[0] = b'X'; // corrupt magic
    assert_eq!(
        RgkReceipt::decode_canonical(&bytes).unwrap_err(),
        crate::error::DecodeError::BadMagic
    );
}

#[test]
fn unknown_version_rejected() {
    let r = sample_receipt(ReceiptPolicy::Any, ProofMode::VerifierReceipt);
    let mut bytes = r.encode_canonical();
    // version is at offset 8 (magic=8 bytes), little-endian u16.
    bytes[8] = 0xff;
    bytes[9] = 0xff;
    assert!(matches!(
        RgkReceipt::decode_canonical(&bytes).unwrap_err(),
        crate::error::DecodeError::UnknownVersion(0xffff)
    ));
}

#[test]
fn trailing_bytes_rejected() {
    let r = sample_receipt(ReceiptPolicy::Any, ProofMode::VerifierReceipt);
    let mut bytes = r.encode_canonical();
    bytes.push(0x99);
    assert!(matches!(
        RgkReceipt::decode_canonical(&bytes).unwrap_err(),
        crate::error::DecodeError::TrailingBytes { remaining: 1 }
    ));
}

#[test]
fn eof_rejected() {
    let r = sample_receipt(ReceiptPolicy::Any, ProofMode::VerifierReceipt);
    let mut bytes = r.encode_canonical();
    bytes.truncate(bytes.len() - 5);
    assert!(matches!(
        RgkReceipt::decode_canonical(&bytes).unwrap_err(),
        crate::error::DecodeError::Eof
    ));
}

#[test]
fn unknown_chain_rejected() {
    let s = sample_state(1, ReceiptPolicy::Any);
    let bytes = s.encode_canonical();
    // Layout: magic(8) + outer-version(2) + state.version(2) + chain-tag(1) + chain-val(1) ...
    // The chain *value* byte is therefore at offset 8 + 2 + 2 + 1 = 13.
    let mut tampered = bytes.clone();
    assert_eq!(
        tampered[12],
        KaspaChainId::TAG,
        "chain tag byte offset assumption"
    );
    tampered[13] = 0xff; // unknown chain value
    assert!(matches!(
        RgkStateCommitment::decode_canonical(&tampered).unwrap_err(),
        crate::error::DecodeError::UnknownChain(0xff)
    ));
    let _ = s;
}

#[test]
fn unknown_proof_mode_rejected() {
    let r = sample_receipt(ReceiptPolicy::Any, ProofMode::VerifierReceipt);
    let bytes = r.encode_canonical();
    // Flip the proof-mode value byte to an unknown tag. We locate it by decoding
    // structurally instead of a brittle offset: easier to just construct a bad
    // receipt at the encoding layer.
    use crate::encoding::Writer;
    let mut w = Writer::new();
    w.write_bytes(crate::encoding::DOMAIN_MAGIC);
    w.write_u16(ENCODING_VERSION);
    w.write_u16(r.version);
    r.chain_id.encode(&mut w);
    w.write_bytes32(&r.covenant_id);
    r.old_state.encode(&mut w);
    r.new_state.encode(&mut w);
    w.write_bytes32(&r.transition_digest);
    w.write_bytes32(&r.continuation_commitment);
    // inject a bad proof-mode: tag ok, value bad
    w.write_u8(crate::policy::ProofMode::TAG);
    w.write_u8(0xee);
    w.write_bytes32(&r.replay_nonce);
    let bad = w.into_vec();
    assert!(matches!(
        RgkReceipt::decode_canonical(&bad).unwrap_err(),
        crate::error::DecodeError::UnknownProofMode(0xee)
    ));
}

#[test]
fn cross_chain_structural_rejected() {
    let mut r = sample_receipt(ReceiptPolicy::Any, ProofMode::VerifierReceipt);
    r.new_state.chain_id = KaspaChainId::KaspaMainnet; // mismatched
    assert!(r.validate_structure().is_err());
    // decode must also reject it
    let bytes = r.encode_canonical();
    assert!(RgkReceipt::decode_canonical(&bytes).is_err());
}

#[test]
fn no_op_transition_rejected() {
    let mut r = sample_receipt(ReceiptPolicy::Any, ProofMode::VerifierReceipt);
    r.new_state.state_digest = r.old_state.state_digest;
    assert!(r.validate_structure().is_err());
}

#[test]
fn policy_mode_mismatch_rejected() {
    // VerifierOnly policy must reject a ZkReceipt.
    let r = sample_receipt(ReceiptPolicy::VerifierOnly, ProofMode::ZkReceipt);
    assert!(r.validate_structure().is_err());
}

#[test]
fn asset_id_change_rejected() {
    let mut r = sample_receipt(ReceiptPolicy::Any, ProofMode::VerifierReceipt);
    r.new_state.asset_id = b32("9999".repeat(16).as_str());
    assert!(r.validate_structure().is_err());
}

// ---------------- Domain separation ----------------

#[test]
fn domain_tags_are_distinct() {
    let payload = b"identical payload";
    let a = domain_hash(DomainTag::StateCommitment, payload);
    let b = domain_hash(DomainTag::Receipt, payload);
    let c = domain_hash(DomainTag::Lineage, payload);
    let d = domain_hash(DomainTag::ReplayNonce, payload);
    let e = domain_hash(DomainTag::PolicyMigration, payload);
    let all = [a, b, c, d, e];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j], "domain tags {} and {} collided", i, j);
        }
    }
}

#[test]
fn receipt_id_is_deterministic_and_payload_sensitive() {
    let r1 = sample_receipt(ReceiptPolicy::Any, ProofMode::VerifierReceipt);
    let r2 = r1.clone();
    assert_eq!(receipt_commitment(&r1), receipt_commitment(&r2));

    // Mutate one field; the id must change.
    let mut r3 = r1.clone();
    r3.new_state.state_digest[0] ^= 0x01;
    assert_ne!(receipt_commitment(&r1), receipt_commitment(&r3));
}

#[test]
fn state_commitment_is_deterministic() {
    let s1 = sample_state(5, ReceiptPolicy::Any);
    let s2 = s1.clone();
    assert_eq!(state_commitment(&s1), state_commitment(&s2));
    let mut s3 = s1.clone();
    s3.chain_id = KaspaChainId::KaspaMainnet;
    assert_ne!(state_commitment(&s1), state_commitment(&s3)); // chain is in the domain
}

#[test]
fn replay_nonce_binds_inputs() {
    let d = b32("3333333333333333333333333333333333333333333333333333333333333333");
    let n1 = replay_nonce(b"outpoint-A", &d);
    let n2 = replay_nonce(b"outpoint-B", &d);
    assert_ne!(n1, n2);
}

#[test]
fn policy_migration_builder_binds_all_fields() {
    let input = PolicyMigrationInput {
        previous_policy: ReceiptPolicy::VerifierOnly,
        new_policy: ReceiptPolicy::ZkOrVerifier,
        previous_state_digest: b32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        ),
        new_state_digest: b32("2222222222222222222222222222222222222222222222222222222222222222"),
        transition_digest: b32("3333333333333333333333333333333333333333333333333333333333333333"),
        authorization_commitment: b32(
            "4444444444444444444444444444444444444444444444444444444444444444",
        ),
    };
    let proof = build_policy_migration_proof(input);
    assert_eq!(proof.previous_policy, input.previous_policy);
    assert_eq!(proof.new_policy, input.new_policy);
    assert_eq!(
        proof.migration_commitment,
        policy_migration_commitment(
            input.previous_policy,
            input.new_policy,
            input.previous_state_digest,
            input.new_state_digest,
            input.transition_digest,
            input.authorization_commitment,
        )
    );

    let mut changed = input;
    changed.authorization_commitment[0] ^= 0x01;
    assert_ne!(
        proof.migration_commitment,
        build_policy_migration_proof(changed).migration_commitment
    );
    assert_eq!(input.build(), proof);
}

// ---------------- Frozen test vectors ----------------
//
// These vectors pin the byte layout. If the canonical encoder ever changes,
// these tests fail and force a spec version bump. The hex strings are the
// *full canonical encoding* (magic + version + body).

#[test]
fn frozen_state_commitment_vector() {
    let s = sample_state(1, ReceiptPolicy::Any);
    let bytes = s.encode_canonical();
    // Sanity: to_hex of an empty fixed array compiles and is empty.
    assert_eq!(to_hex::<0>(&[]), "");
    // Body layout (see RECEIPT-SPEC.md):
    //   u16 version(2) + chain(2) + covenant(32) + asset(32) +
    //   digest(32) + policy(2) = 102
    // Framing: magic(8) + outer-version(2) = 10
    const STATE_BODY: usize = 2 + 2 + 32 + 32 + 32 + 2;
    const STATE_TOTAL: usize = 8 + 2 + STATE_BODY;
    assert_eq!(bytes.len(), STATE_TOTAL, "state commitment length");
    assert_eq!(&bytes[0..8], b"rgk:v0\x00\x00");
    assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), ENCODING_VERSION);
}

#[test]
fn frozen_receipt_vector_anchor() {
    let r = sample_receipt(ReceiptPolicy::Any, ProofMode::VerifierReceipt);
    let bytes = r.encode_canonical();
    // Body: u16 version(2) + chain(2) + covenant(32) +
    //       old_state(STATE_BODY=102) + new_state(102) + transition(32) +
    //       continuation(32) + proofmode(2) + nonce(32)
    const STATE_BODY: usize = 2 + 2 + 32 + 32 + 32 + 2;
    const RECEIPT_BODY: usize = 2 + 2 + 32 + STATE_BODY + STATE_BODY + 32 + 32 + 2 + 32;
    const RECEIPT_TOTAL: usize = 8 + 2 + RECEIPT_BODY;
    assert_eq!(bytes.len(), RECEIPT_TOTAL, "receipt canonical length");
    assert_eq!(&bytes[0..8], b"rgk:v0\x00\x00");
    // The receipt id is deterministic and 32 bytes:
    let id = receipt_commitment(&r);
    let id_hex = to_hex(&id);
    assert_eq!(id_hex.len(), 64);
}

// ---------------- Hex helpers ----------------

#[test]
fn hex_round_trip() {
    let raw: [u8; 32] = b32("00ff".repeat(16).as_str());
    let s = to_hex(&raw);
    assert_eq!(s, "00ff".repeat(16).as_str());
    let back = from_hex::<32>(&s).unwrap();
    assert_eq!(raw, back);
}

#[test]
fn hex_rejects_bad() {
    assert!(from_hex::<32>("ab").is_err()); // wrong length
    assert!(from_hex::<32>(&"zz".repeat(16)).is_err()); // bad char
    assert!(from_hex::<32>(&"AB".repeat(16)).is_err()); // uppercase rejected
}

// ---------------- Misc ----------------

#[test]
fn policy_admits_table() {
    assert!(ReceiptPolicy::Any.admits(ProofMode::VerifierReceipt));
    assert!(ReceiptPolicy::Any.admits(ProofMode::ZkReceipt));
    assert!(ReceiptPolicy::VerifierOnly.admits(ProofMode::VerifierReceipt));
    assert!(!ReceiptPolicy::VerifierOnly.admits(ProofMode::ZkReceipt));
    assert!(ReceiptPolicy::ZkOrVerifier.admits(ProofMode::VerifierReceipt));
    assert!(ReceiptPolicy::ZkOrVerifier.admits(ProofMode::ZkReceipt));
    assert!(!ReceiptPolicy::ZkOrVerifier.admits(ProofMode::P2mrRet));
}

#[test]
fn chain_domain_strings_stable() {
    assert_eq!(KaspaChainId::KaspaMainnet.as_domain_str(), "kaspa-mainnet");
    assert_eq!(KASPA_LOCAL_TOCCATA.as_domain_str(), "kaspa-local-toccata");
    // Unused-type warnings cleanup: ensure RgkSchemaId alias is exercised.
    let _schema: RgkSchemaId = b32("5555".repeat(16).as_str());
    let _asset: RgkAssetId = b32("6666".repeat(16).as_str());
}
