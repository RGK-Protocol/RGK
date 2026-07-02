use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use rgk_core::{RgkStateCommitment, KASPA_LOCAL_TOCCATA};
use rgk_receipt::{ProofMode, ReceiptBuilder, ReceiptInput, ReceiptPolicy, ReceiptVerifier};

fn bytes32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn state(digest_byte: u8, policy: ReceiptPolicy) -> RgkStateCommitment {
    RgkStateCommitment::new(
        KASPA_LOCAL_TOCCATA,
        bytes32(0x11),
        bytes32(0x22),
        bytes32(digest_byte),
        policy,
    )
    .expect("benchmark state commitment is valid")
}

fn input() -> ReceiptInput {
    ReceiptInput::new(
        KASPA_LOCAL_TOCCATA,
        bytes32(0x11),
        state(0x01, ReceiptPolicy::Any),
        state(0x02, ReceiptPolicy::Any),
        bytes32(0x33),
        bytes32(0x55),
        ProofMode::VerifierReceipt,
        bytes32(0x44),
    )
    .expect("receipt input")
}

fn bench_receipt_build(c: &mut Criterion) {
    let input = input();
    c.bench_function("receipt_build", |b| {
        b.iter(|| black_box(ReceiptBuilder::build(black_box(&input)).expect("build receipt")))
    });
}

fn bench_receipt_verify(c: &mut Criterion) {
    let input = input();
    let (_receipt, _id, bytes) = ReceiptBuilder::build(&input).expect("build receipt");
    c.bench_function("receipt_verify_local", |b| {
        b.iter(|| {
            black_box(
                ReceiptVerifier::verify_local(
                    black_box(&bytes),
                    black_box(input.covenant_id),
                    black_box(&input.old_state),
                    black_box(KASPA_LOCAL_TOCCATA),
                )
                .expect("verify receipt"),
            )
        })
    });
}

criterion_group!(benches, bench_receipt_build, bench_receipt_verify);
criterion_main!(benches);
