use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use rgk_core::{ProofMode, ReceiptPolicy, KASPA_LOCAL_TOCCATA};
use rgk_covenant::{CovenantSpec, CovenantState};

fn bytes32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn spec() -> CovenantSpec {
    CovenantSpec {
        chain_id: KASPA_LOCAL_TOCCATA,
        lineage_id: bytes32(0x11),
        asset_id: bytes32(0x22),
        initial_state_digest: bytes32(0x33),
        receipt_policy: ReceiptPolicy::Any,
        genesis_proof_mode: ProofMode::VerifierReceipt,
    }
}

fn state() -> CovenantState {
    CovenantState::genesis(
        KASPA_LOCAL_TOCCATA,
        bytes32(0x22),
        bytes32(0x11),
        ReceiptPolicy::Any,
        ProofMode::VerifierReceipt,
    )
}

fn bench_covenant_build_script(c: &mut Criterion) {
    let spec = spec();
    c.bench_function("covenant_build_script", |b| {
        b.iter(|| black_box(spec.build_script().expect("build covenant script")))
    });
}

fn bench_covenant_state_advance(c: &mut Criterion) {
    let state = state();
    c.bench_function("covenant_state_advance", |b| {
        b.iter(|| {
            black_box(
                state
                    .advance(black_box(bytes32(0x44)), black_box(bytes32(0x55)))
                    .expect("advance covenant state"),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_covenant_build_script,
    bench_covenant_state_advance
);
criterion_main!(benches);
