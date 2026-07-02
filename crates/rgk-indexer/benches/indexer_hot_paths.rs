use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rgk_core::{KaspaCovenantId, KaspaOutpoint, RgkStateCommitment, KASPA_LOCAL_TOCCATA};
use rgk_indexer::{InMemoryIndexer, Indexer};

fn covenant_id(n: u64) -> KaspaCovenantId {
    let mut id = [0u8; 32];
    id[24..32].copy_from_slice(&n.to_be_bytes());
    id
}

fn lineage_id(n: u64) -> [u8; 32] {
    let mut id = [0xaa; 32];
    id[24..32].copy_from_slice(&n.to_be_bytes());
    id
}

fn outpoint(n: u64, index: u32) -> KaspaOutpoint {
    let mut txid = [0u8; 32];
    txid[24..32].copy_from_slice(&n.to_be_bytes());
    KaspaOutpoint {
        transaction_id: txid,
        index,
    }
}

fn receipt_id(n: u64) -> [u8; 32] {
    let mut id = [0x33; 32];
    id[24..32].copy_from_slice(&n.to_be_bytes());
    id
}

fn state(covenant: KaspaCovenantId, digest: u64) -> RgkStateCommitment {
    let mut asset_id = [0x22; 32];
    asset_id[24..32].copy_from_slice(&42u64.to_be_bytes());
    let mut state_digest = [0u8; 32];
    state_digest[24..32].copy_from_slice(&digest.to_be_bytes());
    RgkStateCommitment::new(
        KASPA_LOCAL_TOCCATA,
        covenant,
        asset_id,
        state_digest,
        rgk_core::ReceiptPolicy::Any,
    )
    .expect("benchmark state commitment is valid")
}

fn seeded_indexer(covenants: u64) -> InMemoryIndexer {
    let mut indexer = InMemoryIndexer::new();
    for n in 0..covenants {
        let covenant = covenant_id(n);
        indexer
            .open(
                KASPA_LOCAL_TOCCATA,
                covenant,
                lineage_id(n),
                state(covenant, 1),
                outpoint(n, 0),
                n,
            )
            .expect("seed covenant");
    }
    indexer
}

fn one_open_indexer(n: u64) -> (InMemoryIndexer, KaspaCovenantId, KaspaOutpoint) {
    let mut indexer = InMemoryIndexer::new();
    let covenant = covenant_id(n);
    let open = outpoint(n, 0);
    indexer
        .open(
            KASPA_LOCAL_TOCCATA,
            covenant,
            lineage_id(n),
            state(covenant, 1),
            open,
            10,
        )
        .expect("open covenant");
    (indexer, covenant, open)
}

fn one_spent_indexer(
    n: u64,
) -> (
    InMemoryIndexer,
    KaspaCovenantId,
    KaspaOutpoint,
    KaspaOutpoint,
) {
    let (mut indexer, covenant, open) = one_open_indexer(n);
    let next = outpoint(n + 1, 0);
    indexer
        .apply_spend(covenant, receipt_id(n), open, next, state(covenant, 2), 11)
        .expect("apply seed spend");
    (indexer, covenant, open, next)
}

fn bench_lookup(c: &mut Criterion) {
    let indexer = seeded_indexer(10_000);
    let covenant = covenant_id(5_000);
    c.bench_function("in_memory_lookup_10k", |b| {
        b.iter(|| black_box(indexer.lookup(black_box(covenant))))
    });
}

fn bench_apply_spend(c: &mut Criterion) {
    c.bench_function("in_memory_apply_spend_one_transition", |b| {
        b.iter_batched(
            || one_open_indexer(1),
            |(mut indexer, covenant, open)| {
                let next = outpoint(2, 0);
                indexer
                    .apply_spend(
                        black_box(covenant),
                        receipt_id(1),
                        black_box(open),
                        black_box(next),
                        state(covenant, 2),
                        black_box(11),
                    )
                    .expect("bench apply_spend");
                black_box(indexer.open_outpoint(covenant))
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_rollback(c: &mut Criterion) {
    c.bench_function("in_memory_rollback_one_transition", |b| {
        b.iter_batched(
            || one_spent_indexer(1),
            |(mut indexer, covenant, _open, _next)| {
                indexer
                    .rollback(black_box(covenant), black_box(1))
                    .expect("bench rollback");
                black_box(indexer.open_outpoint(covenant))
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_lookup, bench_apply_spend, bench_rollback);
criterion_main!(benches);
