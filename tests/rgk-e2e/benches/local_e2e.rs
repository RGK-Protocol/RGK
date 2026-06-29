use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rgk_core::KASPA_LOCAL_TOCCATA;
use rgk_e2e::run_e2e_fixture;
use rgk_kaspa::FixtureBackend;

fn bench_fixture_e2e(c: &mut Criterion) {
    c.bench_function("fixture_e2e_full_resolution", |b| {
        b.iter_batched(
            || FixtureBackend::new(KASPA_LOCAL_TOCCATA),
            |mut backend| black_box(run_e2e_fixture(&mut backend).expect("fixture e2e")),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_fixture_e2e);
criterion_main!(benches);
