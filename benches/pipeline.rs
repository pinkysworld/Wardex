use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sentineledge::detector::AnomalyDetector;
use sentineledge::policy::PolicyEngine;
use sentineledge::runtime::{demo_samples, execute};
use sentineledge::telemetry::TelemetrySample;

fn make_samples(n: usize) -> Vec<TelemetrySample> {
    let base = demo_samples();
    base.into_iter().cycle().take(n).collect()
}

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");
    for size in [5, 50, 200, 1000] {
        let samples = make_samples(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &samples, |b, s| {
            b.iter(|| execute(black_box(s)));
        });
    }
    group.finish();
}

fn bench_detector_evaluate(c: &mut Criterion) {
    let samples = demo_samples();
    c.bench_function("detector_evaluate_single", |b| {
        b.iter(|| {
            let mut detector = AnomalyDetector::default();
            detector.evaluate(black_box(&samples[4]));
        });
    });
}

fn bench_policy_evaluate(c: &mut Criterion) {
    let samples = demo_samples();
    let mut detector = AnomalyDetector::default();
    // Warm up detector so baseline is established
    for s in &samples[..4] {
        detector.evaluate(s);
    }
    let signal = detector.evaluate(&samples[4]);

    c.bench_function("policy_evaluate_single", |b| {
        b.iter(|| {
            let policy = PolicyEngine;
            policy.evaluate(black_box(&signal), black_box(&samples[4]));
        });
    });
}

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(criterion::Throughput::Elements(1000));
    let samples = make_samples(1000);
    group.bench_function("1000_samples", |b| {
        b.iter(|| execute(black_box(&samples)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_full_pipeline,
    bench_detector_evaluate,
    bench_policy_evaluate,
    bench_throughput,
);
criterion_main!(benches);
