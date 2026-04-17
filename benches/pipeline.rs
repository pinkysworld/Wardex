use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use wardex::detector::AnomalyDetector;
use wardex::policy::PolicyEngine;
use wardex::runtime::{demo_samples, execute};
use wardex::telemetry::TelemetrySample;

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

fn bench_search_index(c: &mut Criterion) {
    use std::collections::HashMap;
    use wardex::search::{SearchIndex, SearchQuery};

    let idx = SearchIndex::new("/tmp/bench_search").unwrap();
    // Populate index with 500 events
    for i in 0..500 {
        let mut fields = HashMap::new();
        fields.insert(
            "timestamp".into(),
            format!("2026-04-05T{:02}:00:00Z", i % 24),
        );
        fields.insert("device_id".into(), format!("srv-{:02}", i % 10));
        fields.insert(
            "process_name".into(),
            if i % 5 == 0 {
                "mimikatz.exe"
            } else {
                "svchost.exe"
            }
            .into(),
        );
        fields.insert(
            "src_ip".into(),
            format!("10.0.{}.{}", i % 256, (i * 7) % 256),
        );
        fields.insert(
            "raw_text".into(),
            format!("Event {} on device srv-{:02}", i, i % 10),
        );
        let _ = idx.index_event(fields);
    }
    idx.commit().unwrap();

    c.bench_function("search_500_events", |b| {
        b.iter(|| {
            let q = SearchQuery {
                query: "mimikatz".into(),
                fields: vec![],
                from: None,
                to: None,
                limit: 50,
                offset: 0,
                sort_by: None,
                sort_desc: false,
            };
            idx.search(black_box(&q)).unwrap()
        });
    });
}

fn bench_hunt_query(c: &mut Criterion) {
    use std::collections::HashMap;
    use wardex::search::SearchIndex;

    let idx = SearchIndex::new("/tmp/bench_hunt").unwrap();
    for i in 0..500 {
        let mut fields = HashMap::new();
        fields.insert(
            "process_name".into(),
            if i % 3 == 0 {
                "powershell.exe"
            } else {
                "cmd.exe"
            }
            .into(),
        );
        fields.insert(
            "src_ip".into(),
            format!("10.0.{}.{}", i % 256, (i * 3) % 256),
        );
        fields.insert("user_name".into(), format!("user{}", i % 20));
        let _ = idx.index_event(fields);
    }
    idx.commit().unwrap();

    c.bench_function("hunt_field_query", |b| {
        b.iter(|| {
            idx.hunt(black_box("process:powershell AND src:10.0.*"))
                .unwrap()
        });
    });
}

fn bench_ml_triage(c: &mut Criterion) {
    use wardex::ml_engine::{StubEngine, TriageFeatures};

    let engine = StubEngine::new();
    let features = TriageFeatures {
        anomaly_score: 0.75,
        confidence: 0.8,
        suspicious_axes: 2,
        hour_of_day: 3,
        day_of_week: 6,
        alert_frequency_1h: 5,
        device_risk_score: 0.6,
    };

    c.bench_function("ml_triage_rf", |b| {
        b.iter(|| engine.triage_alert(black_box(&features)));
    });
}

fn bench_sigma_evaluate(c: &mut Criterion) {
    use wardex::ocsf::{ActorProcess, DeviceInfo, OcsfEvent, OsInfo, ProcessEvent, ProcessInfo};
    use wardex::sigma::{SigmaEngine, builtin_rules};

    let event = OcsfEvent::process(
        "bench-process-1",
        "2026-04-17T00:00:00Z",
        4,
        ProcessEvent {
            activity_id: 1,
            actor: ActorProcess {
                process: ProcessInfo {
                    pid: 1234,
                    ppid: Some(4321),
                    name: "mimikatz.exe".into(),
                    cmd_line: Some("mimikatz.exe sekurlsa::logonpasswords".into()),
                    file: None,
                    created_time: None,
                    uid: None,
                },
                user: None,
            },
            process: ProcessInfo {
                pid: 1234,
                ppid: Some(4321),
                name: "mimikatz.exe".into(),
                cmd_line: Some("mimikatz.exe sekurlsa::logonpasswords".into()),
                file: None,
                created_time: None,
                uid: None,
            },
            parent_process: Some(ProcessInfo {
                pid: 4321,
                ppid: None,
                name: "cmd.exe".into(),
                cmd_line: Some("cmd.exe /c mimikatz.exe sekurlsa::logonpasswords".into()),
                file: None,
                created_time: None,
                uid: None,
            }),
            device: DeviceInfo {
                hostname: "test-host".into(),
                os: OsInfo {
                    name: "Windows".into(),
                    os_type: "windows".into(),
                    version: Some("11".into()),
                },
                ip: None,
                agent_uid: None,
            },
        },
    );

    c.bench_function("sigma_evaluate_20_rules", |b| {
        b.iter(|| {
            let mut eng = SigmaEngine::new();
            eng.load_rules(builtin_rules());
            eng.evaluate(black_box(&event), 1000)
        });
    });
}

criterion_group!(
    benches,
    bench_full_pipeline,
    bench_detector_evaluate,
    bench_policy_evaluate,
    bench_throughput,
    bench_search_index,
    bench_hunt_query,
    bench_ml_triage,
    bench_sigma_evaluate,
);
criterion_main!(benches);
