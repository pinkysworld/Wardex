use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use wardex::detector::{AnomalyDetector, EntropyDetector, VelocityDetector};
use wardex::policy::PolicyEngine;
use wardex::runtime::{demo_samples, execute};
use wardex::storage::{SharedStorage, StoredAlert};
use wardex::telemetry::TelemetrySample;

fn make_samples(n: usize) -> Vec<TelemetrySample> {
    let base = demo_samples();
    base.into_iter().cycle().take(n).collect()
}

fn make_alert(id: u64) -> StoredAlert {
    StoredAlert {
        id: format!("bench-alert-{id}"),
        timestamp: "2026-04-25T00:00:00Z".into(),
        device_id: format!("bench-device-{}", id % 32),
        score: 0.87,
        level: "Elevated".into(),
        reasons: vec!["benchmark".into(), "storage-lock-audit".into()],
        acknowledged: false,
        assigned_to: None,
        case_id: None,
        tenant_id: "bench".into(),
    }
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

fn bench_detector_window_stream(c: &mut Criterion) {
    let samples = make_samples(256);
    c.bench_function("detector_window_stream_256", |b| {
        b.iter(|| {
            let mut velocity = VelocityDetector::new(64, 2.5);
            let mut entropy = EntropyDetector::new(64, 8);
            for sample in black_box(&samples) {
                let _ = velocity.update(sample);
                let _ = entropy.update(sample);
            }
        });
    });
}

fn bench_shared_storage_lock_observation(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("bench storage tempdir");
    let storage = SharedStorage::open(dir.path().to_str().expect("utf-8 tempdir"))
        .expect("bench shared storage");

    c.bench_function("shared_storage_observed_schema_read", |b| {
        b.iter(|| {
            let (_, observation) = storage
                .with_observed(|store| Ok(store.schema_version()))
                .expect("observed storage read");
            black_box((observation.wait_micros(), observation.hold_micros()))
        });
    });
}

fn bench_shared_storage_concurrent_alert_inserts(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("bench storage tempdir");
    let storage = SharedStorage::open(dir.path().to_str().expect("utf-8 tempdir"))
        .expect("bench shared storage");
    let storage = Arc::new(storage);
    let next_id = Arc::new(AtomicU64::new(1));

    c.bench_function("shared_storage_4_threads_64_alerts", |b| {
        b.iter(|| {
            let mut handles = Vec::new();
            for _ in 0..4 {
                let storage = Arc::clone(&storage);
                let next_id = Arc::clone(&next_id);
                handles.push(thread::spawn(move || {
                    for _ in 0..16 {
                        let id = next_id.fetch_add(1, Ordering::Relaxed);
                        storage
                            .insert_alert_dedup(make_alert(id))
                            .expect("insert alert");
                    }
                }));
            }
            for handle in handles {
                handle.join().expect("storage worker");
            }
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
    use wardex::ml_engine::{RandomForestEngine, TriageFeatures};

    let engine = RandomForestEngine::new();
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
    bench_detector_window_stream,
    bench_shared_storage_lock_observation,
    bench_shared_storage_concurrent_alert_inserts,
    bench_policy_evaluate,
    bench_throughput,
    bench_search_index,
    bench_hunt_query,
    bench_ml_triage,
    bench_sigma_evaluate,
);
criterion_main!(benches);
