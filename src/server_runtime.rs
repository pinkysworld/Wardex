use super::*;

pub async fn run_server(
    port: u16,
    site_dir: &Path,
    shutdown: Arc<AtomicBool>,
    mut initial_config: Config,
) -> Result<(), String> {
    let addr = format!("0.0.0.0:{port}");

    // Determine TLS mode from environment variables
    let tls_cert = std::env::var("WARDEX_TLS_CERT").ok();
    let tls_key = std::env::var("WARDEX_TLS_KEY").ok();

    if let (Some(cert_path), Some(key_path)) = (&tls_cert, &tls_key) {
        // Validate that cert/key files exist and are readable at startup
        if !std::path::Path::new(cert_path).exists() {
            return Err(format!("WARDEX_TLS_CERT file not found: {cert_path}"));
        }
        if !std::path::Path::new(key_path).exists() {
            return Err(format!("WARDEX_TLS_KEY file not found: {key_path}"));
        }
        // Validate PEM structure
        let cert_contents = std::fs::read_to_string(cert_path)
            .map_err(|e| format!("failed to read TLS cert {cert_path}: {e}"))?;
        let key_contents = std::fs::read_to_string(key_path)
            .map_err(|e| format!("failed to read TLS key {key_path}: {e}"))?;
        if !cert_contents.contains("-----BEGIN") {
            return Err(format!(
                "WARDEX_TLS_CERT does not appear to be valid PEM: {cert_path}"
            ));
        }
        if !key_contents.contains("-----BEGIN") {
            return Err(format!(
                "WARDEX_TLS_KEY does not appear to be valid PEM: {key_path}"
            ));
        }
        eprintln!(
            "  NOTE: TLS configured via WARDEX_TLS_CERT/KEY — use a reverse proxy (nginx/caddy) for production TLS"
        );
    } else if tls_cert.is_some() || tls_key.is_some() {
        return Err(
            "Both WARDEX_TLS_CERT and WARDEX_TLS_KEY must be set (only one was provided)".into(),
        );
    }

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;

    let config_path = crate::config::runtime_config_path();
    apply_server_env_overrides(&mut initial_config);
    validate_production_trust_config(&initial_config)?;

    // Use persistent token from environment if set, otherwise generate a random one
    let token = std::env::var("WARDEX_ADMIN_TOKEN").unwrap_or_else(|_| generate_token());
    let scheme = if tls_cert.is_some() && tls_key.is_some() && cfg!(feature = "tls") {
        "https"
    } else {
        "http"
    };
    eprintln!("Wardex admin console");
    eprintln!("  Listening on {scheme}://localhost:{port}");
    eprintln!("  Site directory: {}", site_dir.display());
    if std::env::var("WARDEX_ADMIN_TOKEN").is_ok() {
        eprintln!("  Auth token: (set via WARDEX_ADMIN_TOKEN)");
    } else {
        // Write generated token to a secure file instead of printing to stderr
        let token_path = std::path::Path::new("var").join(".wardex_token");
        if let Ok(()) = std::fs::create_dir_all("var") {
            if let Ok(()) = std::fs::write(&token_path, &token) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &token_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                eprintln!(
                    "  Auth token: written to {} (mode 0600)",
                    token_path.display()
                );
            } else {
                eprintln!("  Auth token: {token}");
            }
        } else {
            eprintln!("  Auth token: {token}");
        }
        eprintln!("  (set WARDEX_ADMIN_TOKEN env var for a persistent token)");
    }
    eprintln!("  Press Ctrl+C to stop");

    // Derive spool encryption key from env var; in production mode, require it explicitly
    let is_production = std::env::var("WARDEX_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false);
    let spool_key = match std::env::var("WARDEX_SPOOL_KEY") {
        Ok(k) => sha2::Sha256::digest(k.as_bytes()),
        Err(_) if is_production => {
            return Err("WARDEX_SPOOL_KEY must be set when WARDEX_ENV=production. \
                 Set it to a persistent secret to ensure spool data survives token rotation."
                .into());
        }
        Err(_) => {
            eprintln!("  WARNING: WARDEX_SPOOL_KEY not set — spool key derived from admin token.");
            eprintln!("           Rotating the token will make existing spool data unreadable.");
            eprintln!("           Set WARDEX_SPOOL_KEY to a persistent secret for production use.");
            sha2::Sha256::digest(format!("spool-key-{token}").as_bytes())
        }
    };
    let session_store = crate::auth::SessionStore::with_persistence_key(
        &session_store_path(&config_path),
        Some(load_or_create_session_seal_key(&config_path)),
    );
    let user_preferences = UserPreferencesStore::new(&user_preferences_store_path(&config_path));
    let model_registry_dir = model_registry_path(&config_path);
    let detection_feedback_path = detection_feedback_store_path(&config_path);

    let storage = SharedStorage::open("var/storage")
        .or_else(|_| SharedStorage::open("/tmp/wardex_storage"))
        .map_err(|e| format!("failed to initialise storage: {e}"))?;
    let failed_auth_snapshot: crate::server_auth::FailedAuthSnapshot =
        load_stored_json(&storage, FAILED_AUTH_TRACKER_STORAGE_KEY);
    crate::server_auth::failed_auth_restore_snapshot(failed_auth_snapshot);

    let state = Arc::new(Mutex::new(AppState {
        detector: AnomalyDetector::default(),
        checkpoints: CheckpointStore::new(10),
        device: DeviceController::default(),
        replay: ReplayBuffer::new(200),
        proofs: ProofRegistry::new(),
        last_report: None,
        last_failover_drill: None,
        token: token.clone(),
        token_issued_at: std::time::Instant::now(),
        session_store,
        oidc_providers: HashMap::new(),
        user_preferences,
        swarm: SwarmNode::new("gateway-0"),
        cluster: ClusterNode::new(initial_config.cluster.clone()),
        enforcement: EnforcementEngine::new(),
        threat_intel: ThreatIntelStore::new(),
        digital_twin: DigitalTwinEngine::new(),
        compliance: ComplianceManager::new(),
        multi_tenant: MultiTenantManager::new(),
        energy: EnergyBudget::new(500.0),
        side_channel: SideChannelDetector::new(),
        key_rotation: KeyRotationManager::new(3600),
        privacy: PrivacyAccountant::new(10.0),
        policy_vm: PolicyVm::default(),
        fingerprint: None,
        monitor: Monitor::new(),
        drift: DriftDetector::new(0.005, 50.0),
        deception: DeceptionEngine::new(),
        patches: PatchManager::new(),
        causal: CausalGraph::new(),
        listener_mode: if tls_cert.is_some() && tls_key.is_some() && cfg!(feature = "tls") {
            ListenerMode::Tls {
                port,
                config: crate::tls::TlsConfig::new(
                    tls_cert.as_deref().unwrap_or_default(),
                    tls_key.as_deref().unwrap_or_default(),
                ),
            }
        } else {
            ListenerMode::Plain { port }
        },
        config: Config::default(),
        config_path,
        alerts: VecDeque::new(),
        server_start: std::time::Instant::now(),
        agent_registry: AgentRegistry::new("var/agents.json"),
        event_store: EventStore::with_persistence(10_000, "var/events.json"),
        clickhouse_store: initial_config.clickhouse.as_ref().map(|cfg| {
            log::info!(
                "[STORAGE] ClickHouse backend enabled: {}/{}",
                cfg.url,
                cfg.database
            );
            crate::storage_clickhouse::ClickHouseStorage::new(cfg.clone())
        }),
        policy_store: PolicyStore::new(),
        update_manager: UpdateManager::new("var/updates"),
        remote_deployments: load_remote_deployments("var/deployments.json"),
        deployment_store_path: "var/deployments.json".to_string(),
        siem_connector: SiemConnector::new(initial_config.siem.clone()),
        taxii_client: crate::siem::TaxiiClient::new(initial_config.taxii.clone()),
        local_telemetry: VecDeque::new(),
        local_host_info: detect_platform(),
        last_inventory: None,
        last_inventory_at_ms: 0,
        velocity: VelocityDetector::new(60, 2.5),
        entropy: EntropyDetector::new(60, 8),
        compound: CompoundThreatDetector::default(),
        shutdown: shutdown.clone(),
        rate_limiter: RateLimiter::new(
            initial_config.server.rate_limit_read_per_minute,
            initial_config.server.rate_limit_write_per_minute,
        ),
        audit_log: AuditLog::new(1000),
        incident_store: IncidentStore::new("var/incidents.json"),
        agent_logs: HashMap::new(),
        agent_logs_last_access: HashMap::new(),
        agent_inventories: HashMap::new(),
        report_store: crate::report::ReportStore::new("var/reports.json"),
        support_store: SupportStore::new("var/support.json"),
        sigma_engine: SigmaEngine::new(),
        response_orchestrator: ResponseOrchestrator::new(),
        feature_flags: FeatureFlagRegistry::new(),
        process_tree: ProcessTree::new("localhost"),
        spool: EncryptedSpool::try_new(&spool_key, 10_000)
            .map_err(|err| format!("failed to initialise encrypted spool: {err}"))?,
        rbac: RbacStore::new(),
        case_store: CaseStore::new("var/cases.json"),
        alert_queue: AlertQueue::new(),
        approval_log: ApprovalLog::new(),
        dead_letter_queue: DeadLetterQueue::new(500),
        enterprise: EnterpriseStore::new("var/enterprise.json"),
        request_count: 0,
        error_count: 0,
        beacon_detector: crate::beacon::BeaconDetector::default(),
        ueba_engine: crate::ueba::UebaEngine::default(),
        kill_chain_analyzer: crate::kill_chain::KillChainAnalyzer::new(),
        lateral_detector: crate::lateral::LateralMovementDetector::default(),
        playbook_engine: crate::playbook::PlaybookEngine::new(),
        live_response_engine: crate::live_response::LiveResponseEngine::default(),
        remediation_engine: crate::remediation::RemediationEngine::new(),
        escalation_engine: crate::escalation::EscalationEngine::new(),
        kernel_event_stream: crate::kernel_events::KernelEventStream::new(10_000),
        last_alert_analysis: None,
        storage: storage.clone(),
        slow_attack: crate::detector::SlowAttackDetector::default(),
        ransomware: crate::ransomware::RansomwareDetector::default(),
        mitre_coverage: crate::mitre_coverage::MitreCoverageTracker::new(),
        tuning_profile: crate::detector::TuningProfile::default(),
        fp_feedback: crate::alert_analysis::FpFeedbackStore::new(),
        vulnerability_scanner: crate::vulnerability::VulnerabilityScanner::new(),
        ndr_engine: crate::ndr::NdrEngine::new(crate::ndr::NdrConfig::default()),
        container_detector: crate::container::ContainerDetector::new(),
        cert_monitor: crate::cert_monitor::CertMonitor::new(),
        config_drift_detector: crate::config_drift::ConfigDriftDetector::new(),
        asset_inventory: crate::cloud_inventory::AssetInventory::new(),
        efficacy_tracker: crate::detection_efficacy::EfficacyTracker::new(100_000),
        workflow_store: crate::investigation::WorkflowStore::new(),
        llm_analyst: Arc::new(Mutex::new(load_llm_analyst_from_env())),
        model_registry: crate::ml_engine::ModelRegistry::new(&model_registry_dir),
        detection_feedback: crate::detection_feedback::DetectionFeedbackStore::new(
            &detection_feedback_path,
        ),
        malware_hash_db: crate::malware_signatures::MalwareHashDb::new(),
        malware_scanner: crate::malware_scanner::MalwareScanner::new(),
        yara_engine: crate::yara_engine::YaraEngine::new(),
        api_analytics: crate::api_analytics::ApiAnalytics::new(),
        trace_collector: crate::telemetry::TraceCollector::new(10000),
        feed_engine: crate::feed_ingestion::FeedIngestionEngine::new_with_defaults(),
        playbook_dsl: crate::playbook_dsl::PlaybookDslStore::new(),
        image_inventory: crate::container_image::ImageInventory::new(),
        quarantine_store: crate::quarantine::QuarantineStore::new(),
        lifecycle_manager: crate::agent_lifecycle::LifecycleManager::new(
            crate::agent_lifecycle::LifecycleConfig::default(),
        ),
        decay_config: crate::ioc_decay::DecayConfig::default(),
        dns_analyzer: crate::dns_threat::DnsAnalyzer::new(),
        alert_broadcaster: crate::ws_stream::AlertBroadcaster::new(),
        extra: HashMap::new(),
    }));

    // Apply loaded config
    let shutdown_timeout_secs = initial_config.server.shutdown_timeout_secs;

    {
        let mut s = crate::state_lock::tracked_lock(&state, "server/run_initial_config_apply");
        s.config = initial_config;
        let effective_rules = s.enterprise.effective_sigma_rules();
        s.sigma_engine.replace_rules(effective_rules);
    }

    // Load community YARA malware rules
    {
        let yara_path = std::path::Path::new("rules/yara/malware.json");
        if yara_path.exists()
            && let Ok(json) = std::fs::read_to_string(yara_path)
        {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            match s.yara_engine.load_rules_json(&json) {
                Ok(n) => tracing::info!("loaded {n} community YARA malware rules"),
                Err(e) => tracing::warn!("failed to load YARA malware rules: {e}"),
            }
        }
    }

    // Load local open-source AV hash signatures by default when present.
    // Operators opt in by placing ClamAV-style .hdb/.hsb files in preset
    // directories; Wardex does not redistribute or auto-download databases.
    let imported = load_local_open_source_av_signatures(&state);
    if imported > 0 {
        tracing::info!("loaded {imported} local open-source AV hash signatures");
    }

    spawn_enterprise_hunt_scheduler(&state);
    spawn_retention_purge_scheduler(&state);
    crate::server_cluster::spawn_cluster_runtime_loop(&state);
    spawn_feed_ingestion_loop(&state);

    // ── Spawn local host monitoring thread ──────────────────────────
    {
        let monitor_state = Arc::clone(&state);
        std::thread::spawn(move || {
            let mut cs = CollectorState::default();
            let mut consecutive_elevated: u32 = 0;
            let mut file_watch_cache: Vec<String> = Vec::new();
            let mut file_monitor: Option<FileIntegrityMonitor> = None;
            let mut persistence_watch_cache: Vec<String> = Vec::new();
            let mut persistence_monitor: Option<FileIntegrityMonitor> = None;
            const CONFIRM_SAMPLES: u32 = 2; // require N consecutive elevated before alerting
            loop {
                let (scope, watch_paths, host_platform) = {
                    let s = monitor_state.lock().unwrap_or_else(|e| e.into_inner());
                    (
                        s.config.monitor.scope.clone(),
                        s.config.monitor.watch_paths.clone(),
                        s.local_host_info.platform,
                    )
                };

                if scope.file_integrity {
                    if watch_paths != file_watch_cache {
                        file_monitor = if watch_paths.is_empty() {
                            None
                        } else {
                            Some(FileIntegrityMonitor::new(&watch_paths))
                        };
                        file_watch_cache = watch_paths.clone();
                    }
                } else {
                    file_monitor = None;
                    file_watch_cache.clear();
                }

                let persistence_paths =
                    crate::collector::persistence_watch_paths(host_platform, &scope);
                if persistence_paths != persistence_watch_cache {
                    persistence_monitor = if persistence_paths.is_empty() {
                        None
                    } else {
                        Some(FileIntegrityMonitor::new(&persistence_paths))
                    };
                    persistence_watch_cache = persistence_paths;
                }

                let sample = crate::collector::collect_sample_scoped(
                    &mut cs,
                    file_monitor.as_ref(),
                    persistence_monitor.as_ref(),
                    &scope,
                );
                {
                    let mut s = match monitor_state.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    if s.local_telemetry.len() >= 300 {
                        s.local_telemetry.pop_front();
                    }
                    s.local_telemetry.push_back(sample);
                    // Refresh host inventory (top processes + sockets) at most
                    // once every 10 s. Best-effort: failure leaves the last
                    // snapshot in place.
                    let should_refresh_inventory =
                        sample.timestamp_ms.saturating_sub(s.last_inventory_at_ms) > 10_000;
                    if should_refresh_inventory {
                        let inventory = crate::collector::collect_host_inventory(50, 50);
                        s.last_inventory_at_ms = sample.timestamp_ms;
                        s.last_inventory = Some(inventory);
                    }
                    let mut signal = s.detector.evaluate(&sample);

                    // Phase 21: velocity / entropy / compound enrichment
                    let vel_report = s.velocity.update(&sample);
                    let ent_report = s.entropy.update(&sample);
                    signal.score += vel_report.score_boost + ent_report.score_boost;
                    let mut extra_reasons: Vec<String> = Vec::new();
                    for ax in &vel_report.anomalous_axes {
                        extra_reasons.push(format!("velocity-spike:{ax}"));
                    }
                    for ax in &ent_report.anomalous_axes {
                        extra_reasons.push(format!("entropy-anomaly:{ax}"));
                    }
                    let cmp_report = s.compound.evaluate(&signal);
                    if cmp_report.is_compound_attack {
                        signal.score = cmp_report.compound_score;
                        extra_reasons.push(format!(
                            "compound-threat({:.0}%)",
                            cmp_report.concurrent_fraction * 100.0
                        ));
                    }
                    signal.reasons.extend(extra_reasons);

                    let crit = s.config.policy.critical_score;
                    let sev = s.config.policy.severe_score;
                    let elev = s.config.policy.elevated_score;
                    if signal.score >= elev {
                        consecutive_elevated += 1;
                        // Critical/Severe bypass confirmation — alert immediately
                        // Elevated requires consecutive confirmation to suppress noise
                        let confirmed =
                            signal.score >= sev || consecutive_elevated >= CONFIRM_SAMPLES;
                        if confirmed {
                            let level = if signal.score >= crit {
                                "Critical"
                            } else if signal.score >= sev {
                                "Severe"
                            } else {
                                "Elevated"
                            };
                            let host = s.local_host_info.clone();
                            let mitre = crate::telemetry::map_alert_to_mitre(&signal.reasons);
                            let recent_samples: Vec<_> =
                                s.local_telemetry.iter().cloned().collect();
                            let mut alert = AlertRecord {
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                hostname: host.hostname.clone(),
                                platform: host.platform.to_string(),
                                score: signal.score,
                                confidence: signal.confidence,
                                level: level.to_string(),
                                action: "monitor".to_string(),
                                reasons: signal.reasons,
                                sample,
                                enforced: false,
                                mitre,
                                narrative: None,
                            };
                            alert.narrative = Some(crate::collector::build_alert_narrative(
                                &alert,
                                &recent_samples,
                                s.last_inventory.as_ref(),
                            ));
                            if s.alerts.len() >= 10_000 {
                                s.alerts.pop_front();
                            }
                            s.alerts.push_back(alert.clone());
                            let process_catalog =
                                assemble_alert_process_catalog(&host.hostname, &s.process_tree);
                            let alert_event = alert_json_value(
                                &alert,
                                s.alerts.len().saturating_sub(1),
                                &host.hostname,
                                &process_catalog,
                            );
                            s.alert_broadcaster.broadcast_alert(alert_event);

                            // Phase 33: broadcast high-severity intel to swarm
                            if alert.score >= sev {
                                let swarm_id = s.swarm.id.clone();
                                for reason in &alert.reasons {
                                    if reason.contains("network burst")
                                        || reason.contains("velocity-spike")
                                    {
                                        let _msg = s.swarm.broadcast_threat_intel(
                                            crate::swarm::GossipPayload::ThreatIntelUpdate {
                                                ioc_type: "network_anomaly".into(),
                                                indicator: format!("{}:{}", alert.hostname, reason),
                                                confidence: alert.confidence,
                                                source_agent: swarm_id.clone(),
                                                ttl_hours: 24,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        consecutive_elevated = 0;
                    }
                    let interval = s.config.monitor.interval_secs.max(1);
                    drop(s);
                    std::thread::sleep(std::time::Duration::from_secs(interval));
                }
            }
        });
    }

    // ── Spawn background alert analysis thread (every 5 minutes) ────
    {
        let analysis_state = Arc::clone(&state);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(300));
                {
                    let s = match analysis_state.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    if s.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
                    drop(s);
                    let analysis = crate::alert_analysis::analyze_alerts(&alerts_vec, 5);
                    let mut s = match analysis_state.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    s.last_alert_analysis = Some(analysis);
                }
            }
        });
    }

    let site_dir = site_dir.to_path_buf();

    // Build axum router
    let shared_state = Arc::clone(&state);
    let shared_site = site_dir.clone();

    // Use a Notify channel for immediate shutdown signaling instead of polling
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let shutdown_notify_bg = shutdown_notify.clone();
    let shutdown_flag_check = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            if shutdown_flag_check.load(Ordering::Relaxed) {
                shutdown_notify_bg.notify_waiters();
                break;
            }
        }
    });

    use axum::Router;
    use axum::extract::ConnectInfo;
    let app = Router::new().fallback(
        move |method: HttpMethod,
              uri: axum::http::Uri,
              headers: HeaderMap,
              ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
              body: axum::body::Bytes| {
            let state = shared_state.clone();
            let site_dir = shared_site.clone();
            async move {
                let url = uri.to_string();
                let remote_addr = addr.ip().to_string();

                // Rate limiting
                {
                    let method_compat = Method::from_http(&method);
                    let mut s = match state.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    s.request_count += 1;
                    if !s.rate_limiter.check(&remote_addr, &method_compat, &url) {
                        drop(s);
                        if url.starts_with("/api/") {
                            return respond_api(
                                &state,
                                &method_compat,
                                &url,
                                &remote_addr,
                                false,
                                error_json("rate limit exceeded", 429),
                            );
                        } else {
                            return error_json("rate limit exceeded", 429);
                        }
                    }
                }

                // CORS preflight
                if method == HttpMethod::OPTIONS {
                    let origin = cors_origin();
                    return Response::builder()
                        .status(204)
                        .header("Access-Control-Allow-Origin", origin)
                        .header(
                            "Access-Control-Allow-Methods",
                            "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        )
                        .header(
                            "Access-Control-Allow-Headers",
                            "Content-Type, Authorization",
                        )
                        .header("Access-Control-Max-Age", "86400")
                        .body(Body::empty())
                        .unwrap_or_else(|_| Response::new(Body::empty()));
                }

                if url.starts_with("/api/") {
                    let m = Method::from_http(&method);
                    let hdrs = headers.clone();
                    let body_bytes: Vec<u8> = body.to_vec();
                    let st = state.clone();
                    let u = url.clone();
                    let ra = remote_addr.clone();
                    match tokio::task::spawn_blocking(move || {
                        // Catch panics so one bad request cannot crash the server
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            handle_api(m, &u, &hdrs, &body_bytes, &ra, &st)
                        }))
                    })
                    .await
                    {
                        Ok(Ok(resp)) => resp,
                        Ok(Err(panic_info)) => {
                            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                                s.to_string()
                            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                                s.clone()
                            } else {
                                "unknown panic in request handler".to_string()
                            };
                            log::error!("[PANIC-RECOVERED] request handler panic: {msg}");
                            let mut s = match state.lock() {
                                Ok(g) => g,
                                Err(e) => e.into_inner(),
                            };
                            s.error_count += 1;
                            drop(s);
                            error_json("internal server error", 500)
                        }
                        Err(_) => error_json("internal server error", 500),
                    }
                } else {
                    crate::server_static::serve_static(&url, &site_dir)
                }
            }
        },
    );

    // Limit request body size to 10 MiB to prevent memory exhaustion attacks
    let app = app.layer(tower_http::limit::RequestBodyLimitLayer::new(
        10 * 1024 * 1024,
    ));

    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();

    eprintln!("Wardex server ready on http://localhost:{port}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let timeout = tokio::time::Duration::from_secs(shutdown_timeout_secs);
            shutdown_notify.notified().await;
            log::info!("Graceful shutdown initiated (timeout={shutdown_timeout_secs}s)…");
            tokio::time::sleep(timeout).await;
            log::info!("Shutdown timeout reached, closing connections");
        })
        .await
        .map_err(|e| format!("server error: {e}"))?;

    // ── Graceful shutdown: flush outstanding data to durable storage ──
    flush_to_storage(&state);

    Ok(())
}

/// Spawn a test server on a random port. Returns `(port, token)`.
/// The server runs in a background thread.
#[doc(hidden)]
pub(crate) fn spawn_test_server_with_state() -> (u16, String, Arc<Mutex<AppState>>) {
    let (tx, rx) = std::sync::mpsc::channel();
    // Find a free port
    let tmp_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let port = tmp_listener.local_addr().expect("local addr").port();
    drop(tmp_listener);
    let token = generate_token();
    let state_root = PathBuf::from(format!("/tmp/wardex_test_{port}"));
    let _ = std::fs::remove_dir_all(&state_root);
    std::fs::create_dir_all(&state_root).expect("create test state root");
    let config_path = state_root.join("wardex.toml");
    let mut test_config = Config::default();
    let test_signing_key = [7u8; 32];
    let test_signing_key_path = state_root.join("update-signing-key.bin");
    std::fs::write(&test_signing_key_path, test_signing_key).expect("write update signing key");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&test_signing_key);
    let signer_pubkey = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signing_key.verifying_key().to_bytes(),
    );
    test_config.security.update_signing.signing_key_path =
        Some(test_signing_key_path.to_string_lossy().to_string());
    test_config
        .security
        .update_signing
        .trusted_update_signers
        .push(signer_pubkey);
    let session_store = crate::auth::SessionStore::with_persistence_key(
        &session_store_path(&config_path),
        Some(load_or_create_session_seal_key(&config_path)),
    );
    let user_preferences = UserPreferencesStore::new(&user_preferences_store_path(&config_path));
    let model_registry_dir = model_registry_path(&config_path);
    let detection_feedback_path = detection_feedback_store_path(&config_path);
    let state = Arc::new(Mutex::new(AppState {
        detector: AnomalyDetector::default(),
        checkpoints: CheckpointStore::new(10),
        device: DeviceController::default(),
        replay: ReplayBuffer::new(200),
        proofs: ProofRegistry::new(),
        last_report: None,
        last_failover_drill: None,
        token: token.clone(),
        token_issued_at: std::time::Instant::now(),
        session_store,
        oidc_providers: HashMap::new(),
        user_preferences,
        swarm: SwarmNode::new("test-node-0"),
        cluster: ClusterNode::new(test_config.cluster.clone()),
        enforcement: EnforcementEngine::new(),
        threat_intel: ThreatIntelStore::new(),
        digital_twin: DigitalTwinEngine::new(),
        compliance: ComplianceManager::new(),
        multi_tenant: MultiTenantManager::new(),
        energy: EnergyBudget::new(500.0),
        side_channel: SideChannelDetector::new(),
        key_rotation: KeyRotationManager::new(3600),
        privacy: PrivacyAccountant::new(10.0),
        policy_vm: PolicyVm::default(),
        fingerprint: None,
        monitor: Monitor::new(),
        drift: DriftDetector::new(0.005, 50.0),
        deception: DeceptionEngine::new(),
        patches: PatchManager::new(),
        causal: CausalGraph::new(),
        listener_mode: ListenerMode::Plain { port },
        config: test_config,
        config_path,
        alerts: VecDeque::new(),
        server_start: std::time::Instant::now(),
        agent_registry: AgentRegistry::new(&state_root.join("agents.json").to_string_lossy()),
        event_store: EventStore::with_persistence(
            1000,
            state_root.join("events.json").to_string_lossy().to_string(),
        ),
        clickhouse_store: None,
        policy_store: PolicyStore::new(),
        update_manager: UpdateManager::new(&state_root.join("updates").to_string_lossy()),
        remote_deployments: load_remote_deployments(
            &state_root.join("deployments.json").to_string_lossy(),
        ),
        deployment_store_path: state_root
            .join("deployments.json")
            .to_string_lossy()
            .to_string(),
        siem_connector: SiemConnector::new(crate::siem::SiemConfig::default()),
        taxii_client: crate::siem::TaxiiClient::new(crate::siem::TaxiiConfig::default()),
        local_telemetry: VecDeque::new(),
        local_host_info: detect_platform(),
        last_inventory: None,
        last_inventory_at_ms: 0,
        velocity: VelocityDetector::new(60, 2.5),
        entropy: EntropyDetector::new(60, 8),
        compound: CompoundThreatDetector::default(),
        shutdown: Arc::new(AtomicBool::new(false)),
        rate_limiter: RateLimiter::new(360, 60),
        audit_log: AuditLog::new(1000),
        incident_store: IncidentStore::new(&state_root.join("incidents.json").to_string_lossy()),
        agent_logs: HashMap::new(),
        agent_logs_last_access: HashMap::new(),
        agent_inventories: HashMap::new(),
        report_store: crate::report::ReportStore::new(
            &state_root.join("reports.json").to_string_lossy(),
        ),
        support_store: SupportStore::new(&state_root.join("support.json").to_string_lossy()),
        sigma_engine: SigmaEngine::new(),
        response_orchestrator: ResponseOrchestrator::new(),
        feature_flags: FeatureFlagRegistry::new(),
        process_tree: ProcessTree::new("localhost"),
        spool: EncryptedSpool::new(
            &sha2::Sha256::digest(format!("spool-key-{token}").as_bytes()),
            10_000,
        ),
        rbac: RbacStore::new(),
        case_store: CaseStore::new(&state_root.join("cases.json").to_string_lossy()),
        alert_queue: AlertQueue::new(),
        approval_log: ApprovalLog::new(),
        dead_letter_queue: DeadLetterQueue::new(500),
        enterprise: EnterpriseStore::new(&state_root.join("enterprise.json").to_string_lossy()),
        request_count: 0,
        error_count: 0,
        beacon_detector: crate::beacon::BeaconDetector::default(),
        ueba_engine: crate::ueba::UebaEngine::default(),
        kill_chain_analyzer: crate::kill_chain::KillChainAnalyzer::new(),
        lateral_detector: crate::lateral::LateralMovementDetector::default(),
        playbook_engine: crate::playbook::PlaybookEngine::new(),
        live_response_engine: crate::live_response::LiveResponseEngine::default(),
        remediation_engine: crate::remediation::RemediationEngine::new(),
        escalation_engine: crate::escalation::EscalationEngine::new(),
        kernel_event_stream: crate::kernel_events::KernelEventStream::new(10_000),
        last_alert_analysis: None,
        storage: SharedStorage::open(state_root.join("storage").to_str().unwrap_or("var/storage"))
            .or_else(|_| SharedStorage::open("/tmp/wardex_storage"))
            .expect("failed to initialise test storage"),
        slow_attack: crate::detector::SlowAttackDetector::default(),
        ransomware: crate::ransomware::RansomwareDetector::default(),
        mitre_coverage: crate::mitre_coverage::MitreCoverageTracker::new(),
        tuning_profile: crate::detector::TuningProfile::default(),
        fp_feedback: crate::alert_analysis::FpFeedbackStore::new(),
        vulnerability_scanner: crate::vulnerability::VulnerabilityScanner::new(),
        ndr_engine: crate::ndr::NdrEngine::new(crate::ndr::NdrConfig::default()),
        container_detector: crate::container::ContainerDetector::new(),
        cert_monitor: crate::cert_monitor::CertMonitor::new(),
        config_drift_detector: crate::config_drift::ConfigDriftDetector::new(),
        asset_inventory: crate::cloud_inventory::AssetInventory::new(),
        efficacy_tracker: crate::detection_efficacy::EfficacyTracker::new(100_000),
        workflow_store: crate::investigation::WorkflowStore::new(),
        llm_analyst: Arc::new(Mutex::new(load_llm_analyst_from_env())),
        model_registry: crate::ml_engine::ModelRegistry::new(&model_registry_dir),
        detection_feedback: crate::detection_feedback::DetectionFeedbackStore::new(
            &detection_feedback_path,
        ),
        malware_hash_db: crate::malware_signatures::MalwareHashDb::new(),
        malware_scanner: crate::malware_scanner::MalwareScanner::new(),
        yara_engine: crate::yara_engine::YaraEngine::new(),
        api_analytics: crate::api_analytics::ApiAnalytics::new(),
        trace_collector: crate::telemetry::TraceCollector::new(10000),
        feed_engine: crate::feed_ingestion::FeedIngestionEngine::new(),
        playbook_dsl: crate::playbook_dsl::PlaybookDslStore::new(),
        image_inventory: crate::container_image::ImageInventory::new(),
        quarantine_store: crate::quarantine::QuarantineStore::new(),
        lifecycle_manager: crate::agent_lifecycle::LifecycleManager::new(
            crate::agent_lifecycle::LifecycleConfig::default(),
        ),
        decay_config: crate::ioc_decay::DecayConfig::default(),
        dns_analyzer: crate::dns_threat::DnsAnalyzer::new(),
        alert_broadcaster: crate::ws_stream::AlertBroadcaster::new(),
        extra: HashMap::new(),
    }));
    {
        let mut s = crate::state_lock::tracked_lock(&state, "server/spawn_enterprise_rules_apply");
        let effective_rules = s.enterprise.effective_sigma_rules();
        s.sigma_engine.replace_rules(effective_rules);
    }
    spawn_enterprise_hunt_scheduler(&state);
    crate::server_cluster::spawn_cluster_runtime_loop(&state);
    spawn_feed_ingestion_loop(&state);
    let site_dir = PathBuf::from("site");
    let shutdown = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.shutdown.clone()
    };
    let server_state = Arc::clone(&state);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async move {
            let shared_state = Arc::clone(&server_state);
            let shared_site = site_dir.clone();
            let shutdown_flag = shutdown.clone();

            use axum::Router;
            use axum::extract::ConnectInfo;

            let app = Router::new().fallback(
                move |method: HttpMethod,
                      uri: axum::http::Uri,
                      headers: HeaderMap,
                      ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
                      body: axum::body::Bytes| {
                    let state = shared_state.clone();
                    let site_dir = shared_site.clone();
                    async move {
                        let url = uri.to_string();
                        let remote_addr = addr.ip().to_string();

                        {
                            let method_compat = Method::from_http(&method);
                            let mut s = match state.lock() {
                                Ok(g) => g,
                                Err(e) => e.into_inner(),
                            };
                            s.request_count += 1;
                            if !s.rate_limiter.check(&remote_addr, &method_compat, &url) {
                                drop(s);
                                return error_json("rate limit exceeded", 429);
                            }
                        }

                        if method == HttpMethod::OPTIONS {
                            let origin = cors_origin();
                            return Response::builder()
                                .status(204)
                                .header("Access-Control-Allow-Origin", origin)
                                .header(
                                    "Access-Control-Allow-Methods",
                                    "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                                )
                                .header(
                                    "Access-Control-Allow-Headers",
                                    "Content-Type, Authorization",
                                )
                                .body(Body::empty())
                                .unwrap_or_else(|_| Response::new(Body::empty()));
                        }

                        if url.starts_with("/api/") {
                            let m = Method::from_http(&method);
                            handle_api(m, &url, &headers, &body, &remote_addr, &state)
                        } else {
                            crate::server_static::serve_static(&url, &site_dir)
                        }
                    }
                },
            );

            let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
                .await
                .expect("bind test listener");
            tx.send(()).ok();
            let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        if shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                })
                .await
                .ok();
        });
    });
    // Wait for server to be listening
    let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
    // Small delay to let the listener actually start accepting
    std::thread::sleep(std::time::Duration::from_millis(50));
    (port, token, state)
}

pub fn spawn_test_server() -> (u16, String) {
    let (port, token, _state) = spawn_test_server_with_state();
    (port, token)
}

#[doc(hidden)]
pub fn spawn_test_server_with_seeded_alerts(alerts: Vec<AlertRecord>) -> (u16, String) {
    let (port, token, state) = spawn_test_server_with_state();
    if !alerts.is_empty() {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        for alert in alerts {
            if s.alerts.len() >= 10_000 {
                s.alerts.pop_front();
            }
            s.alerts.push_back(alert);
        }
    }
    (port, token)
}

#[doc(hidden)]
pub fn spawn_test_server_with_seeded_remote_installs(
    installs: Vec<RemoteInstallRecord>,
) -> (u16, String) {
    let (port, token, state) = spawn_test_server_with_state();
    if !installs.is_empty() {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        let _ = save_stored_json(&s.storage, FLEET_REMOTE_INSTALLS_KEY, &installs);
    }
    (port, token)
}

#[doc(hidden)]
pub fn spawn_test_server_with_live_rollback_enabled() -> (u16, String) {
    let (port, token, state) = spawn_test_server_with_state();
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.config.remediation.allow_live_rollback = true;
    }
    (port, token)
}

#[doc(hidden)]
pub fn spawn_test_server_with_live_rollback_execution_enabled() -> (u16, String) {
    let (port, token, state) = spawn_test_server_with_state();
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.config.remediation.allow_live_rollback = true;
        s.config.remediation.execute_live_rollback_commands = true;
    }
    (port, token)
}

/// Flush in-memory alerts, audit entries, and event store to the SQLite
/// storage backend so nothing is lost on shutdown.
fn flush_to_storage(state: &Arc<Mutex<AppState>>) {
    let s = match state.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let storage = s.storage.clone();
    let alerts: Vec<_> = s.alerts.iter().cloned().collect();
    let audit_entries: Vec<_> = s.audit_log.entries.iter().cloned().collect();
    let events: Vec<_> = s.event_store.all_events().to_vec();
    let hostname = s.local_host_info.hostname.clone();
    drop(s);

    let mut stored = 0usize;
    let mut errors = 0usize;

    // Flush in-memory alerts
    for (i, alert) in alerts.iter().enumerate() {
        let stored_alert = crate::storage::StoredAlert {
            id: format!("mem-{}-{}", hostname, i),
            timestamp: alert.timestamp.clone(),
            device_id: hostname.clone(),
            score: alert.score as f64,
            level: alert.level.clone(),
            reasons: alert.reasons.clone(),
            acknowledged: false,
            assigned_to: None,
            case_id: None,
            tenant_id: "default".into(),
        };
        match storage.with(|store| store.insert_alert(stored_alert)) {
            Ok(()) => stored += 1,
            Err(e) => {
                // Conflict (duplicate) is OK — alert was already persisted
                if e.code != crate::storage::StorageErrorCode::Conflict {
                    errors += 1;
                }
            }
        }
    }

    // Flush API audit log entries
    let mut audit_stored = 0usize;
    for entry in &audit_entries {
        let action = format!("{} {}", entry.method, entry.path);
        if storage
            .with(|store| {
                store.append_audit(
                    &entry.source_ip,
                    &action,
                    Some(&entry.path),
                    Some(&format!(
                        "status={} auth={}",
                        entry.status_code, entry.auth_used
                    )),
                    "default",
                )
            })
            .is_ok()
        {
            audit_stored += 1;
        }
    }

    // Flush forwarded events as stored alerts
    let mut event_stored = 0usize;
    for event in &events {
        let stored_alert = crate::storage::StoredAlert {
            id: format!("evt-{}", event.id),
            timestamp: event.received_at.clone(),
            device_id: event.agent_id.clone(),
            score: event.alert.score as f64,
            level: event.alert.level.clone(),
            reasons: event.alert.reasons.clone(),
            acknowledged: false,
            assigned_to: None,
            case_id: None,
            tenant_id: "default".into(),
        };
        match storage.with(|store| store.insert_alert(stored_alert)) {
            Ok(()) => event_stored += 1,
            Err(e) => {
                if e.code != crate::storage::StorageErrorCode::Conflict {
                    errors += 1;
                }
            }
        }
    }

    log::info!(
        "Shutdown flush: {stored} alerts, {audit_stored} audit entries, {event_stored} events written to storage ({errors} errors)",
    );
}

