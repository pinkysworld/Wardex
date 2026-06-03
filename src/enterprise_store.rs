use super::*;

impl EnterpriseStore {
    pub fn new(store_path: &str) -> Self {
        let mut store = Self {
            snapshot: EnterpriseSnapshot {
                packs: default_pack_list(),
                scim: ScimConfig::default(),
                ..EnterpriseSnapshot::default()
            },
            store_path: store_path.to_string(),
        };
        store.load();
        store.ensure_default_connectors();
        store.bootstrap_builtin_sigma();
        store.persist();
        store
    }

    fn load(&mut self) {
        let path = Path::new(&self.store_path);
        if !path.exists() {
            return;
        }
        if let Ok(content) = std::fs::read_to_string(path)
            && let Ok(snapshot) = serde_json::from_str::<EnterpriseSnapshot>(&content)
        {
            self.snapshot = snapshot;
        }
    }

    fn persist(&self) {
        let path = Path::new(&self.store_path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.snapshot) {
            let tmp = format!("{}.tmp", self.store_path);
            if std::fs::write(&tmp, &json).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.snapshot.next_counter += 1;
        format!("{prefix}-{:06}", self.snapshot.next_counter)
    }

    fn ensure_default_connectors(&mut self) {
        let defaults = [
            ("asset-inventory", "asset_inventory", "Asset Inventory"),
            (
                "vuln-scanner",
                "vulnerability_scanner",
                "Vulnerability Scanner",
            ),
            (
                "identity-directory",
                "identity_directory",
                "Identity Directory",
            ),
            ("geoip", "geoip", "GeoIP"),
            ("whois", "whois", "WHOIS"),
            (
                "threat-reputation",
                "threat_reputation",
                "Threat Reputation",
            ),
            ("aws-cloudtrail", "aws_cloudtrail", "AWS CloudTrail"),
            ("azure-activity", "azure_activity", "Azure Activity Log"),
            ("gcp-audit", "gcp_audit", "GCP Audit Logs"),
            ("okta", "okta", "Okta"),
            ("entra", "entra_id", "Microsoft Entra ID"),
            ("m365", "microsoft_365", "Microsoft 365"),
            ("gworkspace", "google_workspace", "Google Workspace"),
        ];
        for (id, kind, display) in defaults {
            if self.snapshot.connectors.iter().any(|c| c.id == id) {
                continue;
            }
            self.snapshot.connectors.push(EnrichmentConnector {
                id: id.to_string(),
                kind: kind.to_string(),
                display_name: display.to_string(),
                endpoint: None,
                auth_mode: None,
                enabled: matches!(
                    kind,
                    "asset_inventory" | "threat_reputation" | "geoip" | "whois"
                ),
                status: if matches!(
                    kind,
                    "asset_inventory" | "threat_reputation" | "geoip" | "whois"
                ) {
                    "ready".to_string()
                } else {
                    "disabled".to_string()
                },
                timeout_secs: 10,
                last_sync_at: None,
                last_error: None,
                metadata: HashMap::new(),
            });
        }
    }

    pub fn bootstrap_builtin_sigma(&mut self) {
        let rules = builtin_rules();
        let mut changed = false;
        for rule in &rules {
            if self
                .snapshot
                .builtin_rules
                .iter()
                .any(|meta| meta.id == rule.id)
            {
                continue;
            }
            self.snapshot
                .builtin_rules
                .push(ManagedRuleMetadata::builtin_from_sigma(rule));
            changed = true;
        }
        if self.snapshot.packs.is_empty() {
            self.snapshot.packs = default_pack_list();
            changed = true;
        }
        for pack in &mut self.snapshot.packs {
            pack.rule_ids.clear();
        }
        for meta in &self.snapshot.builtin_rules {
            for pack_id in &meta.pack_ids {
                if let Some(pack) = self
                    .snapshot
                    .packs
                    .iter_mut()
                    .find(|pack| pack.id == *pack_id)
                {
                    if !pack.rule_ids.contains(&meta.id) {
                        pack.rule_ids.push(meta.id.clone());
                    }
                    pack.updated_at = now_rfc3339();
                }
            }
        }
        for rule in &self.snapshot.native_rules {
            for pack_id in &rule.metadata.pack_ids {
                if let Some(pack) = self
                    .snapshot
                    .packs
                    .iter_mut()
                    .find(|pack| pack.id == *pack_id)
                {
                    if !pack.rule_ids.contains(&rule.metadata.id) {
                        pack.rule_ids.push(rule.metadata.id.clone());
                    }
                    pack.updated_at = now_rfc3339();
                }
            }
        }
        if changed {
            self.persist();
        }
    }

    pub fn effective_sigma_rules(&self) -> Vec<SigmaRule> {
        let mut rules = builtin_rules();
        for rule in &mut rules {
            if let Some(meta) = self
                .snapshot
                .builtin_rules
                .iter()
                .find(|meta| meta.id == rule.id)
            {
                rule.enabled = meta.enabled
                    && matches!(
                        meta.lifecycle,
                        ContentLifecycle::Active
                            | ContentLifecycle::Canary
                            | ContentLifecycle::Test
                    );
                rule.status = match meta.lifecycle {
                    ContentLifecycle::Draft => RuleStatus::Experimental,
                    ContentLifecycle::Test => RuleStatus::Test,
                    ContentLifecycle::Canary | ContentLifecycle::Active => RuleStatus::Stable,
                    ContentLifecycle::Deprecated | ContentLifecycle::RolledBack => {
                        RuleStatus::Deprecated
                    }
                };
            }
        }
        rules
    }

    pub fn builtin_rules(&self) -> &[ManagedRuleMetadata] {
        &self.snapshot.builtin_rules
    }

    pub fn native_rules(&self) -> &[NativeContentRule] {
        &self.snapshot.native_rules
    }

    pub fn rule_tests(&self) -> &[RuleTestResult] {
        &self.snapshot.rule_tests
    }

    pub fn packs(&self) -> &[ContentPack] {
        &self.snapshot.packs
    }

    pub fn hunts(&self) -> &[SavedHunt] {
        &self.snapshot.hunts
    }

    pub fn hunt_runs(&self, hunt_id: &str) -> Vec<&HuntRun> {
        self.snapshot
            .hunt_runs
            .iter()
            .filter(|run| run.hunt_id == hunt_id)
            .collect()
    }

    pub fn link_hunt_run_case(&mut self, run_id: &str, case_id: u64) -> bool {
        if let Some(run) = self
            .snapshot
            .hunt_runs
            .iter_mut()
            .find(|candidate| candidate.id == run_id)
        {
            run.case_id = Some(case_id);
            self.persist();
            return true;
        }
        false
    }

    pub fn suppressions(&self) -> &[AlertSuppression] {
        &self.snapshot.suppressions
    }

    pub fn connectors(&self) -> &[EnrichmentConnector] {
        &self.snapshot.connectors
    }

    pub fn ticket_syncs(&self) -> &[TicketSyncRecord] {
        &self.snapshot.ticket_syncs
    }

    pub fn idp_providers(&self) -> &[IdentityProviderConfig] {
        &self.snapshot.idp_providers
    }

    pub fn scim(&self) -> &ScimConfig {
        &self.snapshot.scim
    }

    pub fn idp_provider_summaries(&self) -> Vec<IdentityProviderSummary> {
        self.snapshot
            .idp_providers
            .iter()
            .cloned()
            .map(|provider| IdentityProviderSummary {
                validation: validate_idp_provider_config(&provider),
                provider,
            })
            .collect()
    }

    pub fn scim_validation(&self) -> IdentityConfigValidation {
        validate_scim_config(&self.snapshot.scim)
    }

    pub fn change_control(&self) -> &[ChangeControlEntry] {
        &self.snapshot.change_control
    }

    pub fn metrics(&self) -> &OperationalMetrics {
        &self.snapshot.metrics
    }

    pub fn playbook_history(&self) -> &[PlaybookAnalyticsRecord] {
        &self.snapshot.playbook_history
    }

    pub fn rollout_history(&self) -> &[RolloutAnalyticsRecord] {
        &self.snapshot.rollout_history
    }

    pub fn record_change(
        &mut self,
        category: &str,
        target: &str,
        summary: &str,
        requested_by: &str,
        reference_id: Option<String>,
        payload: Option<&str>,
    ) -> ChangeControlEntry {
        let entry = ChangeControlEntry {
            id: self.next_id("chg"),
            category: category.to_string(),
            target: target.to_string(),
            summary: summary.to_string(),
            requested_by: requested_by.to_string(),
            status: "approved".to_string(),
            created_at: now_rfc3339(),
            executed_at: Some(now_rfc3339()),
            payload_hash: payload.map(|value| sha256_hex(value.as_bytes())),
            reference_id,
        };
        self.snapshot.change_control.push(entry.clone());
        self.persist();
        entry
    }

    pub fn record_search_metrics(&mut self, latency_ms: u64) {
        self.snapshot.metrics.search_queries_total += 1;
        self.snapshot.metrics.last_search_latency_ms = latency_ms;
        self.snapshot.metrics.last_search_at = Some(now_rfc3339());
        self.persist();
    }

    pub fn record_hunt_metrics(&mut self, latency_ms: u64) {
        self.snapshot.metrics.hunt_runs_total += 1;
        self.snapshot.metrics.last_hunt_latency_ms = latency_ms;
        self.snapshot.metrics.last_hunt_at = Some(now_rfc3339());
        self.persist();
    }

    pub fn record_response_metrics(&mut self, latency_ms: u64) {
        self.snapshot.metrics.response_exec_total += 1;
        self.snapshot.metrics.last_response_latency_ms = latency_ms;
        self.snapshot.metrics.last_response_at = Some(now_rfc3339());
        self.persist();
    }

    pub fn record_ticket_sync_metrics(&mut self, latency_ms: u64) {
        self.snapshot.metrics.ticket_sync_total += 1;
        self.snapshot.metrics.last_ticket_sync_latency_ms = latency_ms;
        self.snapshot.metrics.last_ticket_sync_at = Some(now_rfc3339());
        self.persist();
    }

    pub fn record_playbook_execution(
        &mut self,
        execution: &crate::playbook::PlaybookExecution,
    ) -> PlaybookAnalyticsRecord {
        let record = PlaybookAnalyticsRecord {
            execution_id: execution.execution_id.clone(),
            playbook_id: execution.playbook_id.clone(),
            alert_id: execution.alert_id.clone(),
            executed_by: execution.executed_by.clone(),
            status: playbook_status_label(&execution.status).to_string(),
            started_at: millis_to_rfc3339(execution.started_at),
            finished_at: execution.finished_at.map(millis_to_rfc3339),
            duration_ms: execution
                .finished_at
                .map(|finished_at| finished_at.saturating_sub(execution.started_at)),
            step_count: execution.step_results.len(),
            error: execution.error.clone(),
            recorded_at: now_rfc3339(),
        };
        if let Some(index) = self
            .snapshot
            .playbook_history
            .iter()
            .position(|entry| entry.execution_id == record.execution_id)
        {
            self.snapshot.playbook_history.remove(index);
        }
        self.snapshot.playbook_history.push(record.clone());
        if self.snapshot.playbook_history.len() > ANALYTICS_HISTORY_LIMIT {
            let overflow = self.snapshot.playbook_history.len() - ANALYTICS_HISTORY_LIMIT;
            self.snapshot.playbook_history.drain(0..overflow);
        }
        self.persist();
        record
    }

    pub fn record_rollout_event(
        &mut self,
        action: &str,
        version: &str,
        platform: Option<String>,
        agent_id: Option<String>,
        rollout_group: Option<String>,
        status: &str,
        requested_by: &str,
        notes: Option<String>,
    ) -> RolloutAnalyticsRecord {
        let record = RolloutAnalyticsRecord {
            id: self.next_id("rollout"),
            action: action.trim().to_ascii_lowercase(),
            version: version.trim().to_string(),
            platform: normalize_optional_text(platform),
            agent_id: normalize_optional_text(agent_id),
            rollout_group: normalize_optional_text(rollout_group),
            status: status.trim().to_ascii_lowercase(),
            requested_by: requested_by.to_string(),
            notes: normalize_optional_text(notes),
            recorded_at: now_rfc3339(),
        };
        self.snapshot.rollout_history.push(record.clone());
        if self.snapshot.rollout_history.len() > ANALYTICS_HISTORY_LIMIT {
            let overflow = self.snapshot.rollout_history.len() - ANALYTICS_HISTORY_LIMIT;
            self.snapshot.rollout_history.drain(0..overflow);
        }
        self.persist();
        record
    }

    pub fn active_suppression_count(&self) -> usize {
        self.snapshot
            .suppressions
            .iter()
            .filter(|suppression| suppression.is_active())
            .count()
    }

    pub fn event_is_suppressed(
        &self,
        event: &StoredEvent,
        rule_id: Option<&str>,
        hunt_id: Option<&str>,
    ) -> bool {
        self.snapshot
            .suppressions
            .iter()
            .any(|suppression| suppression.matches_event(event, rule_id, hunt_id))
    }

    pub fn apply_active_native_rules(&self, alert: &mut AlertRecord, agent_id: &str) -> usize {
        let pseudo_event = StoredEvent {
            id: 0,
            agent_id: agent_id.to_string(),
            received_at: alert.timestamp.clone(),
            alert: alert.clone(),
            correlated: false,
            triage: Default::default(),
        };
        let mut matched = 0usize;
        for rule in &self.snapshot.native_rules {
            if !rule.metadata.enabled
                || !matches!(
                    rule.metadata.lifecycle,
                    ContentLifecycle::Active | ContentLifecycle::Canary | ContentLifecycle::Test
                )
            {
                continue;
            }
            if !search_query_matches_event(&pseudo_event, &rule.query) {
                continue;
            }
            matched += 1;
            let reason = format!("native_rule:{}", rule.metadata.id);
            if !alert.reasons.iter().any(|existing| existing == &reason) {
                alert.reasons.push(reason);
            }
            for attack in &rule.metadata.attack {
                if !alert
                    .mitre
                    .iter()
                    .any(|existing| existing.technique_id == attack.technique_id)
                {
                    alert.mitre.push(attack.clone());
                }
            }
        }
        matched
    }

    pub fn create_or_update_hunt(
        &mut self,
        id: Option<&str>,
        name: String,
        owner: String,
        severity: String,
        threshold: usize,
        suppression_window_secs: u64,
        schedule_interval_secs: Option<u64>,
        schedule_cron: Option<String>,
        query: SearchQuery,
        hypothesis: String,
        expected_outcome: HuntExpectedOutcome,
        lifecycle: ContentLifecycle,
        canary_percentage: u8,
        pack_id: Option<String>,
        recommended_workflows: Vec<String>,
        target_group: Option<String>,
    ) -> SavedHunt {
        let normalized_canary = if matches!(lifecycle, ContentLifecycle::Canary) {
            canary_percentage.clamp(1, 100)
        } else {
            100
        };
        let normalized_pack_id = normalize_optional_text(pack_id);
        let normalized_workflows = normalize_string_list(recommended_workflows);
        let normalized_target_group = normalize_optional_text(target_group);
        let normalized_hypothesis = hypothesis.trim().to_string();
        let normalized_schedule_cron = normalize_optional_text(schedule_cron);
        if let Some(existing_id) = id
            && let Some(index) = self
                .snapshot
                .hunts
                .iter()
                .position(|hunt| hunt.id == existing_id)
        {
            let updated = {
                let hunt = &mut self.snapshot.hunts[index];
                hunt.name = name;
                hunt.owner = owner;
                hunt.severity = severity;
                hunt.threshold = threshold;
                hunt.suppression_window_secs = suppression_window_secs;
                hunt.schedule_interval_secs = schedule_interval_secs;
                hunt.schedule_cron = normalized_schedule_cron;
                hunt.query = query;
                hunt.hypothesis = normalized_hypothesis;
                hunt.expected_outcome = expected_outcome;
                hunt.lifecycle = lifecycle;
                hunt.canary_percentage = normalized_canary;
                hunt.pack_id = normalized_pack_id;
                hunt.recommended_workflows = normalized_workflows;
                hunt.target_group = normalized_target_group;
                hunt.updated_at = now_rfc3339();
                hunt.clone()
            };
            self.persist();
            return updated;
        }
        let created_at = now_rfc3339();
        let hunt = SavedHunt {
            id: self.next_id("hunt"),
            name,
            owner,
            enabled: true,
            severity,
            threshold,
            suppression_window_secs,
            schedule_interval_secs,
            schedule_cron: normalized_schedule_cron,
            last_run_at: None,
            next_run_at: schedule_interval_secs.map(|secs| {
                (chrono::Utc::now() + chrono::Duration::seconds(secs as i64)).to_rfc3339()
            }),
            query,
            hypothesis: normalized_hypothesis,
            expected_outcome,
            created_at: created_at.clone(),
            updated_at: created_at,
            lifecycle,
            canary_percentage: normalized_canary,
            pack_id: normalized_pack_id,
            recommended_workflows: normalized_workflows,
            target_group: normalized_target_group,
            response_actions: Vec::new(),
            tags: Vec::new(),
            mitre_techniques: Vec::new(),
        };
        self.snapshot.hunts.push(hunt.clone());
        self.persist();
        hunt
    }

    pub fn due_hunt_ids(&self) -> Vec<String> {
        let now = chrono::Utc::now();
        self.snapshot
            .hunts
            .iter()
            .filter(|hunt| {
                hunt.enabled
                    && (hunt.schedule_interval_secs.is_some() || hunt.schedule_cron.is_some())
            })
            .filter(|hunt| {
                let interval_due = hunt
                    .next_run_at
                    .as_deref()
                    .and_then(parse_time)
                    .is_some_and(|next| next <= now);
                let cron_due_now = hunt
                    .schedule_cron
                    .as_deref()
                    .is_some_and(|expr| cron_is_due(expr, now, hunt.last_run_at.as_deref()));
                interval_due || cron_due_now
            })
            .map(|hunt| hunt.id.clone())
            .collect()
    }

    pub fn run_hunt(
        &mut self,
        hunt_id: &str,
        events: &[StoredEvent],
        time_from: Option<chrono::DateTime<chrono::Utc>>,
        time_to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<HuntRun, String> {
        let hunt_index = self
            .snapshot
            .hunts
            .iter()
            .position(|hunt| hunt.id == hunt_id)
            .ok_or_else(|| "hunt not found".to_string())?;

        let hunt = self.snapshot.hunts[hunt_index].clone();
        let matches: Vec<&StoredEvent> = events
            .iter()
            .filter(|event| {
                let received_at = parse_time(&event.received_at);
                if let (Some(received), Some(from)) = (received_at, time_from)
                    && received < from
                {
                    return false;
                }
                if let (Some(received), Some(to)) = (received_at, time_to)
                    && received > to
                {
                    return false;
                }
                true
            })
            .filter(|event| search_query_matches_event(event, &hunt.query))
            .collect();
        let suppressed_matches: Vec<&StoredEvent> = matches
            .iter()
            .copied()
            .filter(|event| self.event_is_suppressed(event, None, Some(hunt_id)))
            .collect();
        let visible_matches: Vec<&StoredEvent> = matches
            .into_iter()
            .filter(|event| !self.event_is_suppressed(event, None, Some(hunt_id)))
            .collect();
        let run = HuntRun {
            id: self.next_id("hrun"),
            hunt_id: hunt.id.clone(),
            run_at: now_rfc3339(),
            match_count: visible_matches.len(),
            suppressed_count: suppressed_matches.len(),
            threshold_exceeded: visible_matches.len() >= hunt.threshold,
            severity: hunt.severity.clone(),
            case_id: None,
            time_from: time_from.map(|dt| dt.to_rfc3339()),
            time_to: time_to.map(|dt| dt.to_rfc3339()),
            yield_rate: if visible_matches.is_empty() {
                0.0
            } else {
                visible_matches.len() as f32
                    / (visible_matches.len() + suppressed_matches.len()) as f32
            },
            matched_event_ids: visible_matches.iter().map(|event| event.id).collect(),
            matched_agent_ids: visible_matches
                .iter()
                .map(|event| event.agent_id.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect(),
            sample_event_ids: visible_matches
                .iter()
                .take(10)
                .map(|event| event.id)
                .collect(),
            summary: format!(
                "{} matched {} event(s){}",
                hunt.name,
                visible_matches.len(),
                if suppressed_matches.is_empty() {
                    String::new()
                } else {
                    format!(" ({} suppressed)", suppressed_matches.len())
                }
            ),
        };
        self.snapshot.hunt_runs.push(run.clone());
        if let Some(hunt_mut) = self.snapshot.hunts.get_mut(hunt_index) {
            hunt_mut.last_run_at = Some(run.run_at.clone());
            hunt_mut.next_run_at = hunt_mut.schedule_interval_secs.map(|secs| {
                (chrono::Utc::now() + chrono::Duration::seconds(secs as i64)).to_rfc3339()
            });
            if hunt_mut.next_run_at.is_none() && hunt_mut.schedule_cron.is_some() {
                hunt_mut.next_run_at =
                    Some((chrono::Utc::now() + chrono::Duration::minutes(1)).to_rfc3339());
            }
            hunt_mut.updated_at = now_rfc3339();
        }
        self.persist();
        Ok(run)
    }

    pub fn create_or_update_native_rule(
        &mut self,
        id: Option<&str>,
        title: String,
        description: String,
        owner: String,
        severity_mapping: String,
        rationale: Option<String>,
        pack_ids: Vec<String>,
        attack: Vec<MitreAttack>,
        query: SearchQuery,
    ) -> NativeContentRule {
        if let Some(existing_id) = id
            && let Some(index) = self
                .snapshot
                .native_rules
                .iter()
                .position(|rule| rule.metadata.id == existing_id)
        {
            let updated = {
                let rule = &mut self.snapshot.native_rules[index];
                rule.metadata.title = title;
                rule.metadata.description = description;
                rule.metadata.owner = owner;
                rule.metadata.pack_ids = pack_ids;
                rule.metadata.attack = attack;
                rule.metadata.updated_at = now_rfc3339();
                rule.severity_mapping = severity_mapping;
                rule.rationale = rationale;
                rule.query = query;
                rule.clone()
            };
            self.bootstrap_builtin_sigma();
            self.persist();
            return updated;
        }
        let created_at = now_rfc3339();
        let rule = NativeContentRule {
            metadata: ManagedRuleMetadata {
                id: self.next_id("nat"),
                title,
                description,
                owner,
                kind: ContentKind::Native,
                builtin: false,
                enabled: true,
                lifecycle: ContentLifecycle::Draft,
                previous_lifecycle: None,
                version: 1,
                pack_ids,
                attack,
                false_positive_review: None,
                last_test_at: None,
                last_test_match_count: 0,
                last_promotion_at: None,
                created_at: created_at.clone(),
                updated_at: created_at,
                lifecycle_history: Vec::new(),
            },
            query,
            severity_mapping,
            rationale,
        };
        self.snapshot.native_rules.push(rule.clone());
        self.bootstrap_builtin_sigma();
        self.persist();
        rule
    }

    pub fn update_builtin_metadata(
        &mut self,
        id: &str,
        owner: Option<String>,
        enabled: Option<bool>,
        pack_ids: Option<Vec<String>>,
        false_positive_review: Option<String>,
    ) -> Result<ManagedRuleMetadata, String> {
        let rule = self
            .snapshot
            .builtin_rules
            .iter_mut()
            .find(|rule| rule.id == id)
            .ok_or_else(|| "content rule not found".to_string())?;
        if let Some(owner) = owner {
            rule.owner = owner;
        }
        if let Some(enabled) = enabled {
            rule.enabled = enabled;
        }
        if let Some(pack_ids) = pack_ids {
            rule.pack_ids = pack_ids;
        }
        if let Some(review) = false_positive_review {
            rule.false_positive_review = Some(review);
        }
        rule.updated_at = now_rfc3339();
        let updated = rule.clone();
        self.bootstrap_builtin_sigma();
        self.persist();
        Ok(updated)
    }

    pub fn find_rule_metadata(&self, id: &str) -> Option<ManagedRuleMetadata> {
        self.snapshot
            .builtin_rules
            .iter()
            .find(|rule| rule.id == id)
            .cloned()
            .or_else(|| {
                self.snapshot
                    .native_rules
                    .iter()
                    .find(|rule| rule.metadata.id == id)
                    .map(|rule| rule.metadata.clone())
            })
    }

    pub fn promote_rule(
        &mut self,
        rule_id: &str,
        target: ContentLifecycle,
        actor: &str,
        reason: &str,
    ) -> Result<ManagedRuleMetadata, String> {
        let target_label = lifecycle_slug(&target).to_string();
        let (updated, previous_label) = if let Some(rule) = self
            .snapshot
            .builtin_rules
            .iter_mut()
            .find(|rule| rule.id == rule_id)
        {
            let previous = rule.lifecycle.clone();
            let previous_label = lifecycle_slug(&previous).to_string();
            rule.previous_lifecycle = Some(previous.clone());
            rule.lifecycle = target.clone();
            rule.version += 1;
            rule.last_promotion_at = Some(now_rfc3339());
            rule.updated_at = now_rfc3339();
            rule.lifecycle_history.push(LifecycleChange {
                changed_at: now_rfc3339(),
                changed_by: actor.to_string(),
                from: previous,
                to: target,
                reason: reason.to_string(),
            });
            (rule.clone(), previous_label)
        } else if let Some(rule) = self
            .snapshot
            .native_rules
            .iter_mut()
            .find(|rule| rule.metadata.id == rule_id)
        {
            let previous = rule.metadata.lifecycle.clone();
            let previous_label = lifecycle_slug(&previous).to_string();
            rule.metadata.previous_lifecycle = Some(previous.clone());
            rule.metadata.lifecycle = target.clone();
            rule.metadata.version += 1;
            rule.metadata.last_promotion_at = Some(now_rfc3339());
            rule.metadata.updated_at = now_rfc3339();
            rule.metadata.lifecycle_history.push(LifecycleChange {
                changed_at: now_rfc3339(),
                changed_by: actor.to_string(),
                from: previous,
                to: target,
                reason: reason.to_string(),
            });
            (rule.metadata.clone(), previous_label)
        } else {
            return Err("content rule not found".to_string());
        };
        self.record_rollout_event(
            "content-promote",
            &format!("{} v{}", updated.title, updated.version),
            Some("content-rule".to_string()),
            Some(updated.id.clone()),
            Some(target_label.clone()),
            "succeeded",
            actor,
            Some(format!(
                "Rule {} moved from {} to {}: {}",
                updated.id, previous_label, target_label, reason
            )),
        );
        Ok(updated)
    }

    pub fn rollback_rule(
        &mut self,
        rule_id: &str,
        actor: &str,
    ) -> Result<ManagedRuleMetadata, String> {
        let (updated, current_label, target_label) = if let Some(rule) = self
            .snapshot
            .builtin_rules
            .iter_mut()
            .find(|rule| rule.id == rule_id)
        {
            let target = rule
                .previous_lifecycle
                .clone()
                .unwrap_or(ContentLifecycle::Test);
            let current = rule.lifecycle.clone();
            let current_label = lifecycle_slug(&current).to_string();
            let target_label = lifecycle_slug(&target).to_string();
            rule.lifecycle = target.clone();
            rule.previous_lifecycle = Some(current.clone());
            rule.updated_at = now_rfc3339();
            rule.lifecycle_history.push(LifecycleChange {
                changed_at: now_rfc3339(),
                changed_by: actor.to_string(),
                from: current,
                to: target,
                reason: "rollback".to_string(),
            });
            (rule.clone(), current_label, target_label)
        } else if let Some(rule) = self
            .snapshot
            .native_rules
            .iter_mut()
            .find(|rule| rule.metadata.id == rule_id)
        {
            let target = rule
                .metadata
                .previous_lifecycle
                .clone()
                .unwrap_or(ContentLifecycle::Draft);
            let current = rule.metadata.lifecycle.clone();
            let current_label = lifecycle_slug(&current).to_string();
            let target_label = lifecycle_slug(&target).to_string();
            rule.metadata.lifecycle = target.clone();
            rule.metadata.previous_lifecycle = Some(current.clone());
            rule.metadata.updated_at = now_rfc3339();
            rule.metadata.lifecycle_history.push(LifecycleChange {
                changed_at: now_rfc3339(),
                changed_by: actor.to_string(),
                from: current,
                to: target,
                reason: "rollback".to_string(),
            });
            (rule.metadata.clone(), current_label, target_label)
        } else {
            return Err("content rule not found".to_string());
        };
        self.record_rollout_event(
            "content-rollback",
            &format!("{} v{}", updated.title, updated.version),
            Some("content-rule".to_string()),
            Some(updated.id.clone()),
            Some(target_label.clone()),
            "succeeded",
            actor,
            Some(format!(
                "Rule {} rolled back from {} to {}.",
                updated.id, current_label, target_label
            )),
        );
        Ok(updated)
    }

    /// Automatically promote canary rules to active and rollback degrading
    /// canary rules based on detection efficacy data.
    ///
    /// Rules in the `Canary` lifecycle are eligible for promotion when they
    /// have accumulated at least `min_alerts` resolved triage records with
    /// zero false positives and have been in canary for at least `min_days`.
    ///
    /// Canary rules whose FP rate exceeds `max_fp_rate` are automatically
    /// rolled back to `Test` to prevent analyst fatigue.
    pub fn canary_auto_promote(
        &mut self,
        efficacy: &[crate::detection_efficacy::RuleEfficacy],
        min_alerts: usize,
        min_days: u64,
        max_fp_rate: f32,
    ) -> Vec<CanaryPromotionResult> {
        let now = chrono::Utc::now();
        let min_duration = chrono::Duration::days(min_days as i64);
        let efficacy_map: std::collections::HashMap<
            &str,
            &crate::detection_efficacy::RuleEfficacy,
        > = efficacy.iter().map(|e| (e.rule_id.as_str(), e)).collect();

        let mut results = Vec::new();

        // Collect canary rule IDs first to avoid borrow issues
        let canary_ids: Vec<(String, Option<String>)> = self
            .snapshot
            .builtin_rules
            .iter()
            .filter(|r| r.lifecycle == ContentLifecycle::Canary)
            .map(|r| (r.id.clone(), r.last_promotion_at.clone()))
            .chain(
                self.snapshot
                    .native_rules
                    .iter()
                    .filter(|r| r.metadata.lifecycle == ContentLifecycle::Canary)
                    .map(|r| (r.metadata.id.clone(), r.metadata.last_promotion_at.clone())),
            )
            .collect();

        for (rule_id, last_promotion_at) in &canary_ids {
            let in_canary_long_enough = last_promotion_at
                .as_deref()
                .and_then(parse_time)
                .is_some_and(|promoted_at| now - promoted_at >= min_duration);

            let eff = efficacy_map.get(rule_id.as_str());

            // Rollback: FP rate exceeds threshold
            if let Some(e) = eff
                && e.total_alerts >= min_alerts
                && e.fp_rate > max_fp_rate
                && let Ok(meta) = self.rollback_rule(rule_id, "canary-auto-promote")
            {
                results.push(CanaryPromotionResult {
                    rule_id: rule_id.clone(),
                    rule_name: meta.title.clone(),
                    action: CanaryAction::RolledBack,
                    reason: format!(
                        "FP rate {:.1}% exceeds threshold {:.1}%",
                        e.fp_rate * 100.0,
                        max_fp_rate * 100.0
                    ),
                });
                continue;
            }

            // Promote: enough alerts, zero FPs, enough time in canary
            if let Some(e) = eff
                && in_canary_long_enough
                && e.total_alerts >= min_alerts
                && e.false_positives == 0
                && let Ok(meta) = self.promote_rule(
                    rule_id,
                    ContentLifecycle::Active,
                    "canary-auto-promote",
                    &format!(
                        "auto-promoted after {} alerts with 0 FPs over {}+ days",
                        e.total_alerts, min_days
                    ),
                )
            {
                results.push(CanaryPromotionResult {
                    rule_id: rule_id.clone(),
                    rule_name: meta.title.clone(),
                    action: CanaryAction::Promoted,
                    reason: format!(
                        "{} alerts, 0 FPs, canary duration satisfied",
                        e.total_alerts
                    ),
                });
                continue;
            }

            // No action yet
            results.push(CanaryPromotionResult {
                rule_id: rule_id.clone(),
                rule_name: eff.map(|e| e.rule_name.clone()).unwrap_or_default(),
                action: CanaryAction::NoChange,
                reason: if eff.is_none() {
                    "no efficacy data yet".to_string()
                } else if !in_canary_long_enough {
                    format!("canary period < {min_days} days")
                } else {
                    format!(
                        "only {} of {min_alerts} required alerts",
                        eff.map_or(0, |e| e.total_alerts)
                    )
                },
            });
        }
        results
    }

    pub fn test_rule(
        &mut self,
        rule_id: &str,
        events: &[StoredEvent],
    ) -> Result<RuleTestResult, String> {
        let previous = self
            .snapshot
            .rule_tests
            .iter()
            .filter(|result| result.rule_id == rule_id)
            .max_by(|a, b| a.tested_at.cmp(&b.tested_at))
            .cloned();

        let (match_ids, suppressed_ids) = if self
            .snapshot
            .builtin_rules
            .iter()
            .any(|rule| rule.id == rule_id)
        {
            let rules = builtin_rules();
            let sigma_rule = rules
                .into_iter()
                .find(|rule| rule.id == rule_id)
                .ok_or_else(|| "builtin sigma rule not found".to_string())?;
            let mut engine = SigmaEngine::new();
            engine.add_rule(sigma_rule);
            let mut match_ids = Vec::new();
            let mut suppressed_ids = Vec::new();
            for event in events {
                let ocsf_event = ocsf::alert_to_ocsf(&event.alert);
                let matched = engine.evaluate(&ocsf_event, 0);
                if matched.is_empty() {
                    continue;
                }
                if self.event_is_suppressed(event, Some(rule_id), None) {
                    suppressed_ids.push(event.id);
                } else {
                    match_ids.push(event.id);
                }
            }
            (match_ids, suppressed_ids)
        } else {
            let rule = self
                .snapshot
                .native_rules
                .iter()
                .find(|rule| rule.metadata.id == rule_id)
                .cloned()
                .ok_or_else(|| "content rule not found".to_string())?;
            let mut match_ids = Vec::new();
            let mut suppressed_ids = Vec::new();
            for event in events {
                if !search_query_matches_event(event, &rule.query) {
                    continue;
                }
                if self.event_is_suppressed(event, Some(rule_id), None) {
                    suppressed_ids.push(event.id);
                } else {
                    match_ids.push(event.id);
                }
            }
            (match_ids, suppressed_ids)
        };

        let previous_ids: HashSet<u64> = previous
            .as_ref()
            .map(|result| result.sample_event_ids.iter().copied().collect())
            .unwrap_or_default();
        let _current_ids: HashSet<u64> = match_ids.iter().copied().collect();
        // Use only the truncated sample set for diff so both sides are comparable
        let current_sample: HashSet<u64> = match_ids.iter().copied().take(25).collect();
        let new_match_ids: Vec<u64> = current_sample.difference(&previous_ids).copied().collect();
        let cleared_match_ids: Vec<u64> =
            previous_ids.difference(&current_sample).copied().collect();

        let result = RuleTestResult {
            id: self.next_id("rtest"),
            rule_id: rule_id.to_string(),
            tested_at: now_rfc3339(),
            match_count: match_ids.len(),
            suppressed_count: suppressed_ids.len(),
            sample_event_ids: match_ids.iter().copied().take(25).collect(),
            new_match_ids,
            cleared_match_ids,
            summary: format!(
                "Rule {} matched {} event(s){}",
                rule_id,
                match_ids.len(),
                if suppressed_ids.is_empty() {
                    String::new()
                } else {
                    format!(" ({} suppressed)", suppressed_ids.len())
                }
            ),
        };
        self.snapshot.rule_tests.push(result.clone());
        if let Some(rule) = self
            .snapshot
            .builtin_rules
            .iter_mut()
            .find(|rule| rule.id == rule_id)
        {
            rule.last_test_at = Some(result.tested_at.clone());
            rule.last_test_match_count = result.match_count;
        }
        if let Some(rule) = self
            .snapshot
            .native_rules
            .iter_mut()
            .find(|rule| rule.metadata.id == rule_id)
        {
            rule.metadata.last_test_at = Some(result.tested_at.clone());
            rule.metadata.last_test_match_count = result.match_count;
        }
        self.persist();
        Ok(result)
    }

    pub fn create_or_update_pack(
        &mut self,
        id: Option<&str>,
        name: String,
        description: String,
        enabled: bool,
        rule_ids: Vec<String>,
        saved_searches: Vec<String>,
        recommended_workflows: Vec<String>,
        target_group: Option<String>,
        rollout_notes: Option<String>,
    ) -> ContentPack {
        let normalized_rule_ids = normalize_string_list(rule_ids);
        let normalized_saved_searches = normalize_string_list(saved_searches);
        let normalized_workflows = normalize_string_list(recommended_workflows);
        let normalized_target_group = normalize_optional_text(target_group);
        let normalized_rollout_notes = normalize_optional_text(rollout_notes);
        if let Some(id) = id
            && let Some(index) = self.snapshot.packs.iter().position(|pack| pack.id == id)
        {
            let pack_id = self.snapshot.packs[index].id.clone();
            let updated = {
                let pack = &mut self.snapshot.packs[index];
                pack.name = name;
                pack.description = description;
                pack.enabled = enabled;
                pack.rule_ids = normalized_rule_ids.clone();
                pack.saved_searches = normalized_saved_searches.clone();
                pack.recommended_workflows = normalized_workflows.clone();
                pack.target_group = normalized_target_group.clone();
                pack.rollout_notes = normalized_rollout_notes.clone();
                pack.updated_at = now_rfc3339();
                pack.clone()
            };
            for rule in &mut self.snapshot.builtin_rules {
                if normalized_rule_ids.contains(&rule.id) {
                    if !rule.pack_ids.contains(&pack_id) {
                        rule.pack_ids.push(pack_id.clone());
                    }
                } else {
                    rule.pack_ids.retain(|existing| existing != &pack_id);
                }
            }
            for rule in &mut self.snapshot.native_rules {
                if normalized_rule_ids.contains(&rule.metadata.id) {
                    if !rule.metadata.pack_ids.contains(&pack_id) {
                        rule.metadata.pack_ids.push(pack_id.clone());
                    }
                } else {
                    rule.metadata
                        .pack_ids
                        .retain(|existing| existing != &pack_id);
                }
            }
            self.persist();
            return updated;
        }
        let pack_id = id.unwrap_or(&self.next_id("pack")).to_string();
        let pack = ContentPack {
            id: pack_id.clone(),
            name,
            description,
            use_case: "custom".to_string(),
            enabled,
            rule_ids: normalized_rule_ids.clone(),
            saved_searches: normalized_saved_searches,
            recommended_workflows: normalized_workflows,
            target_group: normalized_target_group,
            rollout_notes: normalized_rollout_notes,
            updated_at: now_rfc3339(),
        };
        for rule in &mut self.snapshot.builtin_rules {
            if normalized_rule_ids.contains(&rule.id) && !rule.pack_ids.contains(&pack_id) {
                rule.pack_ids.push(pack_id.clone());
            }
        }
        for rule in &mut self.snapshot.native_rules {
            if normalized_rule_ids.contains(&rule.metadata.id)
                && !rule.metadata.pack_ids.contains(&pack_id)
            {
                rule.metadata.pack_ids.push(pack_id.clone());
            }
        }
        self.snapshot.packs.push(pack.clone());
        self.persist();
        pack
    }

    pub fn create_or_update_suppression(
        &mut self,
        id: Option<&str>,
        name: String,
        rule_id: Option<String>,
        hunt_id: Option<String>,
        hostname: Option<String>,
        agent_id: Option<String>,
        severity: Option<String>,
        text: Option<String>,
        expires_at: Option<String>,
        justification: String,
        actor: String,
        active: bool,
    ) -> AlertSuppression {
        if let Some(existing_id) = id
            && let Some(index) = self
                .snapshot
                .suppressions
                .iter()
                .position(|suppression| suppression.id == existing_id)
        {
            let updated = {
                let suppression = &mut self.snapshot.suppressions[index];
                suppression.name = name;
                suppression.rule_id = rule_id;
                suppression.hunt_id = hunt_id;
                suppression.hostname = hostname;
                suppression.agent_id = agent_id;
                suppression.severity = severity;
                suppression.text = text;
                suppression.expires_at = expires_at;
                suppression.justification = justification.clone();
                suppression.active = active;
                suppression.audit.push(AlertSuppressionAuditEntry {
                    timestamp: now_rfc3339(),
                    actor,
                    action: if active { "updated" } else { "disabled" }.to_string(),
                    reason: justification,
                });
                suppression.clone()
            };
            self.persist();
            return updated;
        }
        let suppression = AlertSuppression {
            id: self.next_id("supp"),
            name,
            rule_id,
            hunt_id,
            hostname,
            agent_id,
            severity,
            text,
            expires_at,
            justification: justification.clone(),
            created_by: actor.clone(),
            created_at: now_rfc3339(),
            active,
            audit: vec![AlertSuppressionAuditEntry {
                timestamp: now_rfc3339(),
                actor,
                action: "created".to_string(),
                reason: justification,
            }],
        };
        self.snapshot.suppressions.push(suppression.clone());
        self.persist();
        suppression
    }

    pub fn create_or_update_connector(
        &mut self,
        id: Option<&str>,
        kind: String,
        display_name: String,
        endpoint: Option<String>,
        auth_mode: Option<String>,
        enabled: bool,
        timeout_secs: u64,
        metadata: HashMap<String, String>,
    ) -> EnrichmentConnector {
        if let Some(id) = id
            && let Some(index) = self
                .snapshot
                .connectors
                .iter()
                .position(|connector| connector.id == id)
        {
            let updated = {
                let connector = &mut self.snapshot.connectors[index];
                connector.kind = kind;
                connector.display_name = display_name;
                connector.endpoint = endpoint;
                connector.auth_mode = auth_mode;
                connector.enabled = enabled;
                connector.timeout_secs = timeout_secs;
                connector.metadata = metadata;
                connector.status = if enabled {
                    "ready".to_string()
                } else {
                    "disabled".to_string()
                };
                connector.last_error = None;
                connector.clone()
            };
            self.persist();
            return updated;
        }
        let connector = EnrichmentConnector {
            id: self.next_id("conn"),
            kind,
            display_name,
            endpoint,
            auth_mode,
            enabled,
            status: if enabled {
                "ready".to_string()
            } else {
                "disabled".to_string()
            },
            timeout_secs,
            last_sync_at: None,
            last_error: None,
            metadata,
        };
        self.snapshot.connectors.push(connector.clone());
        self.persist();
        connector
    }

    pub fn sync_ticket(
        &mut self,
        provider: String,
        object_kind: String,
        object_id: String,
        queue_or_project: Option<String>,
        summary: String,
        synced_by: String,
    ) -> TicketSyncRecord {
        if let Some(index) = self.snapshot.ticket_syncs.iter().position(|sync| {
            sync.provider == provider
                && sync.object_kind == object_kind
                && sync.object_id == object_id
        }) {
            let updated = {
                let existing = &mut self.snapshot.ticket_syncs[index];
                existing.sync_count += 1;
                existing.synced_at = now_rfc3339();
                existing.summary = summary;
                existing.status = "updated".to_string();
                existing.clone()
            };
            self.persist();
            return updated;
        }
        let external_key = format!(
            "{}-{}-{}",
            provider.to_ascii_uppercase(),
            object_kind.to_ascii_uppercase(),
            object_id
        );
        let record = TicketSyncRecord {
            id: self.next_id("ticket"),
            provider,
            object_kind,
            object_id,
            status: "created".to_string(),
            external_key,
            queue_or_project,
            summary,
            synced_by,
            synced_at: now_rfc3339(),
            sync_count: 1,
        };
        self.snapshot.ticket_syncs.push(record.clone());
        self.persist();
        record
    }

    pub fn create_or_update_idp_provider(
        &mut self,
        id: Option<&str>,
        kind: String,
        display_name: String,
        issuer_url: Option<String>,
        sso_url: Option<String>,
        client_id: Option<String>,
        client_secret: Option<String>,
        redirect_uri: Option<String>,
        entity_id: Option<String>,
        enabled: bool,
        group_role_mappings: HashMap<String, String>,
    ) -> Result<IdentityProviderConfig, String> {
        let normalized_kind = kind.trim().to_ascii_lowercase();
        if normalized_kind != "oidc" && normalized_kind != "saml" {
            return Err("identity provider kind must be 'oidc' or 'saml'".into());
        }
        let normalized_name = display_name.trim();
        if normalized_name.is_empty() {
            return Err("identity provider display_name cannot be empty".into());
        }
        let normalized_issuer_url = normalize_optional_text(issuer_url);
        let normalized_sso_url = normalize_optional_text(sso_url);
        let normalized_client_id = normalize_optional_text(client_id);
        let normalized_client_secret = if normalized_kind == "oidc" {
            normalize_optional_text(client_secret)
        } else {
            None
        };
        let normalized_redirect_uri = if normalized_kind == "oidc" {
            normalize_optional_text(redirect_uri)
        } else {
            None
        };
        let normalized_entity_id = normalize_optional_text(entity_id);
        let normalized_mappings = normalize_group_role_mappings(group_role_mappings)?;

        if enabled {
            if normalized_kind == "oidc" {
                if normalized_issuer_url.is_none() {
                    return Err("enabled OIDC providers require issuer_url".into());
                }
                if normalized_client_id.is_none() {
                    return Err("enabled OIDC providers require client_id".into());
                }
                if normalized_client_secret.is_none() {
                    return Err("enabled OIDC providers require client_secret".into());
                }
                if normalized_redirect_uri.is_none() {
                    return Err("enabled OIDC providers require redirect_uri".into());
                }
            } else {
                if normalized_sso_url.is_none() {
                    return Err("enabled SAML providers require sso_url".into());
                }
                if normalized_entity_id.is_none() {
                    return Err("enabled SAML providers require entity_id".into());
                }
            }
        }

        if let Some(id) = id
            && let Some(index) = self
                .snapshot
                .idp_providers
                .iter()
                .position(|provider| provider.id == id)
        {
            let existing_client_secret = self.snapshot.idp_providers[index].client_secret.clone();
            let effective_client_secret = if normalized_kind == "oidc" {
                normalized_client_secret
                    .clone()
                    .or(existing_client_secret.clone())
            } else {
                None
            };
            if enabled && normalized_kind == "oidc" {
                if effective_client_secret.is_none() {
                    return Err("enabled OIDC providers require client_secret".into());
                }
                if normalized_redirect_uri.is_none() {
                    return Err("enabled OIDC providers require redirect_uri".into());
                }
            }
            let updated = {
                let provider = &mut self.snapshot.idp_providers[index];
                provider.kind = normalized_kind;
                provider.display_name = normalized_name.to_string();
                provider.issuer_url = normalized_issuer_url;
                provider.sso_url = normalized_sso_url;
                provider.client_id = normalized_client_id;
                provider.client_secret = effective_client_secret;
                provider.redirect_uri = normalized_redirect_uri;
                provider.entity_id = normalized_entity_id;
                provider.enabled = enabled;
                provider.group_role_mappings = normalized_mappings;
                provider.status = if enabled {
                    "configured".to_string()
                } else {
                    "disabled".to_string()
                };
                provider.updated_at = now_rfc3339();
                provider.clone()
            };
            self.persist();
            return Ok(updated);
        }
        let provider = IdentityProviderConfig {
            id: self.next_id("idp"),
            kind: normalized_kind,
            display_name: normalized_name.to_string(),
            issuer_url: normalized_issuer_url,
            sso_url: normalized_sso_url,
            client_id: normalized_client_id,
            client_secret: normalized_client_secret,
            redirect_uri: normalized_redirect_uri,
            entity_id: normalized_entity_id,
            enabled,
            status: if enabled {
                "configured".to_string()
            } else {
                "disabled".to_string()
            },
            group_role_mappings: normalized_mappings,
            updated_at: now_rfc3339(),
        };
        self.snapshot.idp_providers.push(provider.clone());
        self.persist();
        Ok(provider)
    }

    pub fn update_scim(
        &mut self,
        enabled: bool,
        base_url: Option<String>,
        bearer_token: Option<String>,
        provisioning_mode: String,
        default_role: String,
        group_role_mappings: HashMap<String, String>,
    ) -> Result<ScimConfig, String> {
        let normalized_mode = provisioning_mode.trim().to_ascii_lowercase();
        if !SCIM_PROVISIONING_MODES.contains(&normalized_mode.as_str()) {
            return Err("scim provisioning_mode must be 'manual' or 'automatic'".into());
        }
        let normalized_default_role = normalize_identity_role(&default_role)?;
        let normalized_base_url = normalize_optional_text(base_url);
        let normalized_bearer_token = normalize_optional_text(bearer_token);
        let normalized_mappings = normalize_group_role_mappings(group_role_mappings)?;

        if enabled {
            if normalized_base_url.is_none() {
                return Err("enabled SCIM configuration requires base_url".into());
            }
            if normalized_bearer_token.is_none() {
                return Err("enabled SCIM configuration requires bearer_token".into());
            }
        }

        self.snapshot.scim.enabled = enabled;
        self.snapshot.scim.base_url = normalized_base_url;
        self.snapshot.scim.bearer_token = normalized_bearer_token;
        self.snapshot.scim.provisioning_mode = normalized_mode;
        self.snapshot.scim.default_role = normalized_default_role;
        self.snapshot.scim.group_role_mappings = normalized_mappings;
        self.snapshot.scim.status = if enabled {
            "configured".to_string()
        } else {
            "disabled".to_string()
        };
        self.snapshot.scim.updated_at = Some(now_rfc3339());
        self.persist();
        Ok(self.snapshot.scim.clone())
    }
}
