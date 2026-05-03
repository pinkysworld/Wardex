//! Fleet-wide attack campaign clustering.
//!
//! Groups related alerts and incidents across devices to identify
//! coordinated attack campaigns spanning the fleet.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// An alert summary suitable for cross-fleet correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetAlert {
    pub alert_id: String,
    pub hostname: String,
    pub timestamp_ms: u64,
    pub score: f32,
    pub level: String,
    pub reasons: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

/// A detected attack campaign spanning multiple hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub campaign_id: String,
    pub name: String,
    pub hosts: Vec<String>,
    pub alert_count: usize,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub avg_score: f32,
    pub max_score: f32,
    pub shared_techniques: Vec<String>,
    pub shared_reasons: Vec<String>,
    pub severity: String,
    pub alert_ids: Vec<String>,
}

/// A temporally adjacent alert burst on a single host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalChain {
    pub chain_id: String,
    pub host: String,
    pub alert_count: usize,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub avg_score: f32,
    pub max_score: f32,
    pub severity: String,
    pub shared_techniques: Vec<String>,
    pub shared_reasons: Vec<String>,
    pub alert_ids: Vec<String>,
}

/// Result of campaign analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
    pub campaigns: Vec<Campaign>,
    pub temporal_chains: Vec<TemporalChain>,
    pub unclustered_alerts: usize,
    pub total_alerts: usize,
    pub fleet_coverage: f32,
}

/// Campaign clustering engine.
pub struct CampaignDetector {
    /// Max time gap (ms) between related alerts in a campaign.
    pub time_window_ms: u64,
    /// Min shared techniques/reasons to link alerts.
    pub min_similarity: f32,
    /// Min hosts for a campaign.
    pub min_hosts: usize,
    next_id: u64,
}

impl Default for CampaignDetector {
    fn default() -> Self {
        Self {
            time_window_ms: 3_600_000, // 1 hour
            min_similarity: 0.3,
            min_hosts: 2,
            next_id: 1,
        }
    }
}

impl CampaignDetector {
    pub fn new(time_window_ms: u64, min_similarity: f32, min_hosts: usize) -> Self {
        Self {
            time_window_ms,
            min_similarity,
            min_hosts,
            next_id: 1,
        }
    }

    /// Detect campaigns from a set of fleet-wide alerts.
    pub fn detect(&mut self, alerts: &[FleetAlert]) -> CampaignReport {
        if alerts.is_empty() {
            return CampaignReport {
                campaigns: Vec::new(),
                temporal_chains: Vec::new(),
                unclustered_alerts: 0,
                total_alerts: 0,
                fleet_coverage: 0.0,
            };
        }

        // Sort by time
        let mut sorted: Vec<&FleetAlert> = alerts.iter().collect();
        sorted.sort_by_key(|a| a.timestamp_ms);

        // Build adjacency: alerts are linked if they share techniques/reasons
        // AND are within the time window
        let n = sorted.len();
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

        for i in 0..n {
            for j in (i + 1)..n {
                if sorted[j]
                    .timestamp_ms
                    .saturating_sub(sorted[i].timestamp_ms)
                    > self.time_window_ms
                {
                    break;
                }
                if sorted[i].hostname == sorted[j].hostname {
                    continue; // Same host doesn't count for cross-fleet
                }
                let sim = alert_similarity(sorted[i], sorted[j]);
                if sim >= self.min_similarity {
                    adj[i].push(j);
                    adj[j].push(i);
                }
            }
        }

        // Connected components
        let mut visited = vec![false; n];
        let mut components: Vec<Vec<usize>> = Vec::new();
        for i in 0..n {
            if visited[i] {
                continue;
            }
            let mut component = Vec::new();
            let mut stack = vec![i];
            while let Some(node) = stack.pop() {
                if visited[node] {
                    continue;
                }
                visited[node] = true;
                component.push(node);
                for &neighbor in &adj[node] {
                    if !visited[neighbor] {
                        stack.push(neighbor);
                    }
                }
            }
            components.push(component);
        }

        // Convert components to campaigns (only multi-host groups)
        let mut campaigns = Vec::new();
        let mut clustered = 0;
        let all_hosts: HashSet<&str> = alerts.iter().map(|a| a.hostname.as_str()).collect();

        for component in &components {
            let hosts: HashSet<&str> = component
                .iter()
                .map(|&i| sorted[i].hostname.as_str())
                .collect();
            if hosts.len() < self.min_hosts {
                continue;
            }

            let comp_alerts: Vec<&FleetAlert> = component.iter().map(|&i| sorted[i]).collect();
            let scores: Vec<f32> = comp_alerts.iter().map(|a| a.score).collect();
            let avg_score = scores.iter().sum::<f32>() / scores.len() as f32;
            let max_score = scores.iter().cloned().fold(0.0_f32, f32::max);

            let shared_techniques = find_shared_strings(
                &comp_alerts
                    .iter()
                    .map(|a| &a.mitre_techniques)
                    .collect::<Vec<_>>(),
            );
            let shared_reasons =
                find_shared_strings(&comp_alerts.iter().map(|a| &a.reasons).collect::<Vec<_>>());

            let severity = if max_score >= 5.0 {
                "Critical"
            } else if max_score >= 3.5 {
                "Severe"
            } else {
                "Elevated"
            };

            let cid = format!("campaign-{}", self.next_id);
            self.next_id += 1;
            let name = if !shared_techniques.is_empty() {
                format!(
                    "{} campaign across {} hosts",
                    shared_techniques[0],
                    hosts.len()
                )
            } else if !shared_reasons.is_empty() {
                format!(
                    "{} campaign across {} hosts",
                    shared_reasons[0],
                    hosts.len()
                )
            } else {
                format!("Coordinated activity across {} hosts", hosts.len())
            };

            clustered += component.len();
            campaigns.push(Campaign {
                campaign_id: cid,
                name,
                hosts: hosts.into_iter().map(String::from).collect(),
                alert_count: component.len(),
                first_seen_ms: comp_alerts
                    .iter()
                    .map(|a| a.timestamp_ms)
                    .min()
                    .unwrap_or(0),
                last_seen_ms: comp_alerts
                    .iter()
                    .map(|a| a.timestamp_ms)
                    .max()
                    .unwrap_or(0),
                avg_score,
                max_score,
                shared_techniques,
                shared_reasons,
                severity: severity.into(),
                alert_ids: comp_alerts.iter().map(|a| a.alert_id.clone()).collect(),
            });
        }

        let campaign_hosts: HashSet<&str> = campaigns
            .iter()
            .flat_map(|c| c.hosts.iter().map(|h| h.as_str()))
            .collect();
        let fleet_coverage = if all_hosts.is_empty() {
            0.0
        } else {
            campaign_hosts.len() as f32 / all_hosts.len() as f32
        };

        let temporal_chains = self.detect_temporal_chains(&sorted);

        CampaignReport {
            campaigns,
            temporal_chains,
            unclustered_alerts: alerts.len() - clustered,
            total_alerts: alerts.len(),
            fleet_coverage,
        }
    }

    fn detect_temporal_chains(&mut self, alerts: &[&FleetAlert]) -> Vec<TemporalChain> {
        let same_host_window_ms = self.time_window_ms.clamp(60_000, 600_000);
        let same_host_similarity = (self.min_similarity * 0.5).clamp(0.1, 1.0);
        let mut by_host: HashMap<&str, Vec<&FleetAlert>> = HashMap::new();
        for alert in alerts {
            by_host
                .entry(alert.hostname.as_str())
                .or_default()
                .push(*alert);
        }

        let mut chains = Vec::new();
        for (host, mut host_alerts) in by_host {
            host_alerts.sort_by_key(|alert| alert.timestamp_ms);
            let mut current_chain: Vec<&FleetAlert> = Vec::new();

            for alert in host_alerts {
                let should_extend = match current_chain.last() {
                    Some(last) => {
                        let gap_ms = alert.timestamp_ms.saturating_sub(last.timestamp_ms);
                        let similarity = current_chain
                            .iter()
                            .map(|existing| alert_similarity(existing, alert))
                            .fold(0.0_f32, f32::max);
                        let severe_burst = current_chain
                            .iter()
                            .any(|existing| is_high_severity(&existing.level))
                            && is_high_severity(&alert.level);
                        gap_ms <= same_host_window_ms
                            && (similarity >= same_host_similarity || severe_burst)
                    }
                    None => true,
                };

                if should_extend {
                    current_chain.push(alert);
                } else {
                    if let Some(chain) = self.build_temporal_chain(host, &current_chain) {
                        chains.push(chain);
                    }
                    current_chain = vec![alert];
                }
            }

            if let Some(chain) = self.build_temporal_chain(host, &current_chain) {
                chains.push(chain);
            }
        }

        chains.sort_by(|left, right| {
            right
                .last_seen_ms
                .cmp(&left.last_seen_ms)
                .then_with(|| right.alert_count.cmp(&left.alert_count))
        });
        chains
    }

    fn build_temporal_chain(
        &mut self,
        host: &str,
        alerts: &[&FleetAlert],
    ) -> Option<TemporalChain> {
        if alerts.len() < 2 {
            return None;
        }

        let shared_techniques = find_shared_strings(
            &alerts
                .iter()
                .map(|alert| &alert.mitre_techniques)
                .collect::<Vec<_>>(),
        );
        let shared_reasons = find_shared_strings(
            &alerts
                .iter()
                .map(|alert| &alert.reasons)
                .collect::<Vec<_>>(),
        );
        let scores = alerts.iter().map(|alert| alert.score).collect::<Vec<_>>();
        let avg_score = scores.iter().sum::<f32>() / scores.len() as f32;
        let max_score = scores.iter().copied().fold(0.0_f32, f32::max);
        let severity = if max_score >= 5.0 {
            "Critical"
        } else if max_score >= 3.5 {
            "Severe"
        } else {
            "Elevated"
        };
        let chain_id = format!("chain-{}", self.next_id);
        self.next_id += 1;

        Some(TemporalChain {
            chain_id,
            host: host.to_string(),
            alert_count: alerts.len(),
            first_seen_ms: alerts.first().map(|alert| alert.timestamp_ms).unwrap_or(0),
            last_seen_ms: alerts.last().map(|alert| alert.timestamp_ms).unwrap_or(0),
            avg_score,
            max_score,
            severity: severity.to_string(),
            shared_techniques,
            shared_reasons,
            alert_ids: alerts.iter().map(|alert| alert.alert_id.clone()).collect(),
        })
    }
}

/// Jaccard similarity between alert technique/reason sets.
fn alert_similarity(a: &FleetAlert, b: &FleetAlert) -> f32 {
    let a_set: HashSet<&str> = a
        .mitre_techniques
        .iter()
        .chain(a.reasons.iter())
        .map(|s| s.as_str())
        .collect();
    let b_set: HashSet<&str> = b
        .mitre_techniques
        .iter()
        .chain(b.reasons.iter())
        .map(|s| s.as_str())
        .collect();
    if a_set.is_empty() && b_set.is_empty() {
        return 0.0; // No evidence of similarity when both have empty metadata
    }
    let intersection = a_set.intersection(&b_set).count() as f32;
    let union = a_set.union(&b_set).count() as f32;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

/// Find strings that appear in most (>50%) of the groups.
fn find_shared_strings(groups: &[&Vec<String>]) -> Vec<String> {
    if groups.is_empty() {
        return Vec::new();
    }
    let mut freq: HashMap<&str, usize> = HashMap::new();
    for group in groups {
        let unique: HashSet<&str> = group.iter().map(|s| s.as_str()).collect();
        for s in unique {
            *freq.entry(s).or_default() += 1;
        }
    }
    let threshold = groups.len() / 2 + 1;
    let mut shared: Vec<String> = freq
        .into_iter()
        .filter(|(_, count)| *count >= threshold)
        .map(|(s, _)| s.to_string())
        .collect();
    shared.sort();
    shared
}

fn is_high_severity(level: &str) -> bool {
    matches!(level, "Critical" | "Severe")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cross_host_campaign() {
        let alerts = vec![
            FleetAlert {
                alert_id: "a1".into(),
                hostname: "host-a".into(),
                timestamp_ms: 1000,
                score: 4.0,
                level: "Severe".into(),
                reasons: vec!["network burst".into()],
                mitre_techniques: vec!["T1071".into()],
            },
            FleetAlert {
                alert_id: "a2".into(),
                hostname: "host-b".into(),
                timestamp_ms: 2000,
                score: 4.5,
                level: "Severe".into(),
                reasons: vec!["network burst".into()],
                mitre_techniques: vec!["T1071".into()],
            },
            FleetAlert {
                alert_id: "a3".into(),
                hostname: "host-c".into(),
                timestamp_ms: 3000,
                score: 3.8,
                level: "Severe".into(),
                reasons: vec!["network burst".into()],
                mitre_techniques: vec!["T1071".into()],
            },
        ];
        let mut detector = CampaignDetector::default();
        let report = detector.detect(&alerts);
        assert_eq!(report.campaigns.len(), 1);
        assert_eq!(report.campaigns[0].hosts.len(), 3);
        assert!(
            report.campaigns[0]
                .shared_techniques
                .contains(&"T1071".into())
        );
    }

    #[test]
    fn no_campaign_single_host() {
        let alerts = vec![
            FleetAlert {
                alert_id: "a1".into(),
                hostname: "host-a".into(),
                timestamp_ms: 1000,
                score: 4.0,
                level: "Severe".into(),
                reasons: vec!["burst".into()],
                mitre_techniques: vec!["T1071".into()],
            },
            FleetAlert {
                alert_id: "a2".into(),
                hostname: "host-a".into(),
                timestamp_ms: 2000,
                score: 4.5,
                level: "Severe".into(),
                reasons: vec!["burst".into()],
                mitre_techniques: vec!["T1071".into()],
            },
        ];
        let mut detector = CampaignDetector::default();
        let report = detector.detect(&alerts);
        assert!(report.campaigns.is_empty());
    }

    #[test]
    fn detects_same_host_temporal_chain() {
        let alerts = vec![
            FleetAlert {
                alert_id: "a1".into(),
                hostname: "host-a".into(),
                timestamp_ms: 1_000,
                score: 3.7,
                level: "Severe".into(),
                reasons: vec!["credential burst".into()],
                mitre_techniques: vec!["T1110".into()],
            },
            FleetAlert {
                alert_id: "a2".into(),
                hostname: "host-a".into(),
                timestamp_ms: 40_000,
                score: 4.2,
                level: "Critical".into(),
                reasons: vec!["credential burst".into(), "suspicious process".into()],
                mitre_techniques: vec!["T1110".into(), "T1059".into()],
            },
            FleetAlert {
                alert_id: "a3".into(),
                hostname: "host-a".into(),
                timestamp_ms: 80_000,
                score: 4.1,
                level: "Severe".into(),
                reasons: vec!["suspicious process".into()],
                mitre_techniques: vec!["T1059".into()],
            },
        ];
        let mut detector = CampaignDetector::default();
        let report = detector.detect(&alerts);
        assert!(report.campaigns.is_empty());
        assert_eq!(report.temporal_chains.len(), 1);
        assert_eq!(report.temporal_chains[0].host, "host-a");
        assert_eq!(report.temporal_chains[0].alert_count, 3);
        assert_eq!(report.temporal_chains[0].severity, "Severe");
        assert!(
            report.temporal_chains[0]
                .shared_techniques
                .contains(&"T1110".into())
        );
    }

    #[test]
    fn unrelated_alerts_not_clustered() {
        let alerts = vec![
            FleetAlert {
                alert_id: "a1".into(),
                hostname: "host-a".into(),
                timestamp_ms: 1000,
                score: 4.0,
                level: "Severe".into(),
                reasons: vec!["auth burst".into()],
                mitre_techniques: vec!["T1110".into()],
            },
            FleetAlert {
                alert_id: "a2".into(),
                hostname: "host-b".into(),
                timestamp_ms: 2000,
                score: 4.5,
                level: "Severe".into(),
                reasons: vec!["dns tunnel".into()],
                mitre_techniques: vec!["T1071".into()],
            },
        ];
        let mut detector = CampaignDetector::default();
        let report = detector.detect(&alerts);
        assert!(report.campaigns.is_empty());
    }

    #[test]
    fn similarity_empty_sets_returns_zero() {
        let a = FleetAlert {
            alert_id: "x".into(),
            hostname: "h1".into(),
            timestamp_ms: 0,
            score: 1.0,
            level: "L".into(),
            reasons: vec![],
            mitre_techniques: vec![],
        };
        let b = FleetAlert {
            alert_id: "y".into(),
            hostname: "h2".into(),
            timestamp_ms: 0,
            score: 1.0,
            level: "L".into(),
            reasons: vec![],
            mitre_techniques: vec![],
        };
        let sim = alert_similarity(&a, &b);
        assert!(
            (sim - 0.0).abs() < f32::EPSILON,
            "empty sets should have zero similarity, got {sim}"
        );
    }

    #[test]
    fn similarity_calculation() {
        let a = FleetAlert {
            alert_id: "a".into(),
            hostname: "h1".into(),
            timestamp_ms: 0,
            score: 1.0,
            level: "L".into(),
            reasons: vec!["burst".into(), "auth".into()],
            mitre_techniques: vec!["T1071".into()],
        };
        let b = FleetAlert {
            alert_id: "b".into(),
            hostname: "h2".into(),
            timestamp_ms: 0,
            score: 1.0,
            level: "L".into(),
            reasons: vec!["burst".into(), "dns".into()],
            mitre_techniques: vec!["T1071".into()],
        };
        let sim = alert_similarity(&a, &b);
        assert!(sim > 0.3); // 2/4 = 0.5
    }
}
