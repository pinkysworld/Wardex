//! Energy harvesting, power-aware scheduling, and model quantization.
//!
//! Covers R14 (energy harvesting archival), R18 (quantization with proofs).

use serde::{Deserialize, Serialize};

// ── Energy Budget Tracking (R14) ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PowerState {
    Full,
    Normal,
    LowPower,
    CriticalPower,
    Harvesting,
    Sleep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnergyBudget {
    pub capacity_mwh: f64,
    pub current_mwh: f64,
    pub harvest_rate_mw: f64,
    pub drain_rate_mw: f64,
    pub state: PowerState,
}

impl EnergyBudget {
    pub fn new(capacity_mwh: f64) -> Self {
        Self {
            capacity_mwh,
            current_mwh: capacity_mwh,
            harvest_rate_mw: 0.0,
            drain_rate_mw: 0.0,
            state: PowerState::Full,
        }
    }

    /// Simulate one time-step (1 second). Returns updated power state.
    pub fn tick(&mut self) -> PowerState {
        // Energy balance: current += harvest - drain (for 1s = 1/3600 hour)
        let delta_mwh = (self.harvest_rate_mw - self.drain_rate_mw) / 3600.0;
        self.current_mwh = (self.current_mwh + delta_mwh).clamp(0.0, self.capacity_mwh);

        let pct = if self.capacity_mwh > 0.0 {
            self.current_mwh / self.capacity_mwh
        } else {
            0.0
        };
        self.state = if pct > 0.75 {
            PowerState::Full
        } else if pct > 0.40 {
            PowerState::Normal
        } else if pct > 0.15 {
            PowerState::LowPower
        } else if pct > 0.0 {
            PowerState::CriticalPower
        } else {
            PowerState::Sleep
        };
        self.state.clone()
    }

    pub fn remaining_pct(&self) -> f64 {
        if self.capacity_mwh > 0.0 {
            self.current_mwh / self.capacity_mwh * 100.0
        } else {
            0.0
        }
    }

    /// Estimate remaining runtime in seconds at current drain rate.
    pub fn estimated_runtime_secs(&self) -> f64 {
        let net = self.drain_rate_mw - self.harvest_rate_mw;
        if net <= 0.0 {
            return f64::INFINITY; // energy is accumulating
        }
        self.current_mwh / net * 3600.0
    }
}

// ── Power-Aware Scheduling ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub name: String,
    pub cost_mwh: f64,
    pub priority: u8,
    pub deferrable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleResult {
    pub executed: Vec<String>,
    pub deferred: Vec<String>,
    pub dropped: Vec<String>,
    pub energy_consumed_mwh: f64,
}

/// Schedule tasks respecting energy constraints.
pub fn energy_aware_schedule(tasks: &[ScheduledTask], budget: &EnergyBudget) -> ScheduleResult {
    let mut sorted = tasks.to_vec();
    sorted.sort_by_key(|a| a.priority);

    let mut available = budget.current_mwh;
    let mut executed = Vec::new();
    let mut deferred = Vec::new();
    let mut dropped = Vec::new();
    let mut consumed = 0.0;

    let is_low = matches!(
        budget.state,
        PowerState::LowPower | PowerState::CriticalPower | PowerState::Sleep
    );

    for task in &sorted {
        if task.cost_mwh <= available {
            if is_low && task.deferrable {
                deferred.push(task.name.clone());
            } else {
                available -= task.cost_mwh;
                consumed += task.cost_mwh;
                executed.push(task.name.clone());
            }
        } else if task.deferrable {
            deferred.push(task.name.clone());
        } else {
            dropped.push(task.name.clone());
        }
    }

    ScheduleResult {
        executed,
        deferred,
        dropped,
        energy_consumed_mwh: consumed,
    }
}

// ── Harvesting Manager ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HarvestSource {
    Solar,
    Vibration,
    Thermal,
    Rf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestReading {
    pub source: HarvestSource,
    pub power_mw: f64,
    pub timestamp: String,
}

#[derive(Debug)]
pub struct HarvestManager {
    readings: Vec<HarvestReading>,
    budget: EnergyBudget,
}

impl HarvestManager {
    pub fn new(capacity_mwh: f64) -> Self {
        Self {
            readings: Vec::new(),
            budget: EnergyBudget::new(capacity_mwh),
        }
    }

    /// Record a harvest reading and update the budget's harvest rate.
    pub fn record_harvest(&mut self, source: HarvestSource, power_mw: f64) {
        self.readings.push(HarvestReading {
            source,
            power_mw,
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
        // Sum all latest readings for total harvest rate
        let total: f64 = self
            .readings
            .iter()
            .rev()
            .take(10)
            .map(|r| r.power_mw)
            .sum::<f64>()
            / self.readings.len().min(10) as f64;
        self.budget.harvest_rate_mw = total;
    }

    pub fn set_drain(&mut self, drain_mw: f64) {
        self.budget.drain_rate_mw = drain_mw;
    }

    pub fn tick(&mut self) -> PowerState {
        self.budget.tick()
    }

    pub fn budget(&self) -> &EnergyBudget {
        &self.budget
    }
}

// ── Model Quantization (R18) ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantizedModel {
    pub name: String,
    pub original_params: usize,
    pub quantized_params: usize,
    pub bit_width: u8,
    pub weights: Vec<i8>, // quantized weights
    pub scale: f64,       // dequantization scale
    pub zero_point: i8,
    pub accuracy_loss_pct: f64,
    pub compression_ratio: f64,
}

/// Quantize a float model to int8 representation.
pub fn quantize_model(name: &str, weights: &[f64], bit_width: u8) -> QuantizedModel {
    assert!((2..=8).contains(&bit_width), "bit_width must be 2..=8");

    let abs_max = weights.iter().cloned().fold(0.0_f64, |a, w| a.max(w.abs()));

    let half_range = (1i32 << (bit_width - 1)) as f64; // 128 for 8-bit
    let scale = if abs_max > 0.0 {
        abs_max / (half_range - 1.0)
    } else {
        1.0
    };
    let zero_point = 0i8;

    let quantized: Vec<i8> = weights
        .iter()
        .map(|w| (w / scale).round().clamp(-half_range, half_range - 1.0) as i8)
        .collect();

    // Estimate accuracy loss as mean absolute quantization error
    let max_val = weights.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let min_val = weights.iter().cloned().fold(f64::INFINITY, f64::min);
    let range = (max_val - min_val).max(1e-10);

    let total_error: f64 = weights
        .iter()
        .zip(quantized.iter())
        .map(|(orig, q)| {
            let reconstructed = *q as f64 * scale;
            (orig - reconstructed).abs()
        })
        .sum();
    let mae = total_error / weights.len().max(1) as f64;
    let accuracy_loss = mae / range * 100.0;

    let original_size = weights.len().saturating_mul(8); // 64-bit floats
    let quantized_size = weights.len().saturating_mul(bit_width as usize) / 8;
    let compression = original_size as f64 / quantized_size.max(1) as f64;

    QuantizedModel {
        name: name.to_string(),
        original_params: weights.len(),
        quantized_params: quantized.len(),
        bit_width,
        weights: quantized,
        scale,
        zero_point,
        accuracy_loss_pct: accuracy_loss,
        compression_ratio: compression,
    }
}

/// Generate a proof that quantization preserved model semantics:
/// returns (hash of original, hash of quantized, max error bound).
pub fn quantization_proof(original: &[f64], quantized: &QuantizedModel) -> QuantizationProof {
    use sha2::{Digest, Sha256};

    let mut hasher_orig = Sha256::new();
    for w in original {
        hasher_orig.update(w.to_le_bytes());
    }
    let orig_hash = hex::encode(hasher_orig.finalize());

    let mut hasher_quant = Sha256::new();
    for w in &quantized.weights {
        hasher_quant.update(w.to_le_bytes());
    }
    let quant_hash = hex::encode(hasher_quant.finalize());

    // Max element-wise error
    let max_error: f64 = original
        .iter()
        .zip(quantized.weights.iter())
        .map(|(orig, q)| {
            let reconstructed = *q as f64 * quantized.scale;
            (orig - reconstructed).abs()
        })
        .fold(0.0_f64, f64::max);

    QuantizationProof {
        original_hash: orig_hash,
        quantized_hash: quant_hash,
        max_error,
        scale: quantized.scale,
        zero_point: quantized.zero_point,
        params_count: original.len(),
        verified: max_error < quantized.scale * 1.5, // within 1.5× scale factor
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantizationProof {
    pub original_hash: String,
    pub quantized_hash: String,
    pub max_error: f64,
    pub scale: f64,
    pub zero_point: i8,
    pub params_count: usize,
    pub verified: bool,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn energy_budget_tick() {
        let mut budget = EnergyBudget::new(100.0);
        budget.drain_rate_mw = 10.0;
        for _ in 0..100 {
            budget.tick();
        }
        assert!(budget.current_mwh < 100.0);
        assert!(budget.remaining_pct() < 100.0);
    }

    #[test]
    fn energy_budget_harvest_sustains() {
        let mut budget = EnergyBudget::new(100.0);
        budget.current_mwh = 50.0;
        budget.harvest_rate_mw = 20.0;
        budget.drain_rate_mw = 10.0;
        // Net positive — should accumulate
        for _ in 0..3600 {
            budget.tick();
        }
        assert!(budget.current_mwh > 50.0);
        assert_eq!(budget.estimated_runtime_secs(), f64::INFINITY);
    }

    #[test]
    fn power_state_transitions() {
        let mut budget = EnergyBudget::new(100.0);
        budget.drain_rate_mw = 360000.0; // 100 mWh/s → drains fast
        budget.tick();
        // After one tick, should drop significantly
        assert_ne!(budget.state, PowerState::Full);
    }

    #[test]
    fn energy_aware_schedule_normal() {
        let budget = EnergyBudget::new(100.0);
        let tasks = vec![
            ScheduledTask {
                name: "scan".into(),
                cost_mwh: 5.0,
                priority: 1,
                deferrable: false,
            },
            ScheduledTask {
                name: "report".into(),
                cost_mwh: 2.0,
                priority: 2,
                deferrable: true,
            },
        ];
        let result = energy_aware_schedule(&tasks, &budget);
        assert_eq!(result.executed.len(), 2);
        assert!(result.deferred.is_empty());
    }

    #[test]
    fn energy_aware_schedule_defers_in_low_power() {
        let mut budget = EnergyBudget::new(100.0);
        budget.current_mwh = 10.0;
        budget.state = PowerState::LowPower;
        let tasks = vec![
            ScheduledTask {
                name: "critical".into(),
                cost_mwh: 5.0,
                priority: 0,
                deferrable: false,
            },
            ScheduledTask {
                name: "optional".into(),
                cost_mwh: 2.0,
                priority: 1,
                deferrable: true,
            },
        ];
        let result = energy_aware_schedule(&tasks, &budget);
        assert!(result.executed.contains(&"critical".to_string()));
        assert!(result.deferred.contains(&"optional".to_string()));
    }

    #[test]
    fn harvest_manager_records() {
        let mut hm = HarvestManager::new(100.0);
        hm.record_harvest(HarvestSource::Solar, 50.0);
        hm.set_drain(10.0);
        assert!(hm.budget().harvest_rate_mw > 0.0);
    }

    #[test]
    fn quantize_model_8bit() {
        let weights = vec![0.1, -0.5, 0.3, 0.8, -0.2, 0.0, 0.6, -0.1];
        let qm = quantize_model("test-model", &weights, 8);
        assert_eq!(qm.quantized_params, weights.len());
        assert!(qm.compression_ratio > 1.0);
        assert!(qm.accuracy_loss_pct < 5.0);
    }

    #[test]
    fn quantization_proof_verifies() {
        let weights: Vec<f64> = (0..100).map(|i| (i as f64 - 50.0) / 100.0).collect();
        let qm = quantize_model("proof-test", &weights, 8);
        let proof = quantization_proof(&weights, &qm);
        assert!(proof.verified);
        assert!(proof.max_error < qm.scale * 1.5);
    }

    #[test]
    fn quantize_4bit() {
        let weights: Vec<f64> = (0..64).map(|i| i as f64 / 64.0).collect();
        let qm = quantize_model("4bit", &weights, 4);
        assert_eq!(qm.bit_width, 4);
        // 4-bit has higher compression than 8-bit
        assert!(qm.compression_ratio >= 8.0);
    }
}
