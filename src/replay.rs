use std::collections::VecDeque;

use crate::telemetry::TelemetrySample;

#[derive(Debug, Clone)]
pub struct ReplayStats {
    pub count: usize,
    pub cpu_mean: f32,
    pub cpu_min: f32,
    pub cpu_max: f32,
    pub memory_mean: f32,
    pub memory_min: f32,
    pub memory_max: f32,
    pub network_mean: f32,
    pub network_min: f32,
    pub network_max: f32,
    pub auth_failures_mean: f32,
    pub auth_failures_max: u32,
    pub integrity_drift_mean: f32,
    pub integrity_drift_max: f32,
}

pub struct ReplayBuffer {
    capacity: usize,
    samples: VecDeque<TelemetrySample>,
}

impl ReplayBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            samples: VecDeque::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, sample: TelemetrySample) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn samples(&self) -> &VecDeque<TelemetrySample> {
        &self.samples
    }

    pub fn stats(&self) -> ReplayStats {
        if self.samples.is_empty() {
            return ReplayStats {
                count: 0,
                cpu_mean: 0.0,
                cpu_min: 0.0,
                cpu_max: 0.0,
                memory_mean: 0.0,
                memory_min: 0.0,
                memory_max: 0.0,
                network_mean: 0.0,
                network_min: 0.0,
                network_max: 0.0,
                auth_failures_mean: 0.0,
                auth_failures_max: 0,
                integrity_drift_mean: 0.0,
                integrity_drift_max: 0.0,
            };
        }

        let n = self.samples.len() as f32;
        let mut cpu_sum = 0.0_f32;
        let mut cpu_min = f32::MAX;
        let mut cpu_max = f32::MIN;
        let mut mem_sum = 0.0_f32;
        let mut mem_min = f32::MAX;
        let mut mem_max = f32::MIN;
        let mut net_sum = 0.0_f32;
        let mut net_min = f32::MAX;
        let mut net_max = f32::MIN;
        let mut auth_sum = 0u64;
        let mut auth_max = 0u32;
        let mut drift_sum = 0.0_f32;
        let mut drift_max = f32::MIN;

        for s in &self.samples {
            cpu_sum += s.cpu_load_pct;
            cpu_min = cpu_min.min(s.cpu_load_pct);
            cpu_max = cpu_max.max(s.cpu_load_pct);

            mem_sum += s.memory_load_pct;
            mem_min = mem_min.min(s.memory_load_pct);
            mem_max = mem_max.max(s.memory_load_pct);

            net_sum += s.network_kbps;
            net_min = net_min.min(s.network_kbps);
            net_max = net_max.max(s.network_kbps);

            auth_sum += s.auth_failures as u64;
            auth_max = auth_max.max(s.auth_failures);

            drift_sum += s.integrity_drift;
            drift_max = drift_max.max(s.integrity_drift);
        }

        ReplayStats {
            count: self.samples.len(),
            cpu_mean: cpu_sum / n,
            cpu_min,
            cpu_max,
            memory_mean: mem_sum / n,
            memory_min: mem_min,
            memory_max: mem_max,
            network_mean: net_sum / n,
            network_min: net_min,
            network_max: net_max,
            auth_failures_mean: auth_sum as f32 / n,
            auth_failures_max: auth_max,
            integrity_drift_mean: drift_sum / n,
            integrity_drift_max: drift_max,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReplayBuffer;
    use crate::telemetry::TelemetrySample;

    fn sample(cpu: f32, auth: u32) -> TelemetrySample {
        TelemetrySample {
            timestamp_ms: 1,
            cpu_load_pct: cpu,
            memory_load_pct: 30.0,
            temperature_c: 38.0,
            network_kbps: 500.0,
            auth_failures: auth,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 40,
            disk_pressure_pct: 10.0,
        }
    }

    #[test]
    fn capacity_bounds_buffer() {
        let mut buf = ReplayBuffer::new(3);
        buf.push(sample(10.0, 0));
        buf.push(sample(20.0, 0));
        buf.push(sample(30.0, 0));
        buf.push(sample(40.0, 0));

        assert_eq!(buf.len(), 3);
        assert_eq!(buf.samples()[0].cpu_load_pct, 20.0);
    }

    #[test]
    fn stats_computes_correctly() {
        let mut buf = ReplayBuffer::new(10);
        buf.push(sample(10.0, 2));
        buf.push(sample(30.0, 6));
        buf.push(sample(20.0, 4));

        let stats = buf.stats();
        assert_eq!(stats.count, 3);
        assert!((stats.cpu_mean - 20.0).abs() < 0.01);
        assert_eq!(stats.cpu_min, 10.0);
        assert_eq!(stats.cpu_max, 30.0);
        assert_eq!(stats.auth_failures_max, 6);
    }

    #[test]
    fn empty_stats() {
        let buf = ReplayBuffer::new(10);
        let stats = buf.stats();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.cpu_mean, 0.0);
    }
}
