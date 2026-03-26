use crate::replay::ReplayBuffer;

#[derive(Debug, Clone)]
pub struct PoisoningReport {
    pub mean_shift: bool,
    pub variance_spike: bool,
    pub drift_accumulation: bool,
    pub auth_burst: bool,
}

impl PoisoningReport {
    pub fn any_triggered(&self) -> bool {
        self.mean_shift || self.variance_spike || self.drift_accumulation || self.auth_burst
    }

    pub fn triggered_count(&self) -> usize {
        [
            self.mean_shift,
            self.variance_spike,
            self.drift_accumulation,
            self.auth_burst,
        ]
        .iter()
        .filter(|&&v| v)
        .count()
    }
}

pub fn mean_shift_detected(buffer: &ReplayBuffer) -> bool {
    let samples = buffer.samples();
    if samples.len() < 4 {
        return false;
    }

    let mid = samples.len() / 2;
    let first_half_mean: f32 = samples.iter().take(mid).map(|s| s.cpu_load_pct).sum::<f32>() / mid as f32;
    let second_half_mean: f32 = samples.iter().skip(mid).map(|s| s.cpu_load_pct).sum::<f32>()
        / (samples.len() - mid) as f32;

    (second_half_mean - first_half_mean).abs() > 20.0
}

pub fn variance_spike_detected(buffer: &ReplayBuffer) -> bool {
    let samples = buffer.samples();
    if samples.len() < 4 {
        return false;
    }

    let n = samples.len() as f32;
    let mean: f32 = samples.iter().map(|s| s.network_kbps).sum::<f32>() / n;
    let variance: f32 =
        samples.iter().map(|s| (s.network_kbps - mean).powi(2)).sum::<f32>() / n;

    variance.sqrt() > mean * 0.8
}

pub fn drift_accumulation_detected(buffer: &ReplayBuffer) -> bool {
    let samples = buffer.samples();
    if samples.len() < 3 {
        return false;
    }

    let mut consecutive_increases = 0usize;
    let mut prev_drift = samples[0].integrity_drift;

    for s in samples.iter().skip(1) {
        if s.integrity_drift > prev_drift + 0.005 {
            consecutive_increases += 1;
        } else {
            consecutive_increases = 0;
        }
        prev_drift = s.integrity_drift;
    }

    consecutive_increases >= 3
}

pub fn auth_burst_detected(buffer: &ReplayBuffer) -> bool {
    let samples = buffer.samples();
    if samples.len() < 2 {
        return false;
    }

    let burst_threshold = 8u32;
    let burst_window = 3;
    let mut burst_count = 0usize;

    for window in samples.iter().collect::<Vec<_>>().windows(burst_window.min(samples.len())) {
        let total_auth: u32 = window.iter().map(|s| s.auth_failures).sum();
        if total_auth >= burst_threshold {
            burst_count += 1;
        }
    }

    burst_count >= 1
}

pub fn check_all(buffer: &ReplayBuffer) -> PoisoningReport {
    PoisoningReport {
        mean_shift: mean_shift_detected(buffer),
        variance_spike: variance_spike_detected(buffer),
        drift_accumulation: drift_accumulation_detected(buffer),
        auth_burst: auth_burst_detected(buffer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::ReplayBuffer;
    use crate::telemetry::TelemetrySample;

    fn base_sample() -> TelemetrySample {
        TelemetrySample {
            timestamp_ms: 1,
            cpu_load_pct: 20.0,
            memory_load_pct: 30.0,
            temperature_c: 38.0,
            network_kbps: 500.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 40,
            disk_pressure_pct: 10.0,
        }
    }

    #[test]
    fn mean_shift_triggers_on_cpu_jump() {
        let mut buf = ReplayBuffer::new(10);
        for _ in 0..4 {
            buf.push(base_sample());
        }
        for _ in 0..4 {
            let mut s = base_sample();
            s.cpu_load_pct = 70.0;
            buf.push(s);
        }

        assert!(mean_shift_detected(&buf));
    }

    #[test]
    fn variance_spike_triggers_on_network_variance() {
        let mut buf = ReplayBuffer::new(10);
        for i in 0..6 {
            let mut s = base_sample();
            s.network_kbps = if i % 2 == 0 { 100.0 } else { 5000.0 };
            buf.push(s);
        }

        assert!(variance_spike_detected(&buf));
    }

    #[test]
    fn drift_accumulation_triggers() {
        let mut buf = ReplayBuffer::new(10);
        for i in 0..6 {
            let mut s = base_sample();
            s.integrity_drift = 0.01 + (i as f32 * 0.02);
            buf.push(s);
        }

        assert!(drift_accumulation_detected(&buf));
    }

    #[test]
    fn auth_burst_triggers() {
        let mut buf = ReplayBuffer::new(10);
        for _ in 0..3 {
            let mut s = base_sample();
            s.auth_failures = 5;
            buf.push(s);
        }

        assert!(auth_burst_detected(&buf));
    }

    #[test]
    fn benign_data_triggers_nothing() {
        let mut buf = ReplayBuffer::new(10);
        for _ in 0..6 {
            buf.push(base_sample());
        }

        let report = check_all(&buf);
        assert!(!report.any_triggered());
        assert_eq!(report.triggered_count(), 0);
    }
}
