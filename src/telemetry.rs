use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

pub const CSV_HEADER: &str = "timestamp_ms,cpu_load_pct,memory_load_pct,temperature_c,network_kbps,auth_failures,battery_pct,integrity_drift,process_count,disk_pressure_pct";

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySample {
    pub timestamp_ms: u64,
    pub cpu_load_pct: f32,
    pub memory_load_pct: f32,
    pub temperature_c: f32,
    pub network_kbps: f32,
    pub auth_failures: u32,
    pub battery_pct: f32,
    pub integrity_drift: f32,
    /// Number of active processes (T014). Defaults to 0 when absent.
    #[serde(default)]
    pub process_count: u32,
    /// Disk I/O pressure as a percentage 0-100 (T014). Defaults to 0.
    #[serde(default)]
    pub disk_pressure_pct: f32,
}

#[derive(Debug, Clone)]
pub struct ParseTelemetryError {
    message: String,
}

impl ParseTelemetryError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseTelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ParseTelemetryError {}

pub const CSV_HEADER_LEGACY: &str = "timestamp_ms,cpu_load_pct,memory_load_pct,temperature_c,network_kbps,auth_failures,battery_pct,integrity_drift";

impl TelemetrySample {
    pub fn parse_csv(path: &Path) -> Result<Vec<Self>, ParseTelemetryError> {
        let raw = fs::read_to_string(path).map_err(|error| {
            ParseTelemetryError::new(format!("failed to read {}: {error}", path.display()))
        })?;

        let mut lines = raw.lines().filter(|line| !line.trim().is_empty());
        let header = lines
            .next()
            .ok_or_else(|| ParseTelemetryError::new("telemetry file is empty"))?;

        let trimmed_header = header.trim();
        let columns = if trimmed_header == CSV_HEADER {
            10
        } else if trimmed_header == CSV_HEADER_LEGACY {
            8
        } else {
            return Err(ParseTelemetryError::new(format!(
                "unexpected CSV header. expected `{CSV_HEADER}` or `{CSV_HEADER_LEGACY}`"
            )));
        };

        let mut samples = Vec::new();
        for (line_offset, line) in lines.enumerate() {
            samples.push(Self::parse_line_cols(line, line_offset + 2, columns)?);
        }

        if samples.is_empty() {
            return Err(ParseTelemetryError::new(
                "telemetry file contained a header but no samples",
            ));
        }

        Ok(samples)
    }

    /// Parse from a JSONL file where each line is a JSON object.
    pub fn parse_jsonl(path: &Path) -> Result<Vec<Self>, ParseTelemetryError> {
        let raw = fs::read_to_string(path).map_err(|error| {
            ParseTelemetryError::new(format!("failed to read {}: {error}", path.display()))
        })?;

        let mut samples = Vec::new();
        for (line_num, line) in raw.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let sample: Self = serde_json::from_str(trimmed).map_err(|error| {
                ParseTelemetryError::new(format!(
                    "line {}: invalid JSON: {error}",
                    line_num + 1,
                ))
            })?;
            sample.validate(line_num + 1)?;
            samples.push(sample);
        }

        if samples.is_empty() {
            return Err(ParseTelemetryError::new(
                "JSONL file contained no samples",
            ));
        }

        Ok(samples)
    }

    /// Auto-detect format (CSV or JSONL) based on file extension.
    pub fn parse_auto(path: &Path) -> Result<Vec<Self>, ParseTelemetryError> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("jsonl" | "ndjson") => Self::parse_jsonl(path),
            _ => Self::parse_csv(path),
        }
    }

    pub fn parse_line(line: &str, line_number: usize) -> Result<Self, ParseTelemetryError> {
        let cols = line.split(',').count();
        let expected = if cols >= 10 { 10 } else { 8 };
        Self::parse_line_cols(line, line_number, expected)
    }

    fn parse_line_cols(
        line: &str,
        line_number: usize,
        expected_cols: usize,
    ) -> Result<Self, ParseTelemetryError> {
        let parts: Vec<_> = line.split(',').map(str::trim).collect();
        if parts.len() != expected_cols {
            return Err(ParseTelemetryError::new(format!(
                "line {line_number}: expected {expected_cols} columns, found {}",
                parts.len()
            )));
        }

        let mut sample = Self {
            timestamp_ms: parse(parts[0], line_number, "timestamp_ms")?,
            cpu_load_pct: parse(parts[1], line_number, "cpu_load_pct")?,
            memory_load_pct: parse(parts[2], line_number, "memory_load_pct")?,
            temperature_c: parse(parts[3], line_number, "temperature_c")?,
            network_kbps: parse(parts[4], line_number, "network_kbps")?,
            auth_failures: parse(parts[5], line_number, "auth_failures")?,
            battery_pct: parse(parts[6], line_number, "battery_pct")?,
            integrity_drift: parse(parts[7], line_number, "integrity_drift")?,
            process_count: 0,
            disk_pressure_pct: 0.0,
        };

        if expected_cols >= 10 {
            sample.process_count = parse(parts[8], line_number, "process_count")?;
            sample.disk_pressure_pct = parse(parts[9], line_number, "disk_pressure_pct")?;
        }

        sample.validate(line_number)?;
        Ok(sample)
    }

    fn validate(&self, line_number: usize) -> Result<(), ParseTelemetryError> {
        validate_range(self.cpu_load_pct, 0.0, 100.0, line_number, "cpu_load_pct")?;
        validate_range(
            self.memory_load_pct,
            0.0,
            100.0,
            line_number,
            "memory_load_pct",
        )?;
        validate_range(self.battery_pct, 0.0, 100.0, line_number, "battery_pct")?;
        validate_range(
            self.integrity_drift,
            0.0,
            1.0,
            line_number,
            "integrity_drift",
        )?;
        validate_range(
            self.disk_pressure_pct,
            0.0,
            100.0,
            line_number,
            "disk_pressure_pct",
        )?;

        if self.network_kbps.is_nan() || self.network_kbps.is_infinite() || self.network_kbps < 0.0 {
            return Err(ParseTelemetryError::new(format!(
                "line {line_number}: network_kbps must be a finite non-negative value"
            )));
        }

        if self.temperature_c.is_nan() || self.temperature_c.is_infinite() {
            return Err(ParseTelemetryError::new(format!(
                "line {line_number}: temperature_c must be a finite value"
            )));
        }

        Ok(())
    }
}

fn parse<T>(raw: &str, line_number: usize, field: &str) -> Result<T, ParseTelemetryError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    raw.parse::<T>().map_err(|error| {
        ParseTelemetryError::new(format!(
            "line {line_number}: invalid {field} value `{raw}`: {error}"
        ))
    })
}

fn validate_range(
    value: f32,
    min: f32,
    max: f32,
    line_number: usize,
    field: &str,
) -> Result<(), ParseTelemetryError> {
    if !(min..=max).contains(&value) {
        return Err(ParseTelemetryError::new(format!(
            "line {line_number}: {field} must be in range {min}..={max}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::TelemetrySample;

    #[test]
    fn parses_line_legacy_8_cols() {
        let sample = TelemetrySample::parse_line("42,10,20,35,1200,2,80,0.15", 3).unwrap();

        assert_eq!(sample.timestamp_ms, 42);
        assert_eq!(sample.auth_failures, 2);
        assert_eq!(sample.integrity_drift, 0.15);
        assert_eq!(sample.process_count, 0);
        assert_eq!(sample.disk_pressure_pct, 0.0);
    }

    #[test]
    fn parses_line_10_cols() {
        let sample =
            TelemetrySample::parse_line_cols("42,10,20,35,1200,2,80,0.15,120,45.5", 3, 10)
                .unwrap();
        assert_eq!(sample.process_count, 120);
        assert!((sample.disk_pressure_pct - 45.5).abs() < 0.01);
    }

    #[test]
    fn rejects_bad_range() {
        let error = TelemetrySample::parse_line("42,101,20,35,1200,2,80,0.15", 3).unwrap_err();
        assert!(error.to_string().contains("cpu_load_pct"));
    }

    #[test]
    fn jsonl_round_trip() {
        let sample = TelemetrySample {
            timestamp_ms: 100,
            cpu_load_pct: 25.0,
            memory_load_pct: 30.0,
            temperature_c: 40.0,
            network_kbps: 500.0,
            auth_failures: 1,
            battery_pct: 85.0,
            integrity_drift: 0.03,
            process_count: 42,
            disk_pressure_pct: 12.5,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let parsed: TelemetrySample = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.process_count, 42);
    }
}
