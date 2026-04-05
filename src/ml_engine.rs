// ONNX ML inference engine — stub for future integration.
//
// This module provides the trait and data structures for running ML models
// (anomaly detection, entity classification, NLP-based alert triage) via
// ONNX Runtime.  The actual `ort` / `onnxruntime` crate dependency is NOT
// added yet; all methods return placeholder results so the rest of the
// codebase can program against the interface today.
//
// To activate:
//   1. Add `ort = "2"` to [dependencies] in Cargo.toml
//   2. Replace the stub implementations below with real inference calls
//   3. Ship .onnx model files under models/

use std::collections::HashMap;

// ── Model metadata ───────────────────────────────────────────────────

/// Describes a registered ML model.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelInfo {
    pub name: String,
    pub version: String,
    pub input_shape: Vec<usize>,
    pub output_shape: Vec<usize>,
    pub description: String,
}

/// Prediction result from a model.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Prediction {
    pub model: String,
    pub label: String,
    pub confidence: f64,
    pub latency_ms: f64,
    pub features_used: usize,
}

/// Alert triage classification from the ML model.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TriageResult {
    pub label: TriageLabel,
    pub confidence: f64,
    pub model_version: String,
}

/// Triage label for an alert — true positive, false positive, or needs human review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TriageLabel {
    TruePositive,
    FalsePositive,
    NeedsReview,
}

/// Feature vector extracted from an anomaly signal for ML triage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TriageFeatures {
    pub anomaly_score: f64,
    pub confidence: f64,
    pub suspicious_axes: u32,
    pub hour_of_day: u8,
    pub day_of_week: u8,
    pub alert_frequency_1h: u32,
    pub device_risk_score: f64,
}

impl TriageFeatures {
    /// Convert to a flat f64 vector for model input.
    pub fn to_vec(&self) -> Vec<f64> {
        vec![
            self.anomaly_score,
            self.confidence,
            self.suspicious_axes as f64,
            self.hour_of_day.min(23) as f64 / 24.0, // normalise [0,1)
            self.day_of_week.min(6) as f64 / 7.0,   // normalise [0,1)
            (self.alert_frequency_1h as f64).ln_1p(), // log-scale
            self.device_risk_score,
        ]
    }
}

/// Status of a model in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ModelStatus {
    NotLoaded,
    Loading,
    Ready,
    Error,
}

// ── Engine trait ──────────────────────────────────────────────────────

/// Trait that any inference backend must implement.
pub trait InferenceEngine: Send + Sync {
    fn load_model(&mut self, path: &str) -> Result<ModelInfo, String>;
    fn predict(&self, model: &str, features: &[f64]) -> Result<Prediction, String>;
    fn list_models(&self) -> Vec<ModelInfo>;
    fn status(&self, model: &str) -> ModelStatus;
    fn unload_model(&mut self, model: &str) -> Result<(), String>;
}

// ── Stub engine (no real ONNX dependency) ────────────────────────────

/// Placeholder engine that returns canned results.
/// Replace with `OnnxEngine` once `ort` crate is wired up.
#[derive(Debug, Default)]
pub struct StubEngine {
    models: HashMap<String, ModelInfo>,
}

impl StubEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run alert triage inference on extracted features.
    /// Returns a triage classification (TP/FP/Review).
    pub fn triage_alert(&self, features: &TriageFeatures) -> TriageResult {
        // Stub: heuristic triage based on anomaly score × confidence.
        let score = features.anomaly_score * features.confidence;
        let (label, conf) = if score > 0.8 {
            (TriageLabel::TruePositive, score)
        } else if score < 0.2 {
            (TriageLabel::FalsePositive, 1.0 - score)
        } else {
            (TriageLabel::NeedsReview, 0.5)
        };
        TriageResult {
            label,
            confidence: conf,
            model_version: "0.0.0-stub".into(),
        }
    }

    /// List built-in model slots that will ship with the first release.
    pub fn planned_models() -> Vec<ModelInfo> {
        vec![
            ModelInfo {
                name: "anomaly_detector_v1".into(),
                version: "0.0.0-stub".into(),
                input_shape: vec![1, 64],
                output_shape: vec![1, 1],
                description: "EWMA residual anomaly scorer (ONNX)".into(),
            },
            ModelInfo {
                name: "entity_classifier_v1".into(),
                version: "0.0.0-stub".into(),
                input_shape: vec![1, 128],
                output_shape: vec![1, 5],
                description: "User/entity risk classifier (ONNX)".into(),
            },
            ModelInfo {
                name: "alert_triage_v1".into(),
                version: "0.0.0-stub".into(),
                input_shape: vec![1, 256],
                output_shape: vec![1, 3],
                description: "NLP alert triage: true-positive / false-positive / needs-review".into(),
            },
        ]
    }
}

impl InferenceEngine for StubEngine {
    fn load_model(&mut self, path: &str) -> Result<ModelInfo, String> {
        // In the real engine this would call ort::Session::new(path)
        let name = std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let info = ModelInfo {
            name: name.clone(),
            version: "0.0.0-stub".into(),
            input_shape: vec![1, 64],
            output_shape: vec![1, 1],
            description: format!("Stub model loaded from {path}"),
        };
        self.models.insert(name, info.clone());
        Ok(info)
    }

    fn predict(&self, model: &str, features: &[f64]) -> Result<Prediction, String> {
        if !self.models.contains_key(model) {
            return Err(format!("model '{model}' not loaded"));
        }
        // Stub: return a neutral prediction
        Ok(Prediction {
            model: model.into(),
            label: "benign".into(),
            confidence: 0.5,
            latency_ms: 0.0,
            features_used: features.len(),
        })
    }

    fn list_models(&self) -> Vec<ModelInfo> {
        self.models.values().cloned().collect()
    }

    fn status(&self, model: &str) -> ModelStatus {
        if self.models.contains_key(model) {
            ModelStatus::Ready
        } else {
            ModelStatus::NotLoaded
        }
    }

    fn unload_model(&mut self, model: &str) -> Result<(), String> {
        self.models.remove(model);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_load_and_predict() {
        let mut engine = StubEngine::new();
        let info = engine.load_model("models/test_model.onnx").unwrap();
        assert_eq!(info.name, "test_model");
        assert_eq!(engine.status("test_model"), ModelStatus::Ready);

        let pred = engine.predict("test_model", &[1.0, 2.0, 3.0]).unwrap();
        assert_eq!(pred.label, "benign");
        assert_eq!(pred.features_used, 3);
    }

    #[test]
    fn stub_predict_unloaded_model_fails() {
        let engine = StubEngine::new();
        assert!(engine.predict("nonexistent", &[1.0]).is_err());
    }

    #[test]
    fn stub_unload() {
        let mut engine = StubEngine::new();
        engine.load_model("models/foo.onnx").unwrap();
        assert_eq!(engine.status("foo"), ModelStatus::Ready);
        engine.unload_model("foo").unwrap();
        assert_eq!(engine.status("foo"), ModelStatus::NotLoaded);
    }

    #[test]
    fn planned_models_populated() {
        let planned = StubEngine::planned_models();
        assert_eq!(planned.len(), 3);
        assert!(planned.iter().any(|m| m.name == "anomaly_detector_v1"));
        assert!(planned.iter().any(|m| m.name == "entity_classifier_v1"));
        assert!(planned.iter().any(|m| m.name == "alert_triage_v1"));
    }

    #[test]
    fn triage_high_score_is_tp() {
        let engine = StubEngine::new();
        let features = TriageFeatures {
            anomaly_score: 0.95, confidence: 0.9,
            suspicious_axes: 3, hour_of_day: 2, day_of_week: 6,
            alert_frequency_1h: 5, device_risk_score: 0.8,
        };
        let result = engine.triage_alert(&features);
        assert_eq!(result.label, TriageLabel::TruePositive);
        assert!(result.confidence > 0.8);
    }

    #[test]
    fn triage_low_score_is_fp() {
        let engine = StubEngine::new();
        let features = TriageFeatures {
            anomaly_score: 0.1, confidence: 0.1,
            suspicious_axes: 0, hour_of_day: 14, day_of_week: 2,
            alert_frequency_1h: 0, device_risk_score: 0.05,
        };
        let result = engine.triage_alert(&features);
        assert_eq!(result.label, TriageLabel::FalsePositive);
    }

    #[test]
    fn triage_mid_score_needs_review() {
        let engine = StubEngine::new();
        let features = TriageFeatures {
            anomaly_score: 0.5, confidence: 0.5,
            suspicious_axes: 1, hour_of_day: 10, day_of_week: 3,
            alert_frequency_1h: 2, device_risk_score: 0.3,
        };
        let result = engine.triage_alert(&features);
        assert_eq!(result.label, TriageLabel::NeedsReview);
    }

    #[test]
    fn triage_features_to_vec() {
        let features = TriageFeatures {
            anomaly_score: 0.5, confidence: 0.8,
            suspicious_axes: 2, hour_of_day: 12, day_of_week: 3,
            alert_frequency_1h: 10, device_risk_score: 0.6,
        };
        let v = features.to_vec();
        assert_eq!(v.len(), 7);
        assert!((v[0] - 0.5).abs() < 1e-6);
        assert!((v[3] - 0.5).abs() < 1e-6); // 12/24
    }
}
