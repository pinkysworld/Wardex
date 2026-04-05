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
}
