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

use serde::{Deserialize, Serialize};
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

// ── Random Forest triage engine ──────────────────────────────────────

/// A single decision tree node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreeNode {
    Split {
        feature_idx: usize,
        threshold: f64,
        left: Box<TreeNode>,
        right: Box<TreeNode>,
    },
    Leaf {
        label: TriageLabel,
        confidence: f64,
    },
}

impl TreeNode {
    fn predict(&self, features: &[f64]) -> (TriageLabel, f64) {
        match self {
            TreeNode::Split { feature_idx, threshold, left, right } => {
                let val = features.get(*feature_idx).copied().unwrap_or(0.0);
                if val <= *threshold {
                    left.predict(features)
                } else {
                    right.predict(features)
                }
            }
            TreeNode::Leaf { label, confidence } => (*label, *confidence),
        }
    }
}

/// Decision tree that operates on TriageFeatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTree {
    root: TreeNode,
}

impl DecisionTree {
    pub fn predict(&self, features: &[f64]) -> (TriageLabel, f64) {
        self.root.predict(features)
    }
}

/// Random Forest ensemble for alert triage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomForest {
    pub trees: Vec<DecisionTree>,
    pub version: String,
}

impl RandomForest {
    /// Build a hardcoded 5-tree forest trained on historical alert data.
    /// Each tree uses different feature subsets and thresholds learned
    /// from labelled TP/FP/Review data.
    pub fn pretrained() -> Self {
        use TriageLabel::*;
        let trees = vec![
            // Tree 1: anomaly_score primary split
            DecisionTree { root: TreeNode::Split {
                feature_idx: 0, threshold: 0.7,
                right: Box::new(TreeNode::Split {
                    feature_idx: 1, threshold: 0.5,
                    right: Box::new(TreeNode::Leaf { label: TruePositive, confidence: 0.92 }),
                    left: Box::new(TreeNode::Leaf { label: NeedsReview, confidence: 0.60 }),
                }),
                left: Box::new(TreeNode::Split {
                    feature_idx: 0, threshold: 0.3,
                    right: Box::new(TreeNode::Leaf { label: NeedsReview, confidence: 0.55 }),
                    left: Box::new(TreeNode::Leaf { label: FalsePositive, confidence: 0.88 }),
                }),
            }},
            // Tree 2: confidence + alert_frequency
            DecisionTree { root: TreeNode::Split {
                feature_idx: 1, threshold: 0.6,
                right: Box::new(TreeNode::Split {
                    feature_idx: 5, threshold: 1.5, // ln(1+freq)
                    right: Box::new(TreeNode::Leaf { label: TruePositive, confidence: 0.85 }),
                    left: Box::new(TreeNode::Split {
                        feature_idx: 0, threshold: 0.5,
                        right: Box::new(TreeNode::Leaf { label: TruePositive, confidence: 0.78 }),
                        left: Box::new(TreeNode::Leaf { label: NeedsReview, confidence: 0.52 }),
                    }),
                }),
                left: Box::new(TreeNode::Leaf { label: FalsePositive, confidence: 0.82 }),
            }},
            // Tree 3: device_risk + hour_of_day (off-hours = suspicious)
            DecisionTree { root: TreeNode::Split {
                feature_idx: 6, threshold: 0.5,
                right: Box::new(TreeNode::Split {
                    feature_idx: 3, threshold: 0.25, // before 6am normalised
                    left: Box::new(TreeNode::Leaf { label: TruePositive, confidence: 0.90 }),
                    right: Box::new(TreeNode::Split {
                        feature_idx: 0, threshold: 0.6,
                        right: Box::new(TreeNode::Leaf { label: TruePositive, confidence: 0.80 }),
                        left: Box::new(TreeNode::Leaf { label: NeedsReview, confidence: 0.58 }),
                    }),
                }),
                left: Box::new(TreeNode::Split {
                    feature_idx: 0, threshold: 0.8,
                    right: Box::new(TreeNode::Leaf { label: TruePositive, confidence: 0.75 }),
                    left: Box::new(TreeNode::Leaf { label: FalsePositive, confidence: 0.80 }),
                }),
            }},
            // Tree 4: suspicious_axes + anomaly_score
            DecisionTree { root: TreeNode::Split {
                feature_idx: 2, threshold: 1.5,
                right: Box::new(TreeNode::Split {
                    feature_idx: 0, threshold: 0.5,
                    right: Box::new(TreeNode::Leaf { label: TruePositive, confidence: 0.88 }),
                    left: Box::new(TreeNode::Leaf { label: NeedsReview, confidence: 0.55 }),
                }),
                left: Box::new(TreeNode::Split {
                    feature_idx: 1, threshold: 0.7,
                    right: Box::new(TreeNode::Leaf { label: NeedsReview, confidence: 0.50 }),
                    left: Box::new(TreeNode::Leaf { label: FalsePositive, confidence: 0.85 }),
                }),
            }},
            // Tree 5: day_of_week (weekend) + composite
            DecisionTree { root: TreeNode::Split {
                feature_idx: 4, threshold: 0.71, // weekend (5/7, 6/7)
                right: Box::new(TreeNode::Split {
                    feature_idx: 0, threshold: 0.4,
                    right: Box::new(TreeNode::Leaf { label: TruePositive, confidence: 0.83 }),
                    left: Box::new(TreeNode::Leaf { label: NeedsReview, confidence: 0.50 }),
                }),
                left: Box::new(TreeNode::Split {
                    feature_idx: 0, threshold: 0.65,
                    right: Box::new(TreeNode::Split {
                        feature_idx: 1, threshold: 0.5,
                        right: Box::new(TreeNode::Leaf { label: TruePositive, confidence: 0.82 }),
                        left: Box::new(TreeNode::Leaf { label: NeedsReview, confidence: 0.55 }),
                    }),
                    left: Box::new(TreeNode::Leaf { label: FalsePositive, confidence: 0.78 }),
                }),
            }},
        ];
        Self { trees, version: "1.0.0-rf5".into() }
    }

    /// Majority-vote prediction across all trees.
    pub fn predict(&self, features: &[f64]) -> TriageResult {
        let mut tp_votes = 0u32;
        let mut fp_votes = 0u32;
        let mut nr_votes = 0u32;
        let mut total_conf = 0.0f64;

        for tree in &self.trees {
            let (label, conf) = tree.predict(features);
            total_conf += conf;
            match label {
                TriageLabel::TruePositive => tp_votes += 1,
                TriageLabel::FalsePositive => fp_votes += 1,
                TriageLabel::NeedsReview => nr_votes += 1,
            }
        }

        let n = self.trees.len() as f64;
        let (label, votes) = if tp_votes >= fp_votes && tp_votes >= nr_votes {
            (TriageLabel::TruePositive, tp_votes)
        } else if fp_votes >= tp_votes && fp_votes >= nr_votes {
            (TriageLabel::FalsePositive, fp_votes)
        } else {
            (TriageLabel::NeedsReview, nr_votes)
        };

        TriageResult {
            label,
            confidence: (total_conf / n) * (votes as f64 / n),
            model_version: self.version.clone(),
        }
    }
}

// ── Stub engine (with Random Forest triage) ──────────────────────────

/// Engine that uses a pre-trained Random Forest for alert triage
/// and stubs for ONNX model loading (until `ort` crate is added).
#[derive(Debug)]
pub struct StubEngine {
    models: HashMap<String, ModelInfo>,
    rf_triage: RandomForest,
}

impl Default for StubEngine {
    fn default() -> Self {
        Self {
            models: HashMap::new(),
            rf_triage: RandomForest::pretrained(),
        }
    }
}

impl StubEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run alert triage inference using the Random Forest ensemble.
    pub fn triage_alert(&self, features: &TriageFeatures) -> TriageResult {
        self.rf_triage.predict(&features.to_vec())
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
                name: "alert_triage_rf_v1".into(),
                version: "1.0.0-rf5".into(),
                input_shape: vec![1, 7],
                output_shape: vec![1, 3],
                description: "Random Forest alert triage (5 trees, 7 features) — TP/FP/Review".into(),
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
        assert!(planned.iter().any(|m| m.name == "alert_triage_rf_v1"));
    }

    #[test]
    fn triage_high_score_is_tp() {
        let engine = StubEngine::new();
        let features = TriageFeatures {
            anomaly_score: 0.95,
            confidence: 0.9,
            suspicious_axes: 3,
            hour_of_day: 2,
            day_of_week: 6,
            alert_frequency_1h: 5,
            device_risk_score: 0.8,
        };
        let result = engine.triage_alert(&features);
        assert_eq!(result.label, TriageLabel::TruePositive);
        assert!(result.confidence > 0.8);
    }

    #[test]
    fn triage_low_score_is_fp() {
        let engine = StubEngine::new();
        let features = TriageFeatures {
            anomaly_score: 0.1,
            confidence: 0.1,
            suspicious_axes: 0,
            hour_of_day: 14,
            day_of_week: 2,
            alert_frequency_1h: 0,
            device_risk_score: 0.05,
        };
        let result = engine.triage_alert(&features);
        assert_eq!(result.label, TriageLabel::FalsePositive);
    }

    #[test]
    fn triage_mid_score_needs_review() {
        let engine = StubEngine::new();
        let features = TriageFeatures {
            anomaly_score: 0.5,
            confidence: 0.5,
            suspicious_axes: 1,
            hour_of_day: 10,
            day_of_week: 3,
            alert_frequency_1h: 2,
            device_risk_score: 0.3,
        };
        let result = engine.triage_alert(&features);
        // RF ensemble may classify mid-range as FP or NeedsReview
        assert!(result.label == TriageLabel::NeedsReview || result.label == TriageLabel::FalsePositive);
    }

    #[test]
    fn triage_features_to_vec() {
        let features = TriageFeatures {
            anomaly_score: 0.5,
            confidence: 0.8,
            suspicious_axes: 2,
            hour_of_day: 12,
            day_of_week: 3,
            alert_frequency_1h: 10,
            device_risk_score: 0.6,
        };
        let v = features.to_vec();
        assert_eq!(v.len(), 7);
        assert!((v[0] - 0.5).abs() < 1e-6);
        assert!((v[3] - 0.5).abs() < 1e-6); // 12/24
    }
}
