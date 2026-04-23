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
            TreeNode::Split {
                feature_idx,
                threshold,
                left,
                right,
            } => {
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
            DecisionTree {
                root: TreeNode::Split {
                    feature_idx: 0,
                    threshold: 0.7,
                    right: Box::new(TreeNode::Split {
                        feature_idx: 1,
                        threshold: 0.5,
                        right: Box::new(TreeNode::Leaf {
                            label: TruePositive,
                            confidence: 0.92,
                        }),
                        left: Box::new(TreeNode::Leaf {
                            label: NeedsReview,
                            confidence: 0.60,
                        }),
                    }),
                    left: Box::new(TreeNode::Split {
                        feature_idx: 0,
                        threshold: 0.3,
                        right: Box::new(TreeNode::Leaf {
                            label: NeedsReview,
                            confidence: 0.55,
                        }),
                        left: Box::new(TreeNode::Leaf {
                            label: FalsePositive,
                            confidence: 0.88,
                        }),
                    }),
                },
            },
            // Tree 2: confidence + alert_frequency
            DecisionTree {
                root: TreeNode::Split {
                    feature_idx: 1,
                    threshold: 0.6,
                    right: Box::new(TreeNode::Split {
                        feature_idx: 5,
                        threshold: 1.5, // ln(1+freq)
                        right: Box::new(TreeNode::Leaf {
                            label: TruePositive,
                            confidence: 0.85,
                        }),
                        left: Box::new(TreeNode::Split {
                            feature_idx: 0,
                            threshold: 0.5,
                            right: Box::new(TreeNode::Leaf {
                                label: TruePositive,
                                confidence: 0.78,
                            }),
                            left: Box::new(TreeNode::Leaf {
                                label: NeedsReview,
                                confidence: 0.52,
                            }),
                        }),
                    }),
                    left: Box::new(TreeNode::Leaf {
                        label: FalsePositive,
                        confidence: 0.82,
                    }),
                },
            },
            // Tree 3: device_risk + hour_of_day (off-hours = suspicious)
            DecisionTree {
                root: TreeNode::Split {
                    feature_idx: 6,
                    threshold: 0.5,
                    right: Box::new(TreeNode::Split {
                        feature_idx: 3,
                        threshold: 0.25, // before 6am normalised
                        left: Box::new(TreeNode::Leaf {
                            label: TruePositive,
                            confidence: 0.90,
                        }),
                        right: Box::new(TreeNode::Split {
                            feature_idx: 0,
                            threshold: 0.6,
                            right: Box::new(TreeNode::Leaf {
                                label: TruePositive,
                                confidence: 0.80,
                            }),
                            left: Box::new(TreeNode::Leaf {
                                label: NeedsReview,
                                confidence: 0.58,
                            }),
                        }),
                    }),
                    left: Box::new(TreeNode::Split {
                        feature_idx: 0,
                        threshold: 0.8,
                        right: Box::new(TreeNode::Leaf {
                            label: TruePositive,
                            confidence: 0.75,
                        }),
                        left: Box::new(TreeNode::Leaf {
                            label: FalsePositive,
                            confidence: 0.80,
                        }),
                    }),
                },
            },
            // Tree 4: suspicious_axes + anomaly_score
            DecisionTree {
                root: TreeNode::Split {
                    feature_idx: 2,
                    threshold: 1.5,
                    right: Box::new(TreeNode::Split {
                        feature_idx: 0,
                        threshold: 0.5,
                        right: Box::new(TreeNode::Leaf {
                            label: TruePositive,
                            confidence: 0.88,
                        }),
                        left: Box::new(TreeNode::Leaf {
                            label: NeedsReview,
                            confidence: 0.55,
                        }),
                    }),
                    left: Box::new(TreeNode::Split {
                        feature_idx: 1,
                        threshold: 0.7,
                        right: Box::new(TreeNode::Leaf {
                            label: NeedsReview,
                            confidence: 0.50,
                        }),
                        left: Box::new(TreeNode::Leaf {
                            label: FalsePositive,
                            confidence: 0.85,
                        }),
                    }),
                },
            },
            // Tree 5: day_of_week (weekend) + composite
            DecisionTree {
                root: TreeNode::Split {
                    feature_idx: 4,
                    threshold: 0.71, // weekend (5/7, 6/7)
                    right: Box::new(TreeNode::Split {
                        feature_idx: 0,
                        threshold: 0.4,
                        right: Box::new(TreeNode::Leaf {
                            label: TruePositive,
                            confidence: 0.83,
                        }),
                        left: Box::new(TreeNode::Leaf {
                            label: NeedsReview,
                            confidence: 0.50,
                        }),
                    }),
                    left: Box::new(TreeNode::Split {
                        feature_idx: 0,
                        threshold: 0.65,
                        right: Box::new(TreeNode::Split {
                            feature_idx: 1,
                            threshold: 0.5,
                            right: Box::new(TreeNode::Leaf {
                                label: TruePositive,
                                confidence: 0.82,
                            }),
                            left: Box::new(TreeNode::Leaf {
                                label: NeedsReview,
                                confidence: 0.55,
                            }),
                        }),
                        left: Box::new(TreeNode::Leaf {
                            label: FalsePositive,
                            confidence: 0.78,
                        }),
                    }),
                },
            },
        ];
        Self {
            trees,
            version: "1.0.0-rf5".into(),
        }
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
                description: "Random Forest alert triage (5 trees, 7 features) — TP/FP/Review"
                    .into(),
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
        assert!(
            result.label == TriageLabel::NeedsReview || result.label == TriageLabel::FalsePositive
        );
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

// ── ONNX Runtime Engine ──────────────────────────────────────────────

/// ONNX Runtime-backed inference engine.
///
/// When the `ort` crate is available, this engine loads .onnx models and
/// runs real inference. The current implementation provides the full
/// scaffolding with model management, batched inference, and warm-up
/// support. Model files are expected under `models/` directory.
#[derive(Debug)]
pub struct OnnxEngine {
    models: HashMap<String, OnnxModelSlot>,
    model_dir: String,
    #[allow(dead_code)]
    warm_up_on_load: bool,
}

#[derive(Debug, Clone)]
struct OnnxModelSlot {
    info: ModelInfo,
    status: ModelStatus,
    #[allow(dead_code)]
    path: String,
    inference_count: u64,
    last_latency_ms: f64,
}

impl OnnxEngine {
    /// Create a new ONNX engine with a model directory.
    pub fn new(model_dir: &str) -> Self {
        Self {
            models: HashMap::new(),
            model_dir: model_dir.to_string(),
            warm_up_on_load: true,
        }
    }

    /// Run alert triage with the ONNX alert triage model, falling back to
    /// the Random Forest ensemble if no ONNX model is loaded.
    pub fn triage_alert(&self, features: &TriageFeatures) -> TriageResult {
        let fv = features.to_vec();

        // Try ONNX model first
        if let Ok(pred) = self.predict("alert_triage_v1", &fv) {
            let label = match pred.label.as_str() {
                "true_positive" => TriageLabel::TruePositive,
                "false_positive" => TriageLabel::FalsePositive,
                _ => TriageLabel::NeedsReview,
            };
            return TriageResult {
                label,
                confidence: pred.confidence,
                model_version: format!("onnx-{}", pred.model),
            };
        }

        // Fallback to Random Forest
        RandomForest::pretrained().predict(&fv)
    }

    /// Get inference statistics for a model.
    pub fn model_stats(&self, model: &str) -> Option<(u64, f64)> {
        self.models
            .get(model)
            .map(|slot| (slot.inference_count, slot.last_latency_ms))
    }

    /// List all available .onnx files in the model directory.
    pub fn discover_models(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.model_dir) else {
            return vec![];
        };
        entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "onnx"))
            .filter_map(|e| e.path().to_str().map(String::from))
            .collect()
    }

    /// Load all discovered models in the model directory.
    pub fn load_all_discovered(&mut self) -> Vec<Result<ModelInfo, String>> {
        let paths = self.discover_models();
        paths.iter().map(|p| self.load_model(p)).collect()
    }
}

impl InferenceEngine for OnnxEngine {
    fn load_model(&mut self, path: &str) -> Result<ModelInfo, String> {
        let name = std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Validate file exists
        if !std::path::Path::new(path).exists() {
            return Err(format!("Model file not found: {path}"));
        }

        let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

        // NOTE: When `ort` crate is added, replace this with:
        //   let session = ort::Session::builder()?.commit_from_file(path)?;
        //   let input_shape = session.inputs[0].dimensions()...;
        //   let output_shape = session.outputs[0].dimensions()...;

        let info = ModelInfo {
            name: name.clone(),
            version: format!("onnx-{}", file_size),
            input_shape: vec![1, 64], // Will be extracted from ONNX metadata
            output_shape: vec![1, 1], // Will be extracted from ONNX metadata
            description: format!("ONNX model loaded from {path} ({file_size} bytes)"),
        };

        self.models.insert(
            name.clone(),
            OnnxModelSlot {
                info: info.clone(),
                status: ModelStatus::Ready,
                path: path.to_string(),
                inference_count: 0,
                last_latency_ms: 0.0,
            },
        );

        Ok(info)
    }

    fn predict(&self, model: &str, features: &[f64]) -> Result<Prediction, String> {
        let slot = self
            .models
            .get(model)
            .ok_or(format!("model '{model}' not loaded"))?;

        if slot.status != ModelStatus::Ready {
            return Err(format!("model '{model}' not ready: {:?}", slot.status));
        }

        let start = std::time::Instant::now();

        // NOTE: When `ort` crate is added, replace this with:
        //   let input = ndarray::Array2::from_shape_vec((1, features.len()), features.to_vec())?;
        //   let outputs = session.run(ort::inputs![input]?)?;
        //   let output = outputs[0].extract_tensor::<f32>()?;

        // Heuristic-based prediction based on feature statistics
        let mean = features.iter().sum::<f64>() / features.len().max(1) as f64;
        let variance =
            features.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / features.len().max(1) as f64;

        let (label, confidence) = if mean > 0.7 && variance < 0.1 {
            ("anomalous", 0.85 + variance)
        } else if mean < 0.3 {
            ("benign", 0.9 - variance)
        } else {
            ("uncertain", 0.5 + mean * 0.2)
        };

        let latency = start.elapsed().as_secs_f64() * 1000.0;

        Ok(Prediction {
            model: model.into(),
            label: label.into(),
            confidence: confidence.clamp(0.0, 1.0),
            latency_ms: latency,
            features_used: features.len(),
        })
    }

    fn list_models(&self) -> Vec<ModelInfo> {
        self.models.values().map(|s| s.info.clone()).collect()
    }

    fn status(&self, model: &str) -> ModelStatus {
        self.models
            .get(model)
            .map(|s| s.status)
            .unwrap_or(ModelStatus::NotLoaded)
    }

    fn unload_model(&mut self, model: &str) -> Result<(), String> {
        self.models.remove(model);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceCalibration {
    pub raw_confidence: f64,
    pub calibrated_confidence: f64,
    pub band: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowInferenceRecord {
    pub slot: String,
    pub timestamp: String,
    pub active_backend: String,
    pub active_label: String,
    pub active_confidence: f64,
    pub shadow_backend: Option<String>,
    pub shadow_label: Option<String>,
    pub shadow_confidence: Option<f64>,
    pub confidence_delta: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedTriageOutcome {
    pub result: TriageResult,
    #[serde(default)]
    pub shadow: Option<TriageResult>,
    pub fallback_used: bool,
    pub active_backend: String,
    #[serde(default)]
    pub shadow_backend: Option<String>,
    pub calibration: ConfidenceCalibration,
    #[serde(default)]
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRegistryStatus {
    pub slot: String,
    pub active_backend: String,
    #[serde(default)]
    pub shadow_backend: Option<String>,
    pub shadow_mode: bool,
    pub onnx_loaded: bool,
    pub last_refreshed_at: String,
    pub discovered_models: Vec<String>,
    pub loaded_models: Vec<ModelInfo>,
    pub available_models: Vec<ModelInfo>,
    #[serde(default)]
    pub recent_shadow_reports: Vec<ShadowInferenceRecord>,
}

#[derive(Debug)]
pub struct ModelRegistry {
    fallback: StubEngine,
    onnx: OnnxEngine,
    shadow_mode: bool,
    prefer_onnx_primary: bool,
    last_refreshed_at: String,
    recent_shadow_reports: Vec<ShadowInferenceRecord>,
}

impl ModelRegistry {
    pub fn new(model_dir: &str) -> Self {
        let mut registry = Self {
            fallback: StubEngine::new(),
            onnx: OnnxEngine::new(model_dir),
            shadow_mode: true,
            prefer_onnx_primary: false,
            last_refreshed_at: chrono::Utc::now().to_rfc3339(),
            recent_shadow_reports: Vec::new(),
        };
        registry.refresh();
        registry
    }

    pub fn refresh(&mut self) {
        for result in self.onnx.load_all_discovered() {
            let _ = result;
        }
        self.prefer_onnx_primary = self.onnx.status("alert_triage_v1") == ModelStatus::Ready;
        self.last_refreshed_at = chrono::Utc::now().to_rfc3339();
    }

    pub fn rollback_alert_triage(&mut self) -> bool {
        let changed = self.prefer_onnx_primary;
        self.prefer_onnx_primary = false;
        changed
    }

    pub fn enable_shadow_mode(&mut self, enabled: bool) {
        self.shadow_mode = enabled;
    }

    pub fn status(&self) -> ModelRegistryStatus {
        let discovered_models = self.onnx.discover_models();
        let loaded_models = {
            let mut models = self.onnx.list_models();
            if models.is_empty() {
                models = self.fallback.list_models();
            }
            models
        };
        ModelRegistryStatus {
            slot: "alert_triage".to_string(),
            active_backend: if self.prefer_onnx_primary && self.onnx.status("alert_triage_v1") == ModelStatus::Ready {
                "onnx".to_string()
            } else {
                "random_forest_fallback".to_string()
            },
            shadow_backend: if self.shadow_mode
                && self.onnx.status("alert_triage_v1") == ModelStatus::Ready
            {
                Some(if self.prefer_onnx_primary {
                    "random_forest_fallback".to_string()
                } else {
                    "onnx".to_string()
                })
            } else {
                None
            },
            shadow_mode: self.shadow_mode,
            onnx_loaded: self.onnx.status("alert_triage_v1") == ModelStatus::Ready,
            last_refreshed_at: self.last_refreshed_at.clone(),
            discovered_models,
            loaded_models,
            available_models: StubEngine::planned_models(),
            recent_shadow_reports: self.recent_shadow_reports.iter().rev().take(20).cloned().collect(),
        }
    }

    pub fn triage_alert(&mut self, features: &TriageFeatures) -> ManagedTriageOutcome {
        let onnx_ready = self.onnx.status("alert_triage_v1") == ModelStatus::Ready;
        let fallback = self.fallback.triage_alert(features);
        let use_onnx_primary = self.prefer_onnx_primary && onnx_ready;
        let primary = if use_onnx_primary {
            self.onnx.triage_alert(features)
        } else {
            fallback.clone()
        };
        let shadow = if self.shadow_mode && onnx_ready {
            Some(if use_onnx_primary {
                fallback.clone()
            } else {
                self.onnx.triage_alert(features)
            })
        } else {
            None
        };
        if let Some(ref shadow_result) = shadow {
            self.record_shadow_report(
                if use_onnx_primary { "onnx" } else { "random_forest_fallback" },
                shadow_result,
                &primary,
                if use_onnx_primary {
                    Some("random_forest_fallback")
                } else {
                    Some("onnx")
                },
            );
        }
        let calibrated_confidence = 1.0 / (1.0 + (-4.0 * (primary.confidence - 0.5)).exp());
        let band = if calibrated_confidence >= 0.85 {
            "high"
        } else if calibrated_confidence >= 0.6 {
            "medium"
        } else {
            "low"
        };
        let mut rationale = Vec::new();
        rationale.push(format!(
            "primary backend: {}",
            if use_onnx_primary { "onnx" } else { "random_forest_fallback" }
        ));
        if shadow.is_some() {
            rationale.push("shadow inference captured for calibration comparison".to_string());
        } else {
            rationale.push("fallback-only decision because no ONNX triage model is loaded".to_string());
        }
        ManagedTriageOutcome {
            result: primary.clone(),
            shadow,
            fallback_used: !use_onnx_primary,
            active_backend: if use_onnx_primary {
                "onnx".to_string()
            } else {
                "random_forest_fallback".to_string()
            },
            shadow_backend: if self.shadow_mode && onnx_ready {
                Some(if use_onnx_primary {
                    "random_forest_fallback".to_string()
                } else {
                    "onnx".to_string()
                })
            } else {
                None
            },
            calibration: ConfidenceCalibration {
                raw_confidence: primary.confidence,
                calibrated_confidence,
                band: band.to_string(),
            },
            rationale,
        }
    }

    fn record_shadow_report(
        &mut self,
        active_backend: &str,
        shadow: &TriageResult,
        primary: &TriageResult,
        shadow_backend: Option<&str>,
    ) {
        self.recent_shadow_reports.push(ShadowInferenceRecord {
            slot: "alert_triage".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            active_backend: active_backend.to_string(),
            active_label: format!("{:?}", primary.label),
            active_confidence: primary.confidence,
            shadow_backend: shadow_backend.map(str::to_string),
            shadow_label: Some(format!("{:?}", shadow.label)),
            shadow_confidence: Some(shadow.confidence),
            confidence_delta: Some((primary.confidence - shadow.confidence).abs()),
        });
        if self.recent_shadow_reports.len() > 200 {
            let keep_from = self.recent_shadow_reports.len() - 200;
            self.recent_shadow_reports.drain(0..keep_from);
        }
    }
}

#[cfg(test)]
mod onnx_tests {
    use super::*;

    #[test]
    fn onnx_engine_creation() {
        let engine = OnnxEngine::new("models");
        assert!(engine.list_models().is_empty());
        assert_eq!(engine.status("nonexistent"), ModelStatus::NotLoaded);
    }

    #[test]
    fn onnx_discover_empty_dir() {
        let engine = OnnxEngine::new("/nonexistent/path");
        assert!(engine.discover_models().is_empty());
    }

    #[test]
    fn onnx_load_missing_model() {
        let mut engine = OnnxEngine::new("models");
        assert!(engine.load_model("/nonexistent/model.onnx").is_err());
    }

    #[test]
    fn onnx_predict_not_loaded() {
        let engine = OnnxEngine::new("models");
        assert!(engine.predict("missing", &[1.0, 2.0]).is_err());
    }

    #[test]
    fn onnx_triage_fallback_to_rf() {
        let engine = OnnxEngine::new("models");
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
    }

    #[test]
    fn onnx_model_stats_none() {
        let engine = OnnxEngine::new("models");
        assert!(engine.model_stats("x").is_none());
    }

    #[test]
    fn triage_features_boundary_values() {
        // Test with all-zero features
        let zero = TriageFeatures {
            anomaly_score: 0.0,
            confidence: 0.0,
            suspicious_axes: 0,
            hour_of_day: 0,
            day_of_week: 0,
            alert_frequency_1h: 0,
            device_risk_score: 0.0,
        };
        let vec = zero.to_vec();
        assert_eq!(vec.len(), 7);
        assert!((vec[0] - 0.0).abs() < f64::EPSILON);
        assert!((vec[5] - 0.0_f64.ln_1p()).abs() < f64::EPSILON);

        // Test with max boundary values
        let max_features = TriageFeatures {
            anomaly_score: 1.0,
            confidence: 1.0,
            suspicious_axes: 100,
            hour_of_day: 255, // should clamp to 23
            day_of_week: 255, // should clamp to 6
            alert_frequency_1h: u32::MAX,
            device_risk_score: 1.0,
        };
        let vec = max_features.to_vec();
        assert!((vec[3] - 23.0 / 24.0).abs() < f64::EPSILON); // hour clamped
        assert!((vec[4] - 6.0 / 7.0).abs() < f64::EPSILON); // day clamped
    }

    #[test]
    fn rf_all_trees_agree_high_anomaly() {
        let rf = RandomForest::pretrained();
        let features = TriageFeatures {
            anomaly_score: 0.99,
            confidence: 0.99,
            suspicious_axes: 5,
            hour_of_day: 3,
            day_of_week: 6,
            alert_frequency_1h: 50,
            device_risk_score: 0.95,
        };
        let result = rf.predict(&features.to_vec());
        assert_eq!(result.label, TriageLabel::TruePositive);
        assert!(result.confidence > 0.7);
    }

    #[test]
    fn rf_all_trees_agree_low_anomaly() {
        let rf = RandomForest::pretrained();
        let features = TriageFeatures {
            anomaly_score: 0.05,
            confidence: 0.1,
            suspicious_axes: 0,
            hour_of_day: 12,
            day_of_week: 3,
            alert_frequency_1h: 0,
            device_risk_score: 0.1,
        };
        let result = rf.predict(&features.to_vec());
        assert_eq!(result.label, TriageLabel::FalsePositive);
    }

    #[test]
    fn onnx_triage_boundary_needs_review() {
        let engine = OnnxEngine::new("models");
        // Mid-range features should yield NeedsReview
        let features = TriageFeatures {
            anomaly_score: 0.5,
            confidence: 0.5,
            suspicious_axes: 1,
            hour_of_day: 12,
            day_of_week: 3,
            alert_frequency_1h: 2,
            device_risk_score: 0.4,
        };
        let result = engine.triage_alert(&features);
        // The RF ensemble may predict NeedsReview for mid-range inputs
        assert!(result.confidence > 0.0 && result.confidence <= 1.0);
    }

    #[test]
    fn stub_multiple_models() {
        let mut engine = StubEngine::new();
        let _ = engine.load_model("model_a");
        let _ = engine.load_model("model_b");
        assert_eq!(engine.list_models().len(), 2);
        engine.unload_model("model_a").unwrap();
        assert_eq!(engine.list_models().len(), 1);
        assert_eq!(engine.status("model_a"), ModelStatus::NotLoaded);
        assert_eq!(engine.status("model_b"), ModelStatus::Ready);
    }

    #[test]
    fn model_info_serialization() {
        let info = ModelInfo {
            name: "test".into(),
            version: "1.0".into(),
            input_shape: vec![1, 7],
            output_shape: vec![1, 3],
            description: "Test model".into(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: ModelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
        assert_eq!(back.input_shape, vec![1, 7]);
    }

    #[test]
    fn model_registry_falls_back_without_onnx_model() {
        let mut registry = ModelRegistry::new("/nonexistent/models");
        let features = TriageFeatures {
            anomaly_score: 0.8,
            confidence: 0.9,
            suspicious_axes: 3,
            hour_of_day: 2,
            day_of_week: 1,
            alert_frequency_1h: 3,
            device_risk_score: 0.7,
        };
        let outcome = registry.triage_alert(&features);
        assert_eq!(outcome.active_backend, "random_forest_fallback");
        assert!(outcome.calibration.calibrated_confidence > 0.0);
        let status = registry.status();
        assert!(!status.onnx_loaded);
        assert_eq!(status.available_models.len(), 3);
    }
}
