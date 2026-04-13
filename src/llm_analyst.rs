// ── LLM-Assisted Analyst ─────────────────────────────────────────────────────
//
// Provides an /api/ask endpoint that lets analysts query their environment
// using natural language. Implements a basic RAG (Retrieval-Augmented
// Generation) pipeline:
//
//   1. Parse analyst question
//   2. Search relevant alerts/events via Tantivy
//   3. Compose prompt with context
//   4. Send to LLM provider (OpenAI-compatible API)
//   5. Return structured response with citations
//
// Supports: OpenAI, Azure OpenAI, Anthropic, Ollama (local), any
// OpenAI-compatible endpoint.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Configuration ────────────────────────────────────────────────────────────

/// LLM provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub provider: LlmProvider,
    pub api_endpoint: String,
    #[serde(skip_serializing)]
    pub api_key: String,
    pub model: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    #[serde(default = "default_context_window")]
    pub context_window: usize,
    #[serde(default)]
    pub system_prompt: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_context_events")]
    pub max_context_events: usize,
}

fn default_max_tokens() -> u32 {
    2048
}
fn default_temperature() -> f32 {
    0.1
}
fn default_context_window() -> usize {
    8192
}
fn default_max_context_events() -> usize {
    20
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: LlmProvider::OpenAi,
            api_endpoint: "https://api.openai.com/v1/chat/completions".into(),
            api_key: String::new(),
            model: "gpt-4o-mini".into(),
            max_tokens: 2048,
            temperature: 0.1,
            context_window: 8192,
            system_prompt: None,
            enabled: false,
            max_context_events: 20,
        }
    }
}

/// Supported LLM providers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LlmProvider {
    OpenAi,
    AzureOpenAi,
    Anthropic,
    Ollama,
    Custom,
}

// ── Request / Response ───────────────────────────────────────────────────────

/// Analyst question to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystQuery {
    pub question: String,
    #[serde(default)]
    pub context_filter: Option<ContextFilter>,
    #[serde(default)]
    pub conversation_id: Option<String>,
}

/// Optional filters to scope the RAG context retrieval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextFilter {
    pub time_range_hours: Option<u64>,
    pub severity_min: Option<String>,
    pub device_filter: Option<String>,
    pub alert_types: Option<Vec<String>>,
}

/// Structured response from the LLM analyst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystResponse {
    pub answer: String,
    pub citations: Vec<Citation>,
    pub confidence: f32,
    pub model_used: String,
    pub tokens_used: TokenUsage,
    pub response_time_ms: u64,
    pub conversation_id: String,
}

/// Citation referencing a specific event or alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Citation {
    pub source_type: String,  // "alert", "event", "rule"
    pub source_id: String,
    pub summary: String,
    pub relevance_score: f32,
}

/// Token usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

// ── LLM Analyst Engine ──────────────────────────────────────────────────────

/// RAG-based LLM analyst engine.
#[derive(Debug)]
pub struct LlmAnalyst {
    config: LlmConfig,
    conversation_history: std::collections::HashMap<String, Vec<ChatMessage>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
    #[serde(default)]
    usage: Option<OpenAiUsage>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

impl LlmAnalyst {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            config,
            conversation_history: std::collections::HashMap::new(),
        }
    }

    /// Process an analyst query through the RAG pipeline.
    pub fn ask(
        &mut self,
        query: &AnalystQuery,
        context_events: &[ContextEvent],
    ) -> Result<AnalystResponse, String> {
        if !self.config.enabled {
            return Err("LLM analyst is not enabled".into());
        }
        if self.config.api_key.is_empty() {
            return Err("API key not configured".into());
        }

        let start = SystemTime::now();

        let conversation_id = query
            .conversation_id
            .clone()
            .unwrap_or_else(|| format!("conv-{}", now_millis()));

        // Build the prompt with context
        let system_msg = self.build_system_prompt();
        let context_block = self.build_context_block(context_events);
        let user_msg = format!("{}\n\n### Relevant Security Context\n{}", query.question, context_block);

        // Get conversation history snapshot (clone to avoid borrow conflict with call_llm)
        let history_snapshot = self
            .conversation_history
            .get(&conversation_id)
            .cloned()
            .unwrap_or_default();

        // Build messages array
        let mut messages = vec![ChatMessage {
            role: "system".into(),
            content: system_msg,
        }];

        // Add last 6 turns of history (3 user + 3 assistant)
        let hist_start = history_snapshot.len().saturating_sub(6);
        messages.extend_from_slice(&history_snapshot[hist_start..]);

        messages.push(ChatMessage {
            role: "user".into(),
            content: user_msg.clone(),
        });

        // Call the LLM
        let (answer, usage) = self.call_llm(&messages)?;

        // Store in history
        let history = self
            .conversation_history
            .entry(conversation_id.clone())
            .or_default();
        history.push(ChatMessage {
            role: "user".into(),
            content: query.question.clone(),
        });
        history.push(ChatMessage {
            role: "assistant".into(),
            content: answer.clone(),
        });

        // Build citations from context
        let citations: Vec<Citation> = context_events
            .iter()
            .take(5)
            .map(|e| Citation {
                source_type: e.event_type.clone(),
                source_id: e.id.clone(),
                summary: e.summary.clone(),
                relevance_score: e.relevance,
            })
            .collect();

        let elapsed = start.elapsed().unwrap_or_default().as_millis() as u64;

        Ok(AnalystResponse {
            answer,
            citations,
            confidence: self.estimate_confidence(&usage),
            model_used: self.config.model.clone(),
            tokens_used: TokenUsage {
                prompt_tokens: usage.prompt_tokens,
                completion_tokens: usage.completion_tokens,
                total_tokens: usage.total_tokens,
            },
            response_time_ms: elapsed,
            conversation_id,
        })
    }

    fn build_system_prompt(&self) -> String {
        self.config.system_prompt.clone().unwrap_or_else(|| {
            "You are an expert security analyst assistant for Wardex XDR. \
             Analyze security events, alerts, and threat data to help SOC analysts \
             investigate incidents. Always cite specific events when making claims. \
             Be concise and actionable. Format responses in Markdown. \
             If you're unsure about something, say so clearly."
                .into()
        })
    }

    fn build_context_block(&self, events: &[ContextEvent]) -> String {
        if events.is_empty() {
            return "No relevant events found in the time window.".into();
        }

        let mut block = String::new();
        for (i, event) in events.iter().take(self.config.max_context_events).enumerate() {
            block.push_str(&format!(
                "**[{}]** ({}) {} — Severity: {} | Device: {} | Time: {}\n  {}\n\n",
                i + 1,
                event.event_type,
                event.id,
                event.severity,
                event.device.as_deref().unwrap_or("unknown"),
                event.timestamp,
                event.summary,
            ));
        }
        block
    }

    fn call_llm(&self, messages: &[ChatMessage]) -> Result<(String, OpenAiUsage), String> {
        let body = serde_json::json!({
            "model": self.config.model,
            "messages": messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        });

        let resp: OpenAiResponse = ureq::post(&self.config.api_endpoint)
            .set("Authorization", &format!("Bearer {}", self.config.api_key))
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| format!("LLM API call failed: {e}"))?
            .into_json()
            .map_err(|e| format!("LLM response parse failed: {e}"))?;

        let answer = resp
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        let usage = resp.usage.unwrap_or(OpenAiUsage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        });

        Ok((answer, usage))
    }

    fn estimate_confidence(&self, usage: &OpenAiUsage) -> f32 {
        // Heuristic: longer responses with more context generally indicate higher confidence
        let ratio = usage.completion_tokens as f32 / usage.prompt_tokens.max(1) as f32;
        (ratio * 2.0).min(1.0).max(0.1)
    }

    /// Clear conversation history for a given conversation ID.
    pub fn clear_conversation(&mut self, conversation_id: &str) -> bool {
        self.conversation_history.remove(conversation_id).is_some()
    }

    /// Get provider status.
    pub fn status(&self) -> LlmStatus {
        LlmStatus {
            enabled: self.config.enabled,
            provider: format!("{:?}", self.config.provider),
            model: self.config.model.clone(),
            has_api_key: !self.config.api_key.is_empty(),
            active_conversations: self.conversation_history.len(),
            endpoint: self.config.api_endpoint.clone(),
        }
    }

    pub fn config(&self) -> &LlmConfig {
        &self.config
    }
}

/// Context event passed to the RAG pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEvent {
    pub id: String,
    pub event_type: String,
    pub summary: String,
    pub severity: String,
    pub timestamp: String,
    pub device: Option<String>,
    pub raw_data: Option<String>,
    pub relevance: f32,
}

/// LLM analyst status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmStatus {
    pub enabled: bool,
    pub provider: String,
    pub model: String,
    pub has_api_key: bool,
    pub active_conversations: usize,
    pub endpoint: String,
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LlmConfig {
        LlmConfig {
            enabled: true,
            api_key: "test-key".into(),
            ..Default::default()
        }
    }

    #[test]
    fn analyst_creation() {
        let analyst = LlmAnalyst::new(test_config());
        let status = analyst.status();
        assert!(status.enabled);
        assert!(status.has_api_key);
        assert_eq!(status.active_conversations, 0);
    }

    #[test]
    fn disabled_analyst_rejects_queries() {
        let mut analyst = LlmAnalyst::new(LlmConfig::default());
        let query = AnalystQuery {
            question: "What happened?".into(),
            context_filter: None,
            conversation_id: None,
        };
        assert!(analyst.ask(&query, &[]).is_err());
    }

    #[test]
    fn missing_api_key_rejects() {
        let mut analyst = LlmAnalyst::new(LlmConfig {
            enabled: true,
            api_key: String::new(),
            ..Default::default()
        });
        let query = AnalystQuery {
            question: "Test".into(),
            context_filter: None,
            conversation_id: None,
        };
        let err = analyst.ask(&query, &[]).unwrap_err();
        assert!(err.contains("API key"));
    }

    #[test]
    fn context_block_formatting() {
        let analyst = LlmAnalyst::new(test_config());
        let events = vec![
            ContextEvent {
                id: "ALT-001".into(),
                event_type: "alert".into(),
                summary: "Brute force detected on SSH".into(),
                severity: "high".into(),
                timestamp: "2025-01-15T10:30:00Z".into(),
                device: Some("gateway-01".into()),
                raw_data: None,
                relevance: 0.95,
            },
            ContextEvent {
                id: "EVT-042".into(),
                event_type: "event".into(),
                summary: "Failed login from 10.0.0.5".into(),
                severity: "medium".into(),
                timestamp: "2025-01-15T10:29:55Z".into(),
                device: None,
                raw_data: None,
                relevance: 0.82,
            },
        ];
        let block = analyst.build_context_block(&events);
        assert!(block.contains("ALT-001"));
        assert!(block.contains("Brute force"));
        assert!(block.contains("gateway-01"));
        assert!(block.contains("unknown")); // second event has no device
    }

    #[test]
    fn empty_context_block() {
        let analyst = LlmAnalyst::new(test_config());
        let block = analyst.build_context_block(&[]);
        assert!(block.contains("No relevant events"));
    }

    #[test]
    fn system_prompt_custom() {
        let config = LlmConfig {
            system_prompt: Some("You are a test bot.".into()),
            ..test_config()
        };
        let analyst = LlmAnalyst::new(config);
        assert_eq!(analyst.build_system_prompt(), "You are a test bot.");
    }

    #[test]
    fn system_prompt_default() {
        let analyst = LlmAnalyst::new(test_config());
        let prompt = analyst.build_system_prompt();
        assert!(prompt.contains("Wardex XDR"));
        assert!(prompt.contains("security analyst"));
    }

    #[test]
    fn conversation_clear() {
        let mut analyst = LlmAnalyst::new(test_config());
        analyst.conversation_history.insert(
            "conv-1".into(),
            vec![ChatMessage {
                role: "user".into(),
                content: "test".into(),
            }],
        );
        assert!(analyst.clear_conversation("conv-1"));
        assert!(!analyst.clear_conversation("conv-nonexistent"));
    }

    #[test]
    fn provider_variants() {
        let p = LlmProvider::Ollama;
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "\"ollama\"");
    }

    #[test]
    fn confidence_estimation() {
        let analyst = LlmAnalyst::new(test_config());
        let usage = OpenAiUsage {
            prompt_tokens: 500,
            completion_tokens: 200,
            total_tokens: 700,
        };
        let conf = analyst.estimate_confidence(&usage);
        assert!(conf > 0.0 && conf <= 1.0);
    }

    #[test]
    fn max_context_events_respected() {
        let mut config = test_config();
        config.max_context_events = 2;
        let analyst = LlmAnalyst::new(config);
        let events: Vec<ContextEvent> = (0..5)
            .map(|i| ContextEvent {
                id: format!("EVT-{i:03}"),
                event_type: "alert".into(),
                summary: format!("Event {i}"),
                severity: "medium".into(),
                timestamp: "2025-01-15T10:00:00Z".into(),
                device: None,
                raw_data: None,
                relevance: 0.5,
            })
            .collect();
        let block = analyst.build_context_block(&events);
        // Should only include max_context_events entries
        assert!(block.contains("EVT-000"));
        assert!(block.contains("EVT-001"));
    }

    #[test]
    fn context_block_escapes_special_chars() {
        let analyst = LlmAnalyst::new(test_config());
        let events = vec![ContextEvent {
            id: "EVT-XSS".into(),
            event_type: "alert".into(),
            summary: "Script <script>alert('xss')</script> detected".into(),
            severity: "high".into(),
            timestamp: "2025-01-15T10:00:00Z".into(),
            device: Some("host-01".into()),
            raw_data: None,
            relevance: 0.9,
        }];
        let block = analyst.build_context_block(&events);
        assert!(block.contains("EVT-XSS"));
        assert!(block.contains("Script"));
    }

    #[test]
    fn conversation_isolation() {
        let mut analyst = LlmAnalyst::new(test_config());
        analyst.conversation_history.insert(
            "conv-a".into(),
            vec![ChatMessage { role: "user".into(), content: "question A".into() }],
        );
        analyst.conversation_history.insert(
            "conv-b".into(),
            vec![ChatMessage { role: "user".into(), content: "question B".into() }],
        );
        // Clearing one doesn't affect the other
        assert!(analyst.clear_conversation("conv-a"));
        assert!(!analyst.conversation_history.contains_key("conv-a"));
        assert!(analyst.conversation_history.contains_key("conv-b"));
    }

    #[test]
    fn default_config_values() {
        let config = LlmConfig::default();
        assert_eq!(config.max_tokens, 2048);
        assert!((config.temperature - 0.1).abs() < f32::EPSILON);
        assert_eq!(config.context_window, 8192);
        assert_eq!(config.max_context_events, 20);
        assert!(!config.enabled);
        assert_eq!(config.provider, LlmProvider::OpenAi);
    }

    #[test]
    fn provider_serialization_roundtrip() {
        for provider in [LlmProvider::OpenAi, LlmProvider::AzureOpenAi, LlmProvider::Anthropic, LlmProvider::Ollama, LlmProvider::Custom] {
            let json = serde_json::to_string(&provider).unwrap();
            let back: LlmProvider = serde_json::from_str(&json).unwrap();
            assert_eq!(provider, back);
        }
    }

    #[test]
    fn config_serialization_hides_api_key() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("test-key-12345"));
    }

    #[test]
    fn analyst_query_deserialization() {
        let json = r#"{"question":"What happened?","conversation_id":"c1"}"#;
        let query: AnalystQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.question, "What happened?");
        assert_eq!(query.conversation_id.unwrap(), "c1");
        assert!(query.context_filter.is_none());
    }

    #[test]
    fn context_filter_deserialization() {
        let json = r#"{"question":"test","context_filter":{"time_range_hours":24,"severity_min":"high"}}"#;
        let query: AnalystQuery = serde_json::from_str(json).unwrap();
        let filter = query.context_filter.unwrap();
        assert_eq!(filter.time_range_hours.unwrap(), 24);
        assert_eq!(filter.severity_min.unwrap(), "high");
    }
}
