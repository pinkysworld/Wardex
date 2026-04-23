use serde::{Deserialize, Serialize};

fn has_text(value: &str) -> bool {
    !value.trim().is_empty()
}

fn normalize_optional_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupValidationIssue {
    pub field: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupValidation {
    pub status: String,
    pub issues: Vec<SetupValidationIssue>,
}

impl SetupValidation {
    fn new(disabled: bool, issues: Vec<SetupValidationIssue>) -> Self {
        let status = if disabled {
            "disabled"
        } else if issues.is_empty() {
            "ready"
        } else {
            "warning"
        };
        Self {
            status: status.to_string(),
            issues,
        }
    }
}

fn error(field: &str, message: &str) -> SetupValidationIssue {
    SetupValidationIssue {
        field: field.to_string(),
        level: "error".to_string(),
        message: message.to_string(),
    }
}

fn warning(field: &str, message: &str) -> SetupValidationIssue {
    SetupValidationIssue {
        field: field.to_string(),
        level: "warning".to_string(),
        message: message.to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCollectorSetup {
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub poll_interval_secs: u64,
    pub max_results: u32,
    pub event_name_filter: Vec<String>,
    pub enabled: bool,
}

impl Default for AwsCollectorSetup {
    fn default() -> Self {
        let defaults = crate::collector_aws::AwsCollectorConfig::default();
        Self {
            region: defaults.region,
            access_key_id: defaults.access_key_id,
            secret_access_key: defaults.secret_access_key,
            session_token: defaults.session_token,
            poll_interval_secs: defaults.poll_interval_secs,
            max_results: defaults.max_results,
            event_name_filter: defaults.event_name_filter,
            enabled: defaults.enabled,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AwsCollectorSetupPatch {
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub session_token: Option<String>,
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
    #[serde(default)]
    pub max_results: Option<u32>,
    #[serde(default)]
    pub event_name_filter: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCollectorSetupView {
    pub region: String,
    pub access_key_id: String,
    pub poll_interval_secs: u64,
    pub max_results: u32,
    pub event_name_filter: Vec<String>,
    pub enabled: bool,
    pub has_secret_access_key: bool,
    pub has_session_token: bool,
}

impl AwsCollectorSetup {
    pub fn apply_patch(&mut self, patch: AwsCollectorSetupPatch) {
        if let Some(region) = patch.region {
            self.region = region;
        }
        if let Some(access_key_id) = patch.access_key_id {
            self.access_key_id = access_key_id;
        }
        if let Some(secret_access_key) = patch.secret_access_key
            && has_text(&secret_access_key)
        {
            self.secret_access_key = secret_access_key;
        }
        if let Some(session_token) = patch.session_token {
            self.session_token = normalize_optional_string(session_token);
        }
        if let Some(poll_interval_secs) = patch.poll_interval_secs {
            self.poll_interval_secs = poll_interval_secs;
        }
        if let Some(max_results) = patch.max_results {
            self.max_results = max_results;
        }
        if let Some(event_name_filter) = patch.event_name_filter {
            self.event_name_filter = event_name_filter;
        }
        if let Some(enabled) = patch.enabled {
            self.enabled = enabled;
        }
    }

    pub fn validate(&self) -> SetupValidation {
        let mut issues = Vec::new();
        if self.enabled {
            if !has_text(&self.region) {
                issues.push(error("region", "Region is required when the collector is enabled."));
            }
            if !has_text(&self.access_key_id) {
                issues.push(error(
                    "access_key_id",
                    "Access key ID or secret reference is required when the collector is enabled.",
                ));
            }
            if !has_text(&self.secret_access_key) {
                issues.push(error(
                    "secret_access_key",
                    "Secret access key or secret reference is required when the collector is enabled.",
                ));
            }
        }
        if self.poll_interval_secs == 0 {
            issues.push(error(
                "poll_interval_secs",
                "Poll interval must be at least 1 second.",
            ));
        }
        if self.max_results == 0 {
            issues.push(error(
                "max_results",
                "At least one event must be requested per poll.",
            ));
        }
        if self.event_name_filter.is_empty() {
            issues.push(warning(
                "event_name_filter",
                "No event-name filter is configured, so every CloudTrail event will be queried.",
            ));
        }
        SetupValidation::new(!self.enabled, issues)
    }

    pub fn to_runtime(
        &self,
        resolver: &crate::secrets::SecretsResolver,
    ) -> Result<crate::collector_aws::AwsCollectorConfig, String> {
        Ok(crate::collector_aws::AwsCollectorConfig {
            region: self.region.clone(),
            access_key_id: resolver.resolve(&self.access_key_id)?,
            secret_access_key: resolver.resolve(&self.secret_access_key)?,
            session_token: self
                .session_token
                .as_ref()
                .map(|value| resolver.resolve(value))
                .transpose()?,
            poll_interval_secs: self.poll_interval_secs,
            max_results: self.max_results,
            event_name_filter: self.event_name_filter.clone(),
            enabled: self.enabled,
        })
    }

    pub fn view(&self) -> AwsCollectorSetupView {
        AwsCollectorSetupView {
            region: self.region.clone(),
            access_key_id: self.access_key_id.clone(),
            poll_interval_secs: self.poll_interval_secs,
            max_results: self.max_results,
            event_name_filter: self.event_name_filter.clone(),
            enabled: self.enabled,
            has_secret_access_key: has_text(&self.secret_access_key),
            has_session_token: self.session_token.as_ref().is_some_and(|value| has_text(value)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureCollectorSetup {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub subscription_id: String,
    pub poll_interval_secs: u64,
    pub categories: Vec<String>,
    pub enabled: bool,
}

impl Default for AzureCollectorSetup {
    fn default() -> Self {
        let defaults = crate::collector_azure::AzureCollectorConfig::default();
        Self {
            tenant_id: defaults.tenant_id,
            client_id: defaults.client_id,
            client_secret: defaults.client_secret,
            subscription_id: defaults.subscription_id,
            poll_interval_secs: defaults.poll_interval_secs,
            categories: defaults.categories,
            enabled: defaults.enabled,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AzureCollectorSetupPatch {
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub subscription_id: Option<String>,
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureCollectorSetupView {
    pub tenant_id: String,
    pub client_id: String,
    pub subscription_id: String,
    pub poll_interval_secs: u64,
    pub categories: Vec<String>,
    pub enabled: bool,
    pub has_client_secret: bool,
}

impl AzureCollectorSetup {
    pub fn apply_patch(&mut self, patch: AzureCollectorSetupPatch) {
        if let Some(tenant_id) = patch.tenant_id {
            self.tenant_id = tenant_id;
        }
        if let Some(client_id) = patch.client_id {
            self.client_id = client_id;
        }
        if let Some(client_secret) = patch.client_secret
            && has_text(&client_secret)
        {
            self.client_secret = client_secret;
        }
        if let Some(subscription_id) = patch.subscription_id {
            self.subscription_id = subscription_id;
        }
        if let Some(poll_interval_secs) = patch.poll_interval_secs {
            self.poll_interval_secs = poll_interval_secs;
        }
        if let Some(categories) = patch.categories {
            self.categories = categories;
        }
        if let Some(enabled) = patch.enabled {
            self.enabled = enabled;
        }
    }

    pub fn validate(&self) -> SetupValidation {
        let mut issues = Vec::new();
        if self.enabled {
            if !has_text(&self.tenant_id) {
                issues.push(error("tenant_id", "Tenant ID is required when the collector is enabled."));
            }
            if !has_text(&self.client_id) {
                issues.push(error("client_id", "Client ID is required when the collector is enabled."));
            }
            if !has_text(&self.client_secret) {
                issues.push(error(
                    "client_secret",
                    "Client secret or secret reference is required when the collector is enabled.",
                ));
            }
            if !has_text(&self.subscription_id) {
                issues.push(error(
                    "subscription_id",
                    "Subscription ID is required when the collector is enabled.",
                ));
            }
        }
        if self.poll_interval_secs == 0 {
            issues.push(error(
                "poll_interval_secs",
                "Poll interval must be at least 1 second.",
            ));
        }
        if self.categories.is_empty() {
            issues.push(warning(
                "categories",
                "No Azure Activity categories are configured, so validation may return sparse results.",
            ));
        }
        SetupValidation::new(!self.enabled, issues)
    }

    pub fn to_runtime(
        &self,
        resolver: &crate::secrets::SecretsResolver,
    ) -> Result<crate::collector_azure::AzureCollectorConfig, String> {
        Ok(crate::collector_azure::AzureCollectorConfig {
            tenant_id: resolver.resolve(&self.tenant_id)?,
            client_id: resolver.resolve(&self.client_id)?,
            client_secret: resolver.resolve(&self.client_secret)?,
            subscription_id: resolver.resolve(&self.subscription_id)?,
            poll_interval_secs: self.poll_interval_secs,
            categories: self.categories.clone(),
            enabled: self.enabled,
        })
    }

    pub fn view(&self) -> AzureCollectorSetupView {
        AzureCollectorSetupView {
            tenant_id: self.tenant_id.clone(),
            client_id: self.client_id.clone(),
            subscription_id: self.subscription_id.clone(),
            poll_interval_secs: self.poll_interval_secs,
            categories: self.categories.clone(),
            enabled: self.enabled,
            has_client_secret: has_text(&self.client_secret),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaCollectorSetup {
    pub domain: String,
    pub api_token: String,
    pub poll_interval_secs: u64,
    pub event_type_filter: Vec<String>,
    pub enabled: bool,
}

impl Default for OktaCollectorSetup {
    fn default() -> Self {
        let defaults = crate::collector_identity::OktaConfig::default();
        Self {
            domain: defaults.domain,
            api_token: defaults.api_token,
            poll_interval_secs: defaults.poll_interval_secs,
            event_type_filter: defaults.event_type_filter,
            enabled: defaults.enabled,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OktaCollectorSetupPatch {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub api_token: Option<String>,
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
    #[serde(default)]
    pub event_type_filter: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaCollectorSetupView {
    pub domain: String,
    pub poll_interval_secs: u64,
    pub event_type_filter: Vec<String>,
    pub enabled: bool,
    pub has_api_token: bool,
}

impl OktaCollectorSetup {
    pub fn apply_patch(&mut self, patch: OktaCollectorSetupPatch) {
        if let Some(domain) = patch.domain {
            self.domain = domain;
        }
        if let Some(api_token) = patch.api_token
            && has_text(&api_token)
        {
            self.api_token = api_token;
        }
        if let Some(poll_interval_secs) = patch.poll_interval_secs {
            self.poll_interval_secs = poll_interval_secs;
        }
        if let Some(event_type_filter) = patch.event_type_filter {
            self.event_type_filter = event_type_filter;
        }
        if let Some(enabled) = patch.enabled {
            self.enabled = enabled;
        }
    }

    pub fn validate(&self) -> SetupValidation {
        let mut issues = Vec::new();
        if self.enabled {
            if !has_text(&self.domain) {
                issues.push(error("domain", "Okta domain is required when the collector is enabled."));
            }
            if !has_text(&self.api_token) {
                issues.push(error(
                    "api_token",
                    "Okta API token or secret reference is required when the collector is enabled.",
                ));
            }
        }
        if self.poll_interval_secs == 0 {
            issues.push(error(
                "poll_interval_secs",
                "Poll interval must be at least 1 second.",
            ));
        }
        if self.event_type_filter.is_empty() {
            issues.push(warning(
                "event_type_filter",
                "No event-type filter is configured, so every Okta system log event will be queried.",
            ));
        }
        SetupValidation::new(!self.enabled, issues)
    }

    pub fn to_runtime(
        &self,
        resolver: &crate::secrets::SecretsResolver,
    ) -> Result<crate::collector_identity::OktaConfig, String> {
        Ok(crate::collector_identity::OktaConfig {
            domain: resolver.resolve(&self.domain)?,
            api_token: resolver.resolve(&self.api_token)?,
            poll_interval_secs: self.poll_interval_secs,
            event_type_filter: self.event_type_filter.clone(),
            enabled: self.enabled,
        })
    }

    pub fn view(&self) -> OktaCollectorSetupView {
        OktaCollectorSetupView {
            domain: self.domain.clone(),
            poll_interval_secs: self.poll_interval_secs,
            event_type_filter: self.event_type_filter.clone(),
            enabled: self.enabled,
            has_api_token: has_text(&self.api_token),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraCollectorSetup {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub poll_interval_secs: u64,
    pub enabled: bool,
}

impl Default for EntraCollectorSetup {
    fn default() -> Self {
        let defaults = crate::collector_identity::EntraConfig::default();
        Self {
            tenant_id: defaults.tenant_id,
            client_id: defaults.client_id,
            client_secret: defaults.client_secret,
            poll_interval_secs: defaults.poll_interval_secs,
            enabled: defaults.enabled,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntraCollectorSetupPatch {
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraCollectorSetupView {
    pub tenant_id: String,
    pub client_id: String,
    pub poll_interval_secs: u64,
    pub enabled: bool,
    pub has_client_secret: bool,
}

impl EntraCollectorSetup {
    pub fn apply_patch(&mut self, patch: EntraCollectorSetupPatch) {
        if let Some(tenant_id) = patch.tenant_id {
            self.tenant_id = tenant_id;
        }
        if let Some(client_id) = patch.client_id {
            self.client_id = client_id;
        }
        if let Some(client_secret) = patch.client_secret
            && has_text(&client_secret)
        {
            self.client_secret = client_secret;
        }
        if let Some(poll_interval_secs) = patch.poll_interval_secs {
            self.poll_interval_secs = poll_interval_secs;
        }
        if let Some(enabled) = patch.enabled {
            self.enabled = enabled;
        }
    }

    pub fn validate(&self) -> SetupValidation {
        let mut issues = Vec::new();
        if self.enabled {
            if !has_text(&self.tenant_id) {
                issues.push(error("tenant_id", "Tenant ID is required when the collector is enabled."));
            }
            if !has_text(&self.client_id) {
                issues.push(error("client_id", "Client ID is required when the collector is enabled."));
            }
            if !has_text(&self.client_secret) {
                issues.push(error(
                    "client_secret",
                    "Client secret or secret reference is required when the collector is enabled.",
                ));
            }
        }
        if self.poll_interval_secs == 0 {
            issues.push(error(
                "poll_interval_secs",
                "Poll interval must be at least 1 second.",
            ));
        }
        SetupValidation::new(!self.enabled, issues)
    }

    pub fn to_runtime(
        &self,
        resolver: &crate::secrets::SecretsResolver,
    ) -> Result<crate::collector_identity::EntraConfig, String> {
        Ok(crate::collector_identity::EntraConfig {
            tenant_id: resolver.resolve(&self.tenant_id)?,
            client_id: resolver.resolve(&self.client_id)?,
            client_secret: resolver.resolve(&self.client_secret)?,
            poll_interval_secs: self.poll_interval_secs,
            enabled: self.enabled,
        })
    }

    pub fn view(&self) -> EntraCollectorSetupView {
        EntraCollectorSetupView {
            tenant_id: self.tenant_id.clone(),
            client_id: self.client_id.clone(),
            poll_interval_secs: self.poll_interval_secs,
            enabled: self.enabled,
            has_client_secret: has_text(&self.client_secret),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpCollectorSetup {
    pub project_id: String,
    pub service_account_email: String,
    pub key_file_path: Option<String>,
    pub private_key_pem: Option<String>,
    pub poll_interval_secs: u64,
    pub log_filter: String,
    pub page_size: u32,
    pub enabled: bool,
}

impl Default for GcpCollectorSetup {
    fn default() -> Self {
        let defaults = crate::collector_gcp::GcpCollectorConfig::default();
        Self {
            project_id: defaults.project_id,
            service_account_email: defaults.service_account_email,
            key_file_path: defaults.key_file_path,
            private_key_pem: defaults.private_key_pem,
            poll_interval_secs: defaults.poll_interval_secs,
            log_filter: defaults.log_filter,
            page_size: defaults.page_size,
            enabled: defaults.enabled,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GcpCollectorSetupPatch {
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub service_account_email: Option<String>,
    #[serde(default)]
    pub key_file_path: Option<String>,
    #[serde(default)]
    pub private_key_pem: Option<String>,
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
    #[serde(default)]
    pub log_filter: Option<String>,
    #[serde(default)]
    pub page_size: Option<u32>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpCollectorSetupView {
    pub project_id: String,
    pub service_account_email: String,
    pub key_file_path: Option<String>,
    pub poll_interval_secs: u64,
    pub log_filter: String,
    pub page_size: u32,
    pub enabled: bool,
    pub has_private_key_pem: bool,
}

impl GcpCollectorSetup {
    pub fn apply_patch(&mut self, patch: GcpCollectorSetupPatch) {
        if let Some(project_id) = patch.project_id {
            self.project_id = project_id;
        }
        if let Some(service_account_email) = patch.service_account_email {
            self.service_account_email = service_account_email;
        }
        if let Some(key_file_path) = patch.key_file_path {
            self.key_file_path = normalize_optional_string(key_file_path);
        }
        if let Some(private_key_pem) = patch.private_key_pem
            && has_text(&private_key_pem)
        {
            self.private_key_pem = Some(private_key_pem);
        }
        if let Some(poll_interval_secs) = patch.poll_interval_secs {
            self.poll_interval_secs = poll_interval_secs;
        }
        if let Some(log_filter) = patch.log_filter {
            self.log_filter = log_filter;
        }
        if let Some(page_size) = patch.page_size {
            self.page_size = page_size;
        }
        if let Some(enabled) = patch.enabled {
            self.enabled = enabled;
        }
    }

    pub fn validate(&self) -> SetupValidation {
        let mut issues = Vec::new();
        if self.enabled {
            if !has_text(&self.project_id) {
                issues.push(error("project_id", "Project ID is required when the collector is enabled."));
            }
            if !has_text(&self.service_account_email) {
                issues.push(error(
                    "service_account_email",
                    "Service-account email is required when the collector is enabled.",
                ));
            }
            if self.key_file_path.as_ref().is_none_or(|value| !has_text(value))
                && self.private_key_pem.as_ref().is_none_or(|value| !has_text(value))
            {
                issues.push(error(
                    "credentials",
                    "Provide either a key-file path or a private-key PEM/reference when the collector is enabled.",
                ));
            }
        }
        if self.poll_interval_secs == 0 {
            issues.push(error(
                "poll_interval_secs",
                "Poll interval must be at least 1 second.",
            ));
        }
        if self.page_size == 0 {
            issues.push(error("page_size", "Page size must be at least 1."));
        }
        if !has_text(&self.log_filter) {
            issues.push(warning(
                "log_filter",
                "No Cloud Logging filter is configured, so validation will query a broad event set.",
            ));
        }
        SetupValidation::new(!self.enabled, issues)
    }

    pub fn to_runtime(
        &self,
        resolver: &crate::secrets::SecretsResolver,
    ) -> Result<crate::collector_gcp::GcpCollectorConfig, String> {
        Ok(crate::collector_gcp::GcpCollectorConfig {
            project_id: resolver.resolve(&self.project_id)?,
            service_account_email: resolver.resolve(&self.service_account_email)?,
            key_file_path: self.key_file_path.clone(),
            private_key_pem: self
                .private_key_pem
                .as_ref()
                .map(|value| resolver.resolve(value))
                .transpose()?,
            poll_interval_secs: self.poll_interval_secs,
            log_filter: self.log_filter.clone(),
            page_size: self.page_size,
            enabled: self.enabled,
        })
    }

    pub fn view(&self) -> GcpCollectorSetupView {
        GcpCollectorSetupView {
            project_id: self.project_id.clone(),
            service_account_email: self.service_account_email.clone(),
            key_file_path: self.key_file_path.clone(),
            poll_interval_secs: self.poll_interval_secs,
            log_filter: self.log_filter.clone(),
            page_size: self.page_size,
            enabled: self.enabled,
            has_private_key_pem: self.private_key_pem.as_ref().is_some_and(|value| has_text(value)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSetup {
    pub address: String,
    pub token: String,
    pub mount: String,
    pub namespace: Option<String>,
    pub enabled: bool,
    pub cache_ttl_secs: u64,
}

impl Default for VaultSetup {
    fn default() -> Self {
        let defaults = crate::secrets::VaultConfig::default();
        Self {
            address: defaults.address,
            token: defaults.token,
            mount: defaults.mount,
            namespace: defaults.namespace,
            enabled: defaults.enabled,
            cache_ttl_secs: defaults.cache_ttl_secs,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultSetupPatch {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub mount: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub cache_ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSetupView {
    pub address: String,
    pub mount: String,
    pub namespace: Option<String>,
    pub enabled: bool,
    pub cache_ttl_secs: u64,
    pub has_token: bool,
}

impl VaultSetup {
    pub fn apply_patch(&mut self, patch: VaultSetupPatch) {
        if let Some(address) = patch.address {
            self.address = address;
        }
        if let Some(token) = patch.token
            && has_text(&token)
        {
            self.token = token;
        }
        if let Some(mount) = patch.mount {
            self.mount = mount;
        }
        if let Some(namespace) = patch.namespace {
            self.namespace = normalize_optional_string(namespace);
        }
        if let Some(enabled) = patch.enabled {
            self.enabled = enabled;
        }
        if let Some(cache_ttl_secs) = patch.cache_ttl_secs {
            self.cache_ttl_secs = cache_ttl_secs;
        }
    }

    pub fn view(&self) -> VaultSetupView {
        VaultSetupView {
            address: self.address.clone(),
            mount: self.mount.clone(),
            namespace: self.namespace.clone(),
            enabled: self.enabled,
            cache_ttl_secs: self.cache_ttl_secs,
            has_token: has_text(&self.token),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretsManagerSetup {
    pub vault: VaultSetup,
    pub env_prefix: Option<String>,
    pub secrets_dir: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsManagerSetupPatch {
    #[serde(default)]
    pub vault: Option<VaultSetupPatch>,
    #[serde(default)]
    pub env_prefix: Option<String>,
    #[serde(default)]
    pub secrets_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsManagerSetupView {
    pub vault: VaultSetupView,
    pub env_prefix: Option<String>,
    pub secrets_dir: Option<String>,
    pub supported_sources: Vec<String>,
}

impl SecretsManagerSetup {
    pub fn apply_patch(&mut self, patch: SecretsManagerSetupPatch) {
        if let Some(vault) = patch.vault {
            self.vault.apply_patch(vault);
        }
        if let Some(env_prefix) = patch.env_prefix {
            self.env_prefix = normalize_optional_string(env_prefix);
        }
        if let Some(secrets_dir) = patch.secrets_dir {
            self.secrets_dir = normalize_optional_string(secrets_dir);
        }
    }

    pub fn validate(&self) -> SetupValidation {
        let mut issues = Vec::new();
        if self.vault.enabled {
            if !has_text(&self.vault.address) {
                issues.push(error("vault.address", "Vault address is required when Vault is enabled."));
            }
            if !has_text(&self.vault.token) {
                issues.push(error(
                    "vault.token",
                    "Vault token or secret reference is required when Vault is enabled.",
                ));
            }
            if !has_text(&self.vault.mount) {
                issues.push(error("vault.mount", "Vault mount is required when Vault is enabled."));
            }
        }
        if self.vault.cache_ttl_secs == 0 {
            issues.push(warning(
                "vault.cache_ttl_secs",
                "Zero cache TTL disables secret caching and may increase Vault traffic.",
            ));
        }
        let disabled = !self.vault.enabled
            && self.env_prefix.as_ref().is_none_or(|value| !has_text(value))
            && self.secrets_dir.as_ref().is_none_or(|value| !has_text(value));
        SetupValidation::new(disabled, issues)
    }

    pub fn to_runtime(&self) -> crate::secrets::SecretsConfig {
        crate::secrets::SecretsConfig {
            vault: crate::secrets::VaultConfig {
                address: self.vault.address.clone(),
                token: self.vault.token.clone(),
                mount: self.vault.mount.clone(),
                namespace: self.vault.namespace.clone(),
                enabled: self.vault.enabled,
                cache_ttl_secs: self.vault.cache_ttl_secs,
            },
            env_prefix: self.env_prefix.clone(),
            secrets_dir: self.secrets_dir.clone(),
        }
    }

    pub fn view(&self) -> SecretsManagerSetupView {
        SecretsManagerSetupView {
            vault: self.vault.view(),
            env_prefix: self.env_prefix.clone(),
            secrets_dir: self.secrets_dir.clone(),
            supported_sources: vec![
                "${ENV_VAR}".to_string(),
                "file:///run/secrets/name".to_string(),
                "vault://secret/path#key".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AwsCollectorSetup, AwsCollectorSetupPatch, SecretsManagerSetup, SecretsManagerSetupPatch,
        VaultSetupPatch,
    };

    #[test]
    fn aws_patch_preserves_existing_secret_when_blank() {
        let mut setup = AwsCollectorSetup::default();
        setup.secret_access_key = "secret-value".to_string();

        setup.apply_patch(AwsCollectorSetupPatch {
            secret_access_key: Some(String::new()),
            ..AwsCollectorSetupPatch::default()
        });

        assert_eq!(setup.secret_access_key, "secret-value");
    }

    #[test]
    fn secrets_patch_preserves_existing_vault_token_when_blank() {
        let mut setup = SecretsManagerSetup::default();
        setup.vault.token = "vault-token".to_string();

        setup.apply_patch(SecretsManagerSetupPatch {
            vault: Some(VaultSetupPatch {
                token: Some(String::new()),
                ..VaultSetupPatch::default()
            }),
            ..SecretsManagerSetupPatch::default()
        });

        assert_eq!(setup.vault.token, "vault-token");
    }
}