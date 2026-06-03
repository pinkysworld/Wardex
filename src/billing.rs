// ── Billing & Subscription Management ────────────────────────────────────────
//
// Handles Stripe-style subscription lifecycle: plans, invoices, payment events.
// Integrates with metering for usage-based billing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── Plans ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BillingPlan {
    Community,
    Professional,
    Enterprise,
    Custom { name: String, monthly_cents: u64 },
}

impl BillingPlan {
    pub fn monthly_price_cents(&self) -> u64 {
        match self {
            BillingPlan::Community => 0,
            BillingPlan::Professional => 9900, // $99/mo
            BillingPlan::Enterprise => 49900,  // $499/mo
            BillingPlan::Custom { monthly_cents, .. } => *monthly_cents,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            BillingPlan::Community => "Community",
            BillingPlan::Professional => "Professional",
            BillingPlan::Enterprise => "Enterprise",
            BillingPlan::Custom { name, .. } => name,
        }
    }
}

// ── Subscription ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub tenant_id: String,
    pub plan: BillingPlan,
    pub status: SubscriptionStatus,
    pub created: DateTime<Utc>,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SubscriptionStatus {
    Active,
    Trialing,
    PastDue,
    Canceled,
    Unpaid,
    Paused,
}

// ── Invoice ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub tenant_id: String,
    pub amount_cents: u64,
    pub currency: String,
    pub status: InvoiceStatus,
    pub created: DateTime<Utc>,
    pub due_date: DateTime<Utc>,
    pub paid_at: Option<DateTime<Utc>>,
    pub line_items: Vec<LineItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InvoiceStatus {
    Draft,
    Open,
    Paid,
    Void,
    Uncollectible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineItem {
    pub description: String,
    pub quantity: u64,
    pub unit_price_cents: u64,
    pub total_cents: u64,
}

// ── Webhook Event ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub id: String,
    pub event_type: String,
    pub created: DateTime<Utc>,
    pub payload: serde_json::Value,
    pub processed: bool,
}

// ── Billing Manager ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BillingManager {
    subscriptions: Arc<Mutex<HashMap<String, Subscription>>>,
    invoices: Arc<Mutex<Vec<Invoice>>>,
    webhook_events: Arc<Mutex<Vec<WebhookEvent>>>,
    next_id: Arc<Mutex<u64>>,
}

impl BillingManager {
    pub fn new() -> Self {
        Self {
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            invoices: Arc::new(Mutex::new(Vec::new())),
            webhook_events: Arc::new(Mutex::new(Vec::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    fn gen_id(&self, prefix: &str) -> String {
        let mut id = self
            .next_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let val = *id;
        *id += 1;
        format!("{prefix}_{val}")
    }

    pub fn create_subscription(&self, tenant_id: &str, plan: BillingPlan) -> Subscription {
        let now = Utc::now();
        let sub = Subscription {
            id: self.gen_id("sub"),
            tenant_id: tenant_id.to_string(),
            plan,
            status: SubscriptionStatus::Active,
            created: now,
            current_period_start: now,
            current_period_end: now + chrono::Duration::days(30),
            cancel_at_period_end: false,
            stripe_customer_id: None,
            stripe_subscription_id: None,
        };
        self.subscriptions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(tenant_id.to_string(), sub.clone());
        sub
    }

    pub fn get_subscription(&self, tenant_id: &str) -> Option<Subscription> {
        self.subscriptions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(tenant_id)
            .cloned()
    }

    pub fn cancel_subscription(&self, tenant_id: &str, immediate: bool) -> Result<(), String> {
        let mut subs = self
            .subscriptions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sub = subs.get_mut(tenant_id).ok_or("Subscription not found")?;
        if immediate {
            sub.status = SubscriptionStatus::Canceled;
        } else {
            sub.cancel_at_period_end = true;
        }
        Ok(())
    }

    pub fn change_plan(&self, tenant_id: &str, new_plan: BillingPlan) -> Result<(), String> {
        let mut subs = self
            .subscriptions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sub = subs.get_mut(tenant_id).ok_or("Subscription not found")?;
        if sub.status == SubscriptionStatus::Canceled {
            return Err("Cannot change plan on canceled subscription".into());
        }
        sub.plan = new_plan;
        Ok(())
    }

    pub fn generate_invoice(&self, tenant_id: &str) -> Result<Invoice, String> {
        let subs = self
            .subscriptions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sub = subs.get(tenant_id).ok_or("Subscription not found")?;
        let now = Utc::now();
        let amount = sub.plan.monthly_price_cents();
        let invoice = Invoice {
            id: self.gen_id("inv"),
            tenant_id: tenant_id.to_string(),
            amount_cents: amount,
            currency: "usd".to_string(),
            status: InvoiceStatus::Open,
            created: now,
            due_date: now + chrono::Duration::days(30),
            paid_at: None,
            line_items: vec![LineItem {
                description: format!("{} plan – monthly", sub.plan.name()),
                quantity: 1,
                unit_price_cents: amount,
                total_cents: amount,
            }],
        };
        drop(subs);
        self.invoices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(invoice.clone());
        Ok(invoice)
    }

    pub fn mark_invoice_paid(&self, invoice_id: &str) -> Result<(), String> {
        let mut invoices = self
            .invoices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let inv = invoices
            .iter_mut()
            .find(|i| i.id == invoice_id)
            .ok_or("Invoice not found")?;
        inv.status = InvoiceStatus::Paid;
        inv.paid_at = Some(Utc::now());
        Ok(())
    }

    pub fn list_invoices(&self, tenant_id: &str) -> Vec<Invoice> {
        self.invoices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|i| i.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub fn process_webhook(
        &self,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<(), String> {
        let event = WebhookEvent {
            id: self.gen_id("evt"),
            event_type: event_type.to_string(),
            created: Utc::now(),
            payload,
            processed: true,
        };
        self.webhook_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event);
        Ok(())
    }

    pub fn revenue_summary(&self) -> HashMap<String, u64> {
        let invoices = self
            .invoices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut summary = HashMap::new();
        let paid_total: u64 = invoices
            .iter()
            .filter(|i| i.status == InvoiceStatus::Paid)
            .map(|i| i.amount_cents)
            .sum();
        let pending_total: u64 = invoices
            .iter()
            .filter(|i| i.status == InvoiceStatus::Open)
            .map(|i| i.amount_cents)
            .sum();
        summary.insert("paid_cents".into(), paid_total);
        summary.insert("pending_cents".into(), pending_total);
        summary.insert("total_invoices".into(), invoices.len() as u64);
        summary
    }
}

impl Default for BillingManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_subscription() {
        let mgr = BillingManager::new();
        let sub = mgr.create_subscription("acme", BillingPlan::Professional);
        assert_eq!(sub.tenant_id, "acme");
        assert_eq!(sub.status, SubscriptionStatus::Active);
        assert_eq!(sub.plan, BillingPlan::Professional);
    }

    #[test]
    fn test_cancel_subscription() {
        let mgr = BillingManager::new();
        mgr.create_subscription("acme", BillingPlan::Professional);
        mgr.cancel_subscription("acme", false).unwrap();
        let sub = mgr.get_subscription("acme").unwrap();
        assert!(sub.cancel_at_period_end);
        assert_eq!(sub.status, SubscriptionStatus::Active);
    }

    #[test]
    fn test_immediate_cancel() {
        let mgr = BillingManager::new();
        mgr.create_subscription("acme", BillingPlan::Enterprise);
        mgr.cancel_subscription("acme", true).unwrap();
        let sub = mgr.get_subscription("acme").unwrap();
        assert_eq!(sub.status, SubscriptionStatus::Canceled);
    }

    #[test]
    fn test_change_plan() {
        let mgr = BillingManager::new();
        mgr.create_subscription("acme", BillingPlan::Professional);
        mgr.change_plan("acme", BillingPlan::Enterprise).unwrap();
        let sub = mgr.get_subscription("acme").unwrap();
        assert_eq!(sub.plan, BillingPlan::Enterprise);
    }

    #[test]
    fn test_generate_and_pay_invoice() {
        let mgr = BillingManager::new();
        mgr.create_subscription("acme", BillingPlan::Professional);
        let inv = mgr.generate_invoice("acme").unwrap();
        assert_eq!(inv.amount_cents, 9900);
        assert_eq!(inv.status, InvoiceStatus::Open);

        mgr.mark_invoice_paid(&inv.id).unwrap();
        let invoices = mgr.list_invoices("acme");
        assert_eq!(invoices[0].status, InvoiceStatus::Paid);
    }

    #[test]
    fn test_community_free() {
        let mgr = BillingManager::new();
        mgr.create_subscription("free_user", BillingPlan::Community);
        let inv = mgr.generate_invoice("free_user").unwrap();
        assert_eq!(inv.amount_cents, 0);
    }

    #[test]
    fn test_revenue_summary() {
        let mgr = BillingManager::new();
        mgr.create_subscription("a", BillingPlan::Professional);
        mgr.create_subscription("b", BillingPlan::Enterprise);
        let inv_a = mgr.generate_invoice("a").unwrap();
        let _inv_b = mgr.generate_invoice("b").unwrap();
        mgr.mark_invoice_paid(&inv_a.id).unwrap();
        let summary = mgr.revenue_summary();
        assert_eq!(*summary.get("paid_cents").unwrap(), 9900);
        assert_eq!(*summary.get("pending_cents").unwrap(), 49900);
    }

    #[test]
    fn test_webhook_processing() {
        let mgr = BillingManager::new();
        mgr.process_webhook("invoice.paid", serde_json::json!({"id": "inv_123"}))
            .unwrap();
    }

    #[test]
    fn test_plan_pricing() {
        assert_eq!(BillingPlan::Community.monthly_price_cents(), 0);
        assert_eq!(BillingPlan::Professional.monthly_price_cents(), 9900);
        assert_eq!(BillingPlan::Enterprise.monthly_price_cents(), 49900);
        let custom = BillingPlan::Custom {
            name: "Startup".into(),
            monthly_cents: 2900,
        };
        assert_eq!(custom.monthly_price_cents(), 2900);
    }
}
