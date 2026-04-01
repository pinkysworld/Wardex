Phase 12: Differentiated features and GA readiness.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Implement differentiated capabilities only after the core is stable:
1. Counterfactual Detection Simulator
2. Causal Attack Storyline
3. Adaptive Decoy Morphing (scaffold if full productization is too large)
4. Privacy-preserving fleet learning interfaces
5. Response Sandboxing
6. Drift Sentinel for integration and telemetry breakage

For each feature:
- define architecture
- define minimal shippable version
- define telemetry prerequisites
- define privacy/security constraints
- define evaluation metrics
- gate behind feature flags

Deliverables:
- ADRs for each feature
- backend scaffolding and UI entry points
- evaluation harnesses
- rollout flags
- docs describing what is experimental vs GA

Acceptance criteria:
- no differentiated feature weakens the core platform
- each feature has metrics and kill switches
- experimental status is explicit where appropriate
