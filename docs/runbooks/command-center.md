# Command Center Runbook

The Command Center is the default analyst workspace for coordinating incident triage, remediation approval, collector onboarding, rule tuning, release readiness, and compliance evidence export.

It also acts as the fast executive surface for shift ownership and detection-review pressure: overdue rule reviews, replay blockers, noisy owners, and the most urgent pivots into Threat Detection should be visible here before an analyst opens a deeper workspace.

## When to use it

Use `/command` at shift start, during incident response handoff, before approving remediation, and before exporting evidence for leadership or auditors.

## Shareable drawer URLs

Each Command Center drawer is reflected in the URL via the `?drawer=<lane>` query parameter, where `<lane>` is one of `remediation`, `connectors`, `rules`, `release`, or `evidence`. Operators can bookmark or paste the URL into chat to bring another analyst directly into the same drawer state. Reload, browser back/forward, and shared links all preserve the open lane. Item-specific selections (a particular connector or rule) live in the local component and need to be re-clicked after a hard reload.

## Per-lane refreshes

When a drawer needs a focused refresh — for example, after running a remediation approval — the console can call `GET /api/command/lanes/{lane}` instead of the full `GET /api/command/summary`. Supported lanes: `incidents`, `remediation`, `connectors`, `rule_tuning`, `release`, `evidence`. The endpoint returns the lane payload, the headline metric value, and the parent generation timestamp.

## Shift-start check

1. Open **Command Center** from the primary analyst destination or go to `/command`.
2. Review the summary cards for open incidents, pending approvals, connector gaps, noisy rules, release candidates, and compliance packs.
3. Select **Refresh Center** when taking over from another analyst so all lane counts are reloaded from the live APIs.
4. Treat failed supporting requests as a partial-data warning. Continue with visible lanes and verify missing detail from the owning workspace.

## Connector validation

1. Open **Connector gaps** or **Validate connectors**.
2. Select the connector lane.
3. For planned lanes, save a setup draft first when the lane has no stored config.
4. Run validation and inspect sample events, validation issues, reliability checkpoint, and downstream pivots.
5. Open Settings for durable edits when validation shows missing secrets, scope, tenant, or endpoint fields.

Planned connector lanes currently covered by Command Center are GitHub audit logs, CrowdStrike Falcon, and generic syslog.

## Remediation approval

1. Open **Pending approvals** or **Review changes**.
2. Check the selected change review, blast-radius context, approval count, and rollback proof state.
3. Add a concise approval comment.
4. Approve only when rollback proof is ready or the change is explicitly low-risk and recoverable.
5. Deny with a comment when evidence is missing, target scope is unclear, or the rollback path is incomplete.

## Rule tuning and promotion

1. Open **Noisy rules**, **Run replay**, or **Open checklist**.
2. Review replay status, suppression count, and promotion readiness.
3. Run replay before promoting rules or converting recurring false positives into suppressions.
4. Open the Detection workspace for full rule editing, lifecycle changes, and pack ownership changes.

## Detection review pressure

1. In **Detection Quality Dashboard**, check overdue reviews, due-this-week items, replay blockers, and owners currently carrying noisy detections.
2. Use the compact review rows to jump directly into the exact rule promotion context in `/detection`.
3. Treat overdue or blocker-heavy rules as shift-handoff items, not background hygiene.
4. Use the SOC Workbench and Threat Detection review calendar together when deciding whether a rule issue is ownership debt, replay debt, or a broader case/collector problem.

## Release readiness

1. Open **Release candidates** or **Check readiness**.
2. Confirm current version, latest release, SBOM component count, and release metadata.
3. Use Infrastructure rollouts for staged deployment, rollback, and agent-target decisions.

## Evidence packs

1. Open **Compliance packs** or **Create evidence pack**.
2. Select a report template when one is available.
3. Create an evidence pack to persist a report run with lane-health context.
4. Use Reports for export format, scheduling, and delivery controls.

## Escalation

Escalate to the owning workspace when a drawer shows partial evidence, validation cannot resolve stored secrets, or a remediation approval needs more context than the drawer provides. Use SOC for incident storylines, Settings for connector secrets, Threat Detection for rule lifecycle, Infrastructure for rollout/remediation execution, and Reports for final evidence delivery.
