# Service Level Objective Policy

> T215 — Phase 27

## Purpose

Define measurable service-level objectives (SLOs) for the Wardex platform so
that operators can set alerting budgets and track reliability over time.

## SLO Definitions

| Indicator | Target | Window | Measurement |
|-----------|--------|--------|-------------|
| API availability | ≥ 99.9 % | 30-day rolling | `1 - (5xx responses / total requests)` |
| API latency (p99) | ≤ 50 ms | 30-day rolling | Server-side request duration |
| Detection latency | ≤ 500 ms | Per event | Time from event ingestion to alert |
| Checkpoint durability | 100 % | Continuous | Checkpoint restore succeeds |
| Agent heartbeat freshness | ≤ 60 s | Per agent | `now - last_heartbeat` |
| Spool delivery | ≥ 99.5 % | 7-day rolling | `delivered / (delivered + DLQ)` |

## Error Budget

```
Monthly error budget  =  1 - SLO target
  Availability 99.9%  →  0.1% budget  ≈  43 min / month
  Latency p99 50ms    →  1% of requests may exceed 50ms
```

When the error budget is exhausted:

1. Freeze non-critical deployments.
2. Prioritise reliability work over features.
3. Page the on-call engineer.

## Endpoint: `GET /api/slo/status`

Returns a JSON object with real-time SLO metrics:

```json
{
  "api_latency_p99_ms": 12.0,
  "error_rate_pct": 0.02,
  "availability_pct": 99.98,
  "budget_remaining_pct": 99.88,
  "uptime_seconds": 86400,
  "request_count": 142857
}
```

## Alerting Rules

| Condition | Action |
|-----------|--------|
| `availability_pct < 99.9` | Page on-call |
| `api_latency_p99_ms > 50` | Warn in Slack |
| `budget_remaining_pct < 20` | Freeze deployments |
| `budget_remaining_pct < 5` | Page on-call + freeze |

## Dashboarding

The admin console exposes SLO metrics on the **Platform** section.  For
external dashboards, poll `/api/slo/status` every 60 s and feed to Prometheus
via the JSON exporter or a custom scraper.

## Review Cadence

- **Weekly**: Review error budget burn rate.
- **Monthly**: Publish SLO report to stakeholders.
- **Quarterly**: Re-evaluate targets based on operational data.
