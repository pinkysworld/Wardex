import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  WardexClient,
  WardexError,
  AuthenticationError,
  NotFoundError,
  RateLimitError,
  ServerError,
} from "./index";

// ── Helpers ──────────────────────────────────────────────────────────────────

function mockFetch(status: number, body: unknown, ok?: boolean) {
  const contentType = typeof body === "string" ? "text/plain" : "application/json";
  return vi.fn().mockResolvedValue({
    ok: ok ?? (status >= 200 && status < 300),
    status,
    headers: {
      get: (name: string) =>
        name.toLowerCase() === "content-type" ? contentType : null,
    },
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(typeof body === "string" ? body : JSON.stringify(body)),
  });
}

// ── Error hierarchy ──────────────────────────────────────────────────────────

describe("Error classes", () => {
  it("WardexError is an Error", () => {
    const err = new WardexError("fail", 400, "bad");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(WardexError);
    expect(err.statusCode).toBe(400);
    expect(err.body).toBe("bad");
    expect(err.name).toBe("WardexError");
  });

  it("AuthenticationError extends WardexError", () => {
    const err = new AuthenticationError("unauthorized", 401, "nope");
    expect(err).toBeInstanceOf(WardexError);
    expect(err).toBeInstanceOf(AuthenticationError);
    expect(err.statusCode).toBe(401);
    expect(err.name).toBe("AuthenticationError");
  });

  it("NotFoundError extends WardexError", () => {
    const err = new NotFoundError("missing", 404);
    expect(err).toBeInstanceOf(WardexError);
    expect(err.statusCode).toBe(404);
    expect(err.name).toBe("NotFoundError");
  });

  it("RateLimitError extends WardexError", () => {
    const err = new RateLimitError("slow down", 429);
    expect(err).toBeInstanceOf(WardexError);
    expect(err.statusCode).toBe(429);
    expect(err.name).toBe("RateLimitError");
  });

  it("ServerError extends WardexError", () => {
    const err = new ServerError("boom", 500, "internal");
    expect(err).toBeInstanceOf(WardexError);
    expect(err.statusCode).toBe(500);
    expect(err.name).toBe("ServerError");
  });
});

// ── Client construction ──────────────────────────────────────────────────────

describe("WardexClient", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("strips trailing slash from baseUrl", () => {
    const client = new WardexClient({
      baseUrl: "http://localhost:8080/",
      apiKey: "tok",
    });
    // Verify by making a request and checking the URL
    const mock = mockFetch(200, { status: "ok" });
    globalThis.fetch = mock;
    client.health();
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/health",
      expect.anything()
    );
  });

  // ── Successful requests ──────────────────────────────────────────────

  it("health() returns parsed JSON", async () => {
    const body = { status: "ok", version: "0.43.0", uptime_secs: 100 };
    globalThis.fetch = mockFetch(200, body);
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.health();
    expect(result).toEqual(body);
  });

  it("healthLive() calls GET /api/healthz/live", async () => {
    const body = { status: "alive" };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.healthLive();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/healthz/live",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("healthReady() calls GET /api/healthz/ready", async () => {
    const body = { status: "ready", storage: "ok" };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.healthReady();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/healthz/ready",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("authCheck() calls GET /api/auth/check", async () => {
    const body = {
      status: "ok",
      ttl_secs: 3600,
      remaining_secs: 3570,
      token_age_secs: 30,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.authCheck();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/auth/check",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("authSession() calls GET /api/auth/session", async () => {
    const body = {
      user_id: "analyst@example.com",
      role: "analyst",
      groups: ["soc", "tier2"],
      authenticated: true,
      source: "session",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.authSession();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/auth/session",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("createAuthSession() calls POST /api/auth/session", async () => {
    const body = {
      authenticated: true,
      user_id: "analyst@example.com",
      role: "analyst",
      groups: ["soc", "tier2"],
      source: "session",
      expires_at: "2026-04-30T13:00:00Z",
      cookie: {
        http_only: true,
        same_site: "Lax",
        secure: false,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.createAuthSession();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/auth/session",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("authLogout() calls POST /api/auth/logout", async () => {
    const body = {
      logged_out: true,
      session_revoked: true,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.authLogout();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/auth/logout",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("sessionInfo() calls GET /api/session/info", async () => {
    const body = {
      uptime_secs: 7200,
      token_age_secs: 300,
      token_ttl_secs: 3600,
      token_expired: false,
      mtls_required: true,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.sessionInfo();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/session/info",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("supportDiagnostics() calls GET /api/support/diagnostics", async () => {
    const body = {
      bundle: {
        generated_at: "2026-04-30T12:00:00Z",
        auth: {
          session: {
            token_ttl_secs: 3600,
            token_age_secs: 300,
          },
          rbac_users: 4,
          idp_providers: [{ id: "okta-main", enabled: true }],
          scim: { enabled: true, status: "ready", mapping_count: 6 },
        },
        content: {
          builtin_rules: 25,
          native_rules: 8,
          packs: [{ id: "baseline", enabled: true }],
          hunts: [{ id: "hunt-1", name: "Suspicious logins" }],
          suppressions: [{ id: "sup-1", active: true }],
        },
        operations: {
          metrics: { hunt_runs_total: 12 },
          request_count: 144,
          error_count: 3,
          queue_depth: 7,
          event_count: 400,
          incident_count: 5,
          cases_count: { total: 9, open: 4 },
          event_analytics: {
            correlation_rate: 0.42,
            severity_counts: { Critical: 2, High: 5 },
            triage_counts: { queued: 4, escalated: 1 },
            hot_agents: [{ agent_id: "agent-1", count: 8 }],
          },
        },
        dependencies: {
          storage_path: "var/events.db",
          event_persistence: true,
          siem: {
            enabled: true,
            siem_type: "generic",
            endpoint: "https://siem.example.test",
            pending_events: 4,
            total_pushed: 12,
            total_pulled: 3,
            last_error: null,
            pull_enabled: true,
          },
          connectors: [{ id: "connector-1", status: "ready" }],
          updates: [{ agent_id: "agent-1", status: "assigned" }],
        },
        change_control: [{ category: "hunt", summary: "Updated scheduled hunt cadence" }],
      },
      digest: "support-digest-123456",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.supportDiagnostics();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/support/diagnostics",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("supportParity() calls GET /api/support/parity", async () => {
    const body = {
      generated_at: "2026-04-30T12:00:00Z",
      runtime: {
        version: "0.55.1-local",
        release_version: "0.55.1",
        docs_version: "0.55.1-local",
      },
      rest: {
        openapi_version: "0.55.1-local",
        openapi_path_count: 180,
        endpoint_catalog_count: 192,
        authenticated_endpoints: 168,
        public_endpoints: 24,
      },
      graphql: {
        documented: true,
        query_type: "QueryRoot",
        types: 42,
        root_fields: ["alerts", "status"],
        supports_introspection: true,
      },
      sdk: {
        python: {
          package: "wardex",
          version: "0.55.0",
          aligned: false,
        },
        typescript: {
          package: "@wardex/sdk",
          version: "0.55.1",
          aligned: true,
        },
      },
      issues: ["Python SDK version 0.55.0 differs from runtime release 0.55.1."],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.supportParity();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/support/parity",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("readinessEvidence() calls GET /api/support/readiness-evidence", async () => {
    const body = {
      digest: "readiness-digest-123456",
      evidence: {
        generated_at: "2026-04-30T12:00:00Z",
        status: "review",
        version: {
          package: "wardex",
          runtime: "0.55.1-local",
          edition: "private-cloud",
        },
        config_posture: {
          config_path: "/etc/wardex/config.toml",
          monitoring_enabled: true,
          siem_enabled: true,
          taxii_enabled: false,
          clickhouse_enabled: false,
          rate_limit_read_per_minute: 120,
          rate_limit_write_per_minute: 60,
        },
        auth: {
          token_ttl_secs: 3600,
          token_age_secs: 300,
          rbac_users: 4,
          idp_provider_count: 2,
          session_store: "enabled",
        },
        tls: {
          enabled: true,
          mtls_required_for_agents: true,
          agent_ca_cert_path: "/etc/wardex/agent-ca.pem",
        },
        storage: {
          backend: "sqlite",
          stats: null,
          event_persistence: true,
          event_store_path: "var/events.db",
        },
        retention: {
          audit_max_records: 5000,
          alert_max_records: 10000,
          event_max_records: 100000,
          audit_max_age_secs: 2592000,
          remote_syslog_endpoint: null,
        },
        backup: {
          enabled: true,
          path: "var/backups",
          retention_count: 7,
          observed_backups: 1,
        },
        audit_chain: {
          status: "verified",
          storage_chain_length: 12,
        },
        collectors: {
          enabled: 2,
          configured: 10,
          collectors: [
            {
              provider: "aws_cloudtrail",
              label: "AWS CloudTrail",
              lane: "cloud",
              enabled: true,
              last_success_at: "2026-04-30T11:55:00Z",
              last_error_at: null,
              error_category: null,
              events_ingested: 128,
              lag_seconds: 30,
              checkpoint_id: "chk-1",
              retry_count: 0,
              backoff_seconds: 0,
              lifecycle_analytics: { runs_total: 5 },
              ingestion_evidence: {
                pivots: [
                  {
                    surface: "SOC Workbench",
                    href: "/soc?collector=aws_cloudtrail&lane=cloud",
                    label: "Open SOC collector context",
                  },
                ],
                recent_runs: [{ started_at: "2026-04-30T11:50:00Z", status: "success" }],
              },
            },
          ],
        },
        response_history: {
          requests: 4,
          closed_or_reopenable: 3,
          audit_entries: 6,
        },
        evidence: {
          stored_reports: 2,
          reports_with_artifact_metadata: 1,
          report_runs: 5,
        },
        contracts: {
          status: "review",
          parity_issue_count: 1,
          parity: {
            generated_at: "2026-04-30T12:00:00Z",
            runtime: {
              version: "0.55.1-local",
              release_version: "0.55.1",
              docs_version: "0.55.1-local",
            },
            rest: {
              openapi_version: "0.55.1-local",
              openapi_path_count: 180,
              endpoint_catalog_count: 192,
              authenticated_endpoints: 168,
              public_endpoints: 24,
            },
            graphql: {
              documented: true,
              query_type: "QueryRoot",
              types: 42,
              root_fields: ["alerts", "status"],
              supports_introspection: true,
            },
            sdk: {
              python: {
                package: "wardex",
                version: "0.55.0",
                aligned: false,
              },
              typescript: {
                package: "@wardex/sdk",
                version: "0.55.1",
                aligned: true,
              },
            },
            issues: ["Python SDK version 0.55.0 differs from runtime release 0.55.1."],
          },
        },
        experimental_surfaces: [
          {
            name: "LLM analyst assistant",
            status: "experimental",
            gate: "retrieval fallback, citations, provider status",
          },
        ],
        known_limitations: ["No cloud, identity, or SaaS collectors are enabled yet."],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.readinessEvidence();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/support/readiness-evidence",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("firstRunProof() calls POST /api/support/first-run-proof", async () => {
    const body = {
      digest: "first-run-proof-digest",
      proof: {
        status: "completed",
        estimated_minutes: 10,
        generated_at: "2026-04-30T12:00:00Z",
        actor: "admin",
        case_id: 42,
        report_id: 7,
        report_run_id: "rr-1",
        response_request_id: "resp-1",
        response_status: "DryRunCompleted",
        telemetry: {
          samples: 12,
          alerts: 4,
          critical: 1,
        },
        artifact_metadata: {
          report: { artifact_hash: "abc123" },
          support_run: { artifact_hash: "def456" },
        },
        demo_surfaces: {
          identity: {
            provider: "okta_identity",
            events: 11,
            pivot: "/soc?collector=okta_identity",
          },
          attack_graph: {
            campaign: "first-run-proof-lateral-path",
            nodes: 4,
            pivot: "/attack-graph?campaign=first-run-proof",
          },
        },
        response_history: {
          id: "resp-1",
          requested_at: "2026-04-30T11:55:00Z",
          requested_by: "admin",
          action: "isolate",
          reason: "First-run operator proof dry-run containment",
          severity: "high",
          tier: "auto",
          status: "dry_run_completed",
          dry_run: true,
          target: {
            hostname: "first-run-demo-host",
            agent_uid: null,
            asset_tags: ["demo", "first-run-proof"],
          },
          approvals: [],
          required_approvals: 0,
          blast_radius: null,
          context: null,
          execution_summary: null,
        },
        steps: [
          { name: "ingest_sample", status: "completed" },
          { name: "package_evidence", status: "completed" },
        ],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.firstRunProof();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/support/first-run-proof",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("productionDemoLab() calls POST /api/demo/lab", async () => {
    const body = {
      digest: "demo-lab-digest",
      proof: {
        status: "completed",
        estimated_minutes: 10,
        generated_at: "2026-04-30T12:05:00Z",
        actor: "admin",
        case_id: 43,
        report_id: 8,
        report_run_id: "rr-2",
        response_request_id: "resp-2",
        response_status: "DryRunCompleted",
        telemetry: {
          samples: 12,
          alerts: 4,
          critical: 1,
        },
        artifact_metadata: {
          report: { artifact_hash: "abc123" },
          support_run: { artifact_hash: "ghi789" },
        },
        demo_surfaces: {
          cloud: {
            provider: "aws_cloudtrail",
            events: 18,
            pivot: "/settings?tab=integrations",
          },
        },
        response_history: null,
        steps: [{ name: "generate_report", status: "completed" }],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.productionDemoLab();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/demo/lab",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("docsIndex() calls GET /api/docs/index with query params", async () => {
    const body = {
      version: "0.55.1-local",
      generated_at: "2026-04-30T12:10:00Z",
      query: "sdk guide",
      section: "api",
      total: 1,
      items: [
        {
          path: "SDK_GUIDE.md",
          title: "SDK Guide",
          section: "api",
          kind: "guide",
          tags: ["api", "guides"],
          summary: "Use generated clients.",
          headings: ["SDK Guide", "TypeScript SDK"],
          score: 10,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.docsIndex({ q: "sdk guide", section: "api", limit: 5 });
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/docs/index?q=sdk+guide&section=api&limit=5",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("docsContent() calls GET /api/docs/content with encoded path", async () => {
    const body = {
      version: "0.55.1-local",
      generated_at: "2026-04-30T12:10:00Z",
      path: "SDK_GUIDE.md",
      title: "SDK Guide",
      section: "api",
      kind: "guide",
      tags: ["api", "guides"],
      summary: "Use generated clients.",
      headings: ["SDK Guide", "TypeScript SDK"],
      content: '# SDK Guide\nUse generated clients.\n\n## TypeScript SDK\n```ts\nimport { WardexClient } from "@wardex/sdk";\n```',
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.docsContent("SDK_GUIDE.md");
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/docs/content?path=SDK_GUIDE.md",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("systemDeps() calls GET /api/system/health/dependencies", async () => {
    const body = {
      storage: {
        backend: "json_file",
        durable: true,
        path: "var/events.json",
        event_count: 400,
      },
      ha_mode: {
        mode: "standalone",
        status: "ready_for_active_passive",
        leader: true,
      },
      identity: {
        providers_enabled: 2,
        scim_enabled: true,
        status: "configured",
      },
      connectors: {
        enabled: 3,
        unhealthy: 1,
        items: [{ id: "connector-1", status: "ready" }],
      },
      deployments: {
        pending: 2,
        stale_agents: 1,
        compliant_agents: 11,
        health_gate: "warning",
      },
      telemetry: {
        hunt_runs_total: 12,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.systemDeps();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/system/health/dependencies",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("siemStatus() calls GET /api/siem/status", async () => {
    const body = {
      enabled: true,
      siem_type: "splunk",
      endpoint: "https://siem.example.test/hec",
      pending_events: 1,
      total_pushed: 12,
      total_pulled: 3,
      last_error: null,
      pull_enabled: true,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.siemStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/siem/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("siemConfig() calls GET /api/siem/config", async () => {
    const body = {
      config: {
        enabled: true,
        siem_type: "splunk",
        endpoint: "https://siem.example.test/hec",
        has_auth_token: true,
        index: "wardex",
        source_type: "wardex:xdr",
        poll_interval_secs: 60,
        pull_enabled: true,
        pull_query: "search index=wardex",
        batch_size: 50,
        verify_tls: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.siemConfig();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/siem/config",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveSiemConfig() posts the SIEM config payload", async () => {
    const request = {
      enabled: true,
      siem_type: "splunk",
      endpoint: "https://siem.example.test/hec",
      auth_token: "secret-token",
      index: "wardex",
      source_type: "wardex:xdr",
      poll_interval_secs: 60,
      pull_enabled: true,
      pull_query: "search index=wardex",
      batch_size: 50,
      verify_tls: true,
    };
    const body = {
      status: "saved",
      config: {
        enabled: true,
        siem_type: "splunk",
        endpoint: "https://siem.example.test/hec",
        has_auth_token: true,
        index: "wardex",
        source_type: "wardex:xdr",
        poll_interval_secs: 60,
        pull_enabled: true,
        pull_query: "search index=wardex",
        batch_size: 50,
        verify_tls: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveSiemConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/siem/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateSiemConfig() posts the SIEM config payload", async () => {
    const request = {
      enabled: true,
      siem_type: "splunk",
      endpoint: "https://siem.example.test/hec",
      auth_token: "secret-token",
      index: "wardex",
      source_type: "wardex:xdr",
      poll_interval_secs: 60,
      pull_enabled: true,
      pull_query: "search index=wardex",
      batch_size: 50,
      verify_tls: true,
    };
    const body = {
      success: true,
      config: {
        enabled: true,
        siem_type: "splunk",
        endpoint: "https://siem.example.test/hec",
        has_auth_token: true,
        index: "wardex",
        source_type: "wardex:xdr",
        poll_interval_secs: 60,
        pull_enabled: true,
        pull_query: "search index=wardex",
        batch_size: 50,
        verify_tls: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateSiemConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/siem/validate",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("taxiiStatus() calls GET /api/taxii/status", async () => {
    const body = {
      enabled: true,
      url: "https://taxii.example.test/collections/main/objects",
      pull_count: 4,
      last_error: null,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.taxiiStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/taxii/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("taxiiConfig() calls GET /api/taxii/config", async () => {
    const body = {
      url: "https://taxii.example.test/collections/main/objects",
      auth_token: "secret-token",
      added_after: "2026-04-29T00:00:00Z",
      poll_interval_secs: 300,
      enabled: true,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.taxiiConfig();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/taxii/config",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveTaxiiConfig() posts the TAXII config payload", async () => {
    const request = {
      url: "https://taxii.example.test/collections/main/objects",
      auth_token: "secret-token",
      added_after: "2026-04-29T00:00:00Z",
      poll_interval_secs: 300,
      enabled: true,
    };
    const body = {
      status: "ok",
      message: "TAXII configuration updated",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveTaxiiConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/taxii/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("taxiiPull() calls POST /api/taxii/pull", async () => {
    const body = {
      pulled: 1,
      records: [
        {
          indicator_type: "ipv4-addr",
          indicator_value: "198.51.100.1",
          severity: "high",
          source: "taxii",
          description: "known bad IP",
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.taxiiPull();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/taxii/pull",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("collectorsAws() calls GET /api/collectors/aws", async () => {
    const body = {
      config: {
        region: "us-east-1",
        access_key_id: "${AWS_ACCESS_KEY_ID}",
        poll_interval_secs: 60,
        max_results: 25,
        event_name_filter: ["ConsoleLogin"],
        enabled: true,
        has_secret_access_key: true,
        has_session_token: false,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.collectorsAws();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/aws",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveAwsCollectorConfig() posts the AWS collector setup payload", async () => {
    const request = {
      enabled: true,
      region: "us-east-1",
      access_key_id: "${AWS_ACCESS_KEY_ID}",
      secret_access_key: "secret-reference",
      session_token: null,
      poll_interval_secs: 60,
      max_results: 25,
      event_name_filter: ["ConsoleLogin"],
    };
    const body = {
      status: "saved",
      provider: "aws_cloudtrail",
      config: {
        region: "us-east-1",
        access_key_id: "${AWS_ACCESS_KEY_ID}",
        poll_interval_secs: 60,
        max_results: 25,
        event_name_filter: ["ConsoleLogin"],
        enabled: true,
        has_secret_access_key: true,
        has_session_token: false,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveAwsCollectorConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/aws/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateAwsCollector() calls POST /api/collectors/aws/validate", async () => {
    const body = {
      provider: "aws_cloudtrail",
      success: true,
      event_count: 2,
      polled_at: "2026-04-29T12:00:00Z",
      next_token: null,
      sample_events: [
        {
          event_id: "event-1",
          event_name: "ConsoleLogin",
          event_source: "signin.amazonaws.com",
          timestamp: "2026-04-29T11:59:00Z",
          region: "us-east-1",
          source_ip: "198.51.100.4",
          user_arn: "arn:aws:iam::123456789012:user/test",
          user_agent: "aws-cli/2",
          error_code: null,
          error_message: null,
          read_only: true,
          risk_score: 7.5,
          mitre_techniques: ["T1078"],
          raw_json: null,
        },
      ],
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
      reliability: {
        last_success_at: "2026-04-29T12:00:00Z",
        last_error_at: null,
        error_category: null,
        events_ingested: 2,
        lag_seconds: 0,
        checkpoint_id: "checkpoint-1",
        retry_count: 0,
        backoff_seconds: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateAwsCollector();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/aws/validate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("collectorsAzure() calls GET /api/collectors/azure", async () => {
    const body = {
      config: {
        tenant_id: "tenant-guid",
        client_id: "client-guid",
        subscription_id: "subscription-guid",
        poll_interval_secs: 120,
        categories: ["Administrative", "Security"],
        enabled: true,
        has_client_secret: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.collectorsAzure();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/azure",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveAzureCollectorConfig() posts the Azure collector setup payload", async () => {
    const request = {
      enabled: true,
      tenant_id: "tenant-guid",
      client_id: "client-guid",
      client_secret: "secret-reference",
      subscription_id: "subscription-guid",
      poll_interval_secs: 120,
      categories: ["Administrative", "Security"],
    };
    const body = {
      status: "saved",
      provider: "azure_activity",
      config: {
        tenant_id: "tenant-guid",
        client_id: "client-guid",
        subscription_id: "subscription-guid",
        poll_interval_secs: 120,
        categories: ["Administrative", "Security"],
        enabled: true,
        has_client_secret: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveAzureCollectorConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/azure/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateAzureCollector() calls POST /api/collectors/azure/validate", async () => {
    const body = {
      provider: "azure_activity",
      success: true,
      event_count: 1,
      polled_at: "2026-04-29T12:00:00Z",
      sample_events: [
        {
          event_id: "event-1",
          operation_name: "Microsoft.Compute/virtualMachines/write",
          category: "Administrative",
          result_type: "Success",
          caller: "user@example.com",
          timestamp: "2026-04-29T11:59:00Z",
          resource_id: "/subscriptions/subscription-guid/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
          resource_group: "rg",
          level: "Informational",
          subscription_id: "subscription-guid",
          source_ip: "198.51.100.8",
          risk_score: 3.5,
          mitre_techniques: ["T1578.002"],
        },
      ],
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
      reliability: {
        last_success_at: "2026-04-29T12:00:00Z",
        last_error_at: null,
        error_category: null,
        events_ingested: 1,
        lag_seconds: 0,
        checkpoint_id: "checkpoint-2",
        retry_count: 0,
        backoff_seconds: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateAzureCollector();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/azure/validate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("collectorsGcp() calls GET /api/collectors/gcp", async () => {
    const body = {
      config: {
        project_id: "wardex-prod",
        service_account_email: "collector@wardex-prod.iam.gserviceaccount.com",
        key_file_path: "/secure/service-account.json",
        poll_interval_secs: 180,
        log_filter: 'logName:"cloudaudit.googleapis.com"',
        page_size: 100,
        enabled: false,
        has_private_key_pem: false,
      },
      validation: {
        status: "warning",
        issues: [
          {
            level: "warning",
            field: "enabled",
            message: "Collector is disabled.",
          },
        ],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.collectorsGcp();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/gcp",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveGcpCollectorConfig() posts the GCP collector setup payload", async () => {
    const request = {
      enabled: true,
      project_id: "wardex-prod",
      service_account_email: "collector@wardex-prod.iam.gserviceaccount.com",
      key_file_path: "/secure/service-account.json",
      private_key_pem: null,
      poll_interval_secs: 180,
      log_filter: 'logName:"cloudaudit.googleapis.com"',
      page_size: 100,
    };
    const body = {
      status: "saved",
      provider: "gcp_audit",
      config: {
        project_id: "wardex-prod",
        service_account_email: "collector@wardex-prod.iam.gserviceaccount.com",
        key_file_path: "/secure/service-account.json",
        poll_interval_secs: 180,
        log_filter: 'logName:"cloudaudit.googleapis.com"',
        page_size: 100,
        enabled: true,
        has_private_key_pem: false,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveGcpCollectorConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/gcp/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateGcpCollector() calls POST /api/collectors/gcp/validate", async () => {
    const body = {
      provider: "gcp_audit",
      success: true,
      event_count: 1,
      polled_at: "2026-04-29T12:00:00Z",
      next_page_token: "next-page-token",
      sample_events: [
        {
          insert_id: "insert-1",
          method_name: "google.iam.admin.v1.SetIamPolicy",
          service_name: "iam.googleapis.com",
          resource_name: "projects/wardex-prod/serviceAccounts/test",
          resource_type: "service_account",
          timestamp: "2026-04-29T11:59:00Z",
          caller_ip: "198.51.100.12",
          principal_email: "user@example.com",
          severity: "NOTICE",
          status_code: 0,
          status_message: null,
          project_id: "wardex-prod",
          risk_score: 7.5,
          mitre_techniques: ["T1098"],
        },
      ],
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
      reliability: {
        last_success_at: "2026-04-29T12:00:00Z",
        last_error_at: null,
        error_category: null,
        events_ingested: 1,
        lag_seconds: 0,
        checkpoint_id: "checkpoint-3",
        retry_count: 0,
        backoff_seconds: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateGcpCollector();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/gcp/validate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("collectorsOkta() calls GET /api/collectors/okta", async () => {
    const body = {
      config: {
        domain: "dev-123456.okta.com",
        poll_interval_secs: 30,
        event_type_filter: ["user.session.start"],
        enabled: true,
        has_api_token: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.collectorsOkta();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/okta",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveOktaCollectorConfig() posts the Okta collector setup payload", async () => {
    const request = {
      enabled: true,
      domain: "dev-123456.okta.com",
      api_token: "secret-reference",
      poll_interval_secs: 30,
      event_type_filter: ["user.session.start"],
    };
    const body = {
      status: "saved",
      provider: "okta_identity",
      config: {
        domain: "dev-123456.okta.com",
        poll_interval_secs: 30,
        event_type_filter: ["user.session.start"],
        enabled: true,
        has_api_token: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveOktaCollectorConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/okta/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateOktaCollector() calls POST /api/collectors/okta/validate", async () => {
    const body = {
      provider: "okta_identity",
      success: true,
      event_count: 3,
      polled_at: "2026-04-29T12:00:00Z",
      sample_events: [
        {
          event_id: "okta-event-1",
          provider: "Okta",
          event_type: "user.session.start",
          outcome: "SUCCESS",
          timestamp: "2026-04-29T11:59:00Z",
          user_principal: "user@example.com",
          user_display_name: "User Example",
          source_ip: "198.51.100.20",
          user_agent: "Mozilla/5.0",
          location: "Berlin, DE",
          target_app: "Okta Dashboard",
          mfa_used: true,
          provider_risk: "low",
          risk_score: 1,
          mitre_techniques: ["T1078"],
          failure_reason: null,
        },
      ],
      summary: {
        total: 3,
        success: 3,
      },
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
      reliability: {
        last_success_at: "2026-04-29T12:00:00Z",
        last_error_at: null,
        error_category: null,
        events_ingested: 3,
        lag_seconds: 0,
        checkpoint_id: "checkpoint-4",
        retry_count: 0,
        backoff_seconds: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateOktaCollector();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/okta/validate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("collectorsEntra() calls GET /api/collectors/entra", async () => {
    const body = {
      config: {
        tenant_id: "entra-tenant-guid",
        client_id: "entra-client-guid",
        poll_interval_secs: 60,
        enabled: true,
        has_client_secret: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.collectorsEntra();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/entra",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveEntraCollectorConfig() posts the Entra collector setup payload", async () => {
    const request = {
      enabled: true,
      tenant_id: "entra-tenant-guid",
      client_id: "entra-client-guid",
      client_secret: "secret-reference",
      poll_interval_secs: 60,
    };
    const body = {
      status: "saved",
      provider: "entra_identity",
      config: {
        tenant_id: "entra-tenant-guid",
        client_id: "entra-client-guid",
        poll_interval_secs: 60,
        enabled: true,
        has_client_secret: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveEntraCollectorConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/entra/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateEntraCollector() calls POST /api/collectors/entra/validate", async () => {
    const body = {
      provider: "entra_identity",
      success: true,
      event_count: 2,
      polled_at: "2026-04-29T12:05:00Z",
      sample_events: [
        {
          event_id: "entra-event-1",
          provider: "MicrosoftEntra",
          event_type: "UserLoggedIn",
          outcome: "SUCCESS",
          timestamp: "2026-04-29T12:04:00Z",
          user_principal: "analyst@example.com",
          user_display_name: "Analyst Example",
          source_ip: "203.0.113.45",
          user_agent: "Mozilla/5.0",
          location: "Munich, DE",
          target_app: "Microsoft Entra ID",
          mfa_used: true,
          provider_risk: "low",
          risk_score: 1,
          mitre_techniques: ["T1078"],
          failure_reason: null,
        },
      ],
      summary: {
        total: 2,
        success: 2,
      },
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
      reliability: {
        last_success_at: "2026-04-29T12:05:00Z",
        last_error_at: null,
        error_category: null,
        events_ingested: 2,
        lag_seconds: 0,
        checkpoint_id: "checkpoint-5",
        retry_count: 0,
        backoff_seconds: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateEntraCollector();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/entra/validate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("collectorsM365() calls GET /api/collectors/m365", async () => {
    const body = {
      config: {
        tenant_id: "tenant-guid",
        client_id: "client-guid",
        poll_interval_secs: 60,
        content_types: ["Audit.AzureActiveDirectory", "Audit.Exchange"],
        enabled: true,
        has_client_secret: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.collectorsM365();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/m365",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveM365CollectorConfig() posts the M365 collector setup payload", async () => {
    const request = {
      enabled: true,
      tenant_id: "tenant-guid",
      client_id: "client-guid",
      client_secret: "secret-reference",
      poll_interval_secs: 60,
      content_types: ["Audit.AzureActiveDirectory", "Audit.Exchange"],
    };
    const body = {
      status: "saved",
      provider: "m365_saas",
      config: {
        tenant_id: "tenant-guid",
        client_id: "client-guid",
        poll_interval_secs: 60,
        content_types: ["Audit.AzureActiveDirectory", "Audit.Exchange"],
        enabled: true,
        has_client_secret: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveM365CollectorConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/m365/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateM365Collector() calls POST /api/collectors/m365/validate", async () => {
    const body = {
      provider: "m365_saas",
      success: true,
      event_count: 2,
      sample_events: [
        {
          content_type: "Audit.AzureActiveDirectory",
          tenant_id: "tenant-guid",
          workload: "AzureActiveDirectory",
          sample_operation: "UserLoggedIn",
          ingest_status: "shadow-ready",
        },
        {
          content_type: "Audit.Exchange",
          tenant_id: "tenant-guid",
          workload: "Exchange",
          sample_operation: "MailboxLogin",
          ingest_status: "shadow-ready",
        },
      ],
      summary: {
        tenant_id: "tenant-guid",
        client_id: "client-guid",
        content_types: ["Audit.AzureActiveDirectory", "Audit.Exchange"],
        recommended_pivots: ["soc", "ueba", "assistant"],
      },
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
      reliability: {
        last_success_at: "2026-04-29T12:10:00Z",
        last_error_at: null,
        error_category: null,
        events_ingested: 2,
        lag_seconds: 0,
        checkpoint_id: "checkpoint-6",
        retry_count: 0,
        backoff_seconds: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateM365Collector();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/m365/validate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("collectorsWorkspace() calls GET /api/collectors/workspace", async () => {
    const body = {
      config: {
        customer_id: "my_customer",
        delegated_admin_email: "admin@example.com",
        service_account_email: "svc-account@example.iam.gserviceaccount.com",
        poll_interval_secs: 60,
        applications: ["login", "admin", "drive"],
        enabled: true,
        has_credentials_json: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.collectorsWorkspace();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/workspace",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveWorkspaceCollectorConfig() posts the Workspace collector setup payload", async () => {
    const request = {
      enabled: true,
      customer_id: "my_customer",
      delegated_admin_email: "admin@example.com",
      service_account_email: "svc-account@example.iam.gserviceaccount.com",
      credentials_json: "secret-reference",
      poll_interval_secs: 60,
      applications: ["login", "admin", "drive"],
    };
    const body = {
      status: "saved",
      provider: "workspace_saas",
      config: {
        customer_id: "my_customer",
        delegated_admin_email: "admin@example.com",
        service_account_email: "svc-account@example.iam.gserviceaccount.com",
        poll_interval_secs: 60,
        applications: ["login", "admin", "drive"],
        enabled: true,
        has_credentials_json: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveWorkspaceCollectorConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/workspace/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateWorkspaceCollector() calls POST /api/collectors/workspace/validate", async () => {
    const body = {
      provider: "workspace_saas",
      success: true,
      event_count: 3,
      sample_events: [
        {
          application: "login",
          customer_id: "my_customer",
          actor_email: "admin@example.com",
          service_account_email: "svc-account@example.iam.gserviceaccount.com",
          sample_event: "login_success",
          ingest_status: "shadow-ready",
        },
        {
          application: "admin",
          customer_id: "my_customer",
          actor_email: "admin@example.com",
          service_account_email: "svc-account@example.iam.gserviceaccount.com",
          sample_event: "admin_role_assignment",
          ingest_status: "shadow-ready",
        },
      ],
      summary: {
        customer_id: "my_customer",
        delegated_admin_email: "admin@example.com",
        applications: ["login", "admin", "drive"],
        recommended_pivots: ["soc", "ueba", "infrastructure"],
      },
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
      reliability: {
        last_success_at: "2026-04-29T12:15:00Z",
        last_error_at: null,
        error_category: null,
        events_ingested: 3,
        lag_seconds: 0,
        checkpoint_id: "checkpoint-7",
        retry_count: 0,
        backoff_seconds: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateWorkspaceCollector();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/workspace/validate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("collectorsGithub() calls GET /api/collectors/github", async () => {
    const body = {
      provider: "github_audit",
      config: {
        provider: "github_audit",
        enabled: true,
        organization: "acme-security",
        token_ref: "********",
        webhook_secret_ref: "********",
        poll_interval_secs: 300,
        repositories: ["platform", "infra"],
        required_fields: ["organization", "token_ref", "webhook_secret_ref"],
        has_token_ref: true,
        has_webhook_secret_ref: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.collectorsGithub();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/github",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveGithubCollectorConfig() posts the GitHub collector setup payload", async () => {
    const request = {
      enabled: true,
      organization: "acme-security",
      token_ref: "secret://github/audit-token",
      webhook_secret_ref: "secret://github/webhook-secret",
      poll_interval_secs: 300,
      repositories: ["platform", "infra"],
    };
    const body = {
      status: "saved",
      provider: "github_audit",
      config: {
        provider: "github_audit",
        enabled: true,
        organization: "acme-security",
        token_ref: "********",
        webhook_secret_ref: "********",
        poll_interval_secs: 300,
        repositories: ["platform", "infra"],
        required_fields: ["organization", "token_ref", "webhook_secret_ref"],
        has_token_ref: true,
        has_webhook_secret_ref: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveGithubCollectorConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/github/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateGithubCollector() calls POST /api/collectors/github/validate", async () => {
    const body = {
      provider: "github_audit",
      success: true,
      event_count: 2,
      sample_events: [
        {
          action: "org.audit_log_export",
          actor: "security-admin",
          organization: "acme-security",
          route: "soc.identity.saas",
        },
        {
          action: "repo.visibility_change",
          actor: "platform-owner",
          repository: "platform",
          route: "supply_chain",
        },
      ],
      summary: {
        organization: "acme-security",
        repository_count: 2,
        has_token_ref: true,
        has_webhook_secret_ref: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
      reliability: {
        last_success_at: "2026-04-29T12:20:00Z",
        last_error_at: null,
        error_category: null,
        events_ingested: 2,
        lag_seconds: 0,
        checkpoint_id: "checkpoint-8",
        retry_count: 0,
        backoff_seconds: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateGithubCollector();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/github/validate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("collectorsCrowdStrike() calls GET /api/collectors/crowdstrike", async () => {
    const body = {
      provider: "crowdstrike_falcon",
      config: {
        provider: "crowdstrike_falcon",
        enabled: true,
        cloud: "us-1",
        client_id: "falcon-client-id",
        client_secret_ref: "********",
        customer_id: "cid-00000000000000000000000000000000",
        poll_interval_secs: 180,
        required_fields: ["cloud", "client_id", "client_secret_ref", "customer_id"],
        has_client_secret_ref: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.collectorsCrowdStrike();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/crowdstrike",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveCrowdStrikeCollectorConfig() posts the CrowdStrike collector setup payload", async () => {
    const request = {
      enabled: true,
      cloud: "us-1",
      client_id: "falcon-client-id",
      client_secret_ref: "secret://crowdstrike/client-secret",
      customer_id: "cid-00000000000000000000000000000000",
      poll_interval_secs: 180,
    };
    const body = {
      status: "saved",
      provider: "crowdstrike_falcon",
      config: {
        provider: "crowdstrike_falcon",
        enabled: true,
        cloud: "us-1",
        client_id: "falcon-client-id",
        client_secret_ref: "********",
        customer_id: "cid-00000000000000000000000000000000",
        poll_interval_secs: 180,
        required_fields: ["cloud", "client_id", "client_secret_ref", "customer_id"],
        has_client_secret_ref: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveCrowdStrikeCollectorConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/crowdstrike/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateCrowdStrikeCollector() calls POST /api/collectors/crowdstrike/validate", async () => {
    const body = {
      provider: "crowdstrike_falcon",
      success: true,
      event_count: 2,
      sample_events: [
        {
          event_simple_name: "DetectionSummaryEvent",
          hostname: "workstation-17",
          severity: "high",
          route: "soc.edr",
        },
        {
          event_simple_name: "SensorHeartbeat",
          customer_id: "cid-00000000000000000000000000000000",
          route: "fleet.health",
        },
      ],
      summary: {
        cloud: "us-1",
        client_id: "falcon-client-id",
        customer_id: "cid-00000000000000000000000000000000",
        has_client_secret_ref: true,
      },
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
      reliability: {
        last_success_at: "2026-04-29T12:25:00Z",
        last_error_at: null,
        error_category: null,
        events_ingested: 2,
        lag_seconds: 0,
        checkpoint_id: "checkpoint-9",
        retry_count: 0,
        backoff_seconds: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateCrowdStrikeCollector();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/crowdstrike/validate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("collectorsSyslog() calls GET /api/collectors/syslog", async () => {
    const body = {
      provider: "generic_syslog",
      config: {
        provider: "generic_syslog",
        enabled: true,
        bind: "0.0.0.0",
        port: 5514,
        protocol: "udp",
        facility: "local4",
        parse_profile: "auto",
        poll_interval_secs: 60,
        required_fields: ["bind", "port", "protocol"],
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.collectorsSyslog();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/syslog",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveSyslogCollectorConfig() posts the syslog collector setup payload", async () => {
    const request = {
      enabled: true,
      bind: "0.0.0.0",
      port: 5514,
      protocol: "udp",
      facility: "local4",
      parse_profile: "auto",
      poll_interval_secs: 60,
    };
    const body = {
      status: "saved",
      provider: "generic_syslog",
      config: {
        provider: "generic_syslog",
        enabled: true,
        bind: "0.0.0.0",
        port: 5514,
        protocol: "udp",
        facility: "local4",
        parse_profile: "auto",
        poll_interval_secs: 60,
        required_fields: ["bind", "port", "protocol"],
      },
      validation: {
        status: "ready",
        issues: [],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveSyslogCollectorConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/syslog/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateSyslogCollector() calls POST /api/collectors/syslog/validate", async () => {
    const body = {
      provider: "generic_syslog",
      success: true,
      event_count: 2,
      sample_events: [
        {
          facility: "local4",
          severity: "notice",
          message: "vpn gateway accepted login for analyst",
          route: "soc.syslog",
        },
        {
          facility: "authpriv",
          severity: "warning",
          message: "sudo authentication failure",
          route: "ueba.identity",
        },
      ],
      summary: {
        bind: "0.0.0.0",
        port: 5514,
        protocol: "udp",
        parse_profile: "auto",
      },
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
      reliability: {
        last_success_at: "2026-04-29T12:30:00Z",
        last_error_at: null,
        error_category: null,
        events_ingested: 2,
        lag_seconds: 0,
        checkpoint_id: "checkpoint-10",
        retry_count: 0,
        backoff_seconds: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateSyslogCollector();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/collectors/syslog/validate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("secretsStatus() calls GET /api/secrets/status", async () => {
    const body = {
      config: {
        vault: {
          address: "https://vault.example.com",
          mount: "secret",
          namespace: "wardex",
          enabled: true,
          cache_ttl_secs: 300,
          has_token: true,
        },
        env_prefix: "WARDEX_",
        secrets_dir: "/run/secrets",
        supported_sources: ["${ENV_VAR}", "file:///run/secrets/name", "vault://secret/path#key"],
      },
      validation: {
        status: "ready",
        issues: [],
      },
      status: {
        vault_enabled: true,
        vault_address: "https://vault.example.com",
        cache_size: 2,
        env_prefix: "WARDEX_",
        secrets_dir: "/run/secrets",
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.secretsStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/secrets/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("saveSecretsConfig() posts the secrets manager setup payload", async () => {
    const request = {
      vault: {
        enabled: true,
        address: "https://vault.example.com",
        token: "secret-reference",
        mount: "secret",
        namespace: "wardex",
        cache_ttl_secs: 300,
      },
      env_prefix: "WARDEX_",
      secrets_dir: "/run/secrets",
    };
    const body = {
      status: "saved",
      config: {
        vault: {
          address: "https://vault.example.com",
          mount: "secret",
          namespace: "wardex",
          enabled: true,
          cache_ttl_secs: 300,
          has_token: true,
        },
        env_prefix: "WARDEX_",
        secrets_dir: "/run/secrets",
        supported_sources: ["${ENV_VAR}", "file:///run/secrets/name", "vault://secret/path#key"],
      },
      validation: {
        status: "ready",
        issues: [],
      },
      status_summary: {
        vault_enabled: true,
        vault_address: "https://vault.example.com",
        cache_size: 0,
        env_prefix: "WARDEX_",
        secrets_dir: "/run/secrets",
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.saveSecretsConfig(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/secrets/config",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("validateSecretReference() posts the secret reference payload", async () => {
    const request = { reference: "vault://secret/path#token" };
    const body = {
      ok: true,
      reference_kind: "vault",
      resolved_length: 18,
      preview: "su..ue",
      status: {
        vault_enabled: true,
        vault_address: "https://vault.example.com",
        cache_size: 1,
        env_prefix: "WARDEX_",
        secrets_dir: "/run/secrets",
      },
      validation: {
        status: "ready",
        issues: [],
      },
      error: null,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.validateSecretReference(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/secrets/validate",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("efficacyTriage() posts the detection efficacy triage record", async () => {
    const request = {
      alert_id: "alert-42",
      rule_id: "sigma-credential-access",
      rule_name: "Suspicious Credential Access",
      severity: "high",
      outcome: "TruePositive" as const,
      triaged_by: "analyst1",
      created_at_ms: 1714464000000,
      triaged_at_ms: 1714464300000,
      triage_duration_ms: 300000,
      agent_id: "host-7",
    };
    const body = { status: "recorded" };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.efficacyTriage(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/efficacy/triage",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });


  it("fpFeedback() posts false-positive feedback", async () => {
    const feedback = {
      alert_fingerprint: "alert-fp-1",
      marked_fp: true,
      analyst: "analyst1",
      timestamp: "2026-05-01T10:00:00Z",
      reason_pattern: "known scanner",
    };
    const body = { recorded: true };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.fpFeedback(feedback);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/fp-feedback",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(feedback),
      })
    );
  });

  it("fpFeedbackStats() calls GET /api/fp-feedback/stats", async () => {
    const body = [
      {
        pattern: "known scanner",
        total_marked: 6,
        false_positives: 5,
        fp_ratio: 0.8333333,
        suppression_weight: 0.33333334,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.fpFeedbackStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/fp-feedback/stats",
      expect.objectContaining({ method: "GET" })
    );
  });
  it("efficacySummary() calls GET /api/efficacy/summary", async () => {
    const body = {
      total_alerts_triaged: 24,
      overall_tp_rate: 0.75,
      overall_fp_rate: 0.125,
      overall_precision: 0.857,
      mean_triage_secs: 187.4,
      rules_tracked: 2,
      worst_rules: [
        {
          rule_id: "sigma-noisy",
          rule_name: "Noisy Sigma Rule",
          total_alerts: 9,
          true_positives: 4,
          false_positives: 3,
          benign: 1,
          inconclusive: 1,
          pending: 0,
          tp_rate: 0.5,
          fp_rate: 0.375,
          precision: 0.571,
          mean_triage_secs: 240.2,
          trend: "Degrading",
        },
      ],
      best_rules: [
        {
          rule_id: "sigma-credential-access",
          rule_name: "Suspicious Credential Access",
          total_alerts: 15,
          true_positives: 11,
          false_positives: 0,
          benign: 2,
          inconclusive: 1,
          pending: 1,
          tp_rate: 0.846,
          fp_rate: 0,
          precision: 1,
          mean_triage_secs: 152.7,
          trend: "Improving",
        },
      ],
      by_severity: {
        high: {
          total: 10,
          tp_rate: 0.8,
          fp_rate: 0.1,
          mean_triage_secs: 143.2,
        },
        medium: {
          total: 14,
          tp_rate: 0.714,
          fp_rate: 0.143,
          mean_triage_secs: 218.9,
        },
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.efficacySummary();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/efficacy/summary",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("efficacyRule() calls GET /api/efficacy/rule/:id with URL encoding", async () => {
    const ruleId = "sigma/credential access";
    const body = {
      rule_id: "sigma/credential-access",
      rule_name: "Suspicious Credential Access",
      total_alerts: 15,
      true_positives: 11,
      false_positives: 0,
      benign: 2,
      inconclusive: 1,
      pending: 1,
      tp_rate: 0.846,
      fp_rate: 0,
      precision: 1,
      mean_triage_secs: 152.7,
      trend: "Improving",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.efficacyRule(ruleId);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/efficacy/rule/sigma%2Fcredential%20access",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("efficacyCanaryPromote() calls POST /api/efficacy/canary-promote", async () => {
    const body = [
      {
        rule_id: "sigma-credential-access",
        rule_name: "Suspicious Credential Access",
        action: "promoted",
        reason: "15 alerts, 0 FPs, canary duration satisfied",
      },
      {
        rule_id: "sigma-noisy",
        rule_name: "Noisy Sigma Rule",
        action: "rolled_back",
        reason: "FP rate 22.0% exceeds threshold 15.0%",
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.efficacyCanaryPromote();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/efficacy/canary-promote",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("investigationWorkflows() calls GET /api/investigations/workflows", async () => {
    const body = [
      {
        id: "credential-compromise",
        name: "Credential Compromise",
        description: "Investigate a suspected credential compromise.",
        trigger_conditions: ["Impossible travel", "MFA fatigue"],
        severity: "high",
        mitre_techniques: ["T1078"],
        estimated_minutes: 35,
        steps: [
          {
            order: 1,
            title: "Validate identity telemetry",
            description: "Review recent login anomalies for the principal.",
            api_pivot: "/api/identity/entity/user-1",
            recommended_actions: ["Confirm recent sign-ins", "Check MFA prompts"],
            evidence_to_collect: ["Authentication logs", "IP reputation"],
            auto_queries: [
              {
                name: "User activity",
                endpoint: "/api/search?q=user-1",
                description: "Recent user activity across telemetry sources",
              },
            ],
          },
        ],
        completion_criteria: ["Identity reset performed", "Sessions revoked"],
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.investigationWorkflows();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/investigations/workflows",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("investigationWorkflow() calls GET /api/investigations/workflows/:id with URL encoding", async () => {
    const workflowId = "credential compromise/v2";
    const body = {
      id: "credential-compromise",
      name: "Credential Compromise",
      description: "Investigate a suspected credential compromise.",
      trigger_conditions: ["Impossible travel", "MFA fatigue"],
      severity: "high",
      mitre_techniques: ["T1078"],
      estimated_minutes: 35,
      steps: [
        {
          order: 1,
          title: "Validate identity telemetry",
          description: "Review recent login anomalies for the principal.",
          api_pivot: "/api/identity/entity/user-1",
          recommended_actions: ["Confirm recent sign-ins", "Check MFA prompts"],
          evidence_to_collect: ["Authentication logs", "IP reputation"],
          auto_queries: [
            {
              name: "User activity",
              endpoint: "/api/search?q=user-1",
              description: "Recent user activity across telemetry sources",
            },
          ],
        },
      ],
      completion_criteria: ["Identity reset performed", "Sessions revoked"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.investigationWorkflow(workflowId);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/investigations/workflows/credential%20compromise%2Fv2",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("investigationStart() posts the investigation start request", async () => {
    const request = {
      workflow_id: "credential-compromise",
      analyst: "analyst1",
      case_id: "case-42",
    };
    const body = {
      id: "inv-1",
      workflow_id: "credential-compromise",
      workflow_name: "Credential Compromise",
      workflow_description: "Investigate a suspected credential compromise.",
      workflow_severity: "high",
      mitre_techniques: ["T1078"],
      estimated_minutes: 35,
      case_id: "case-42",
      analyst: "analyst1",
      started_at: "2026-04-30T09:00:00Z",
      updated_at: "2026-04-30T09:00:00Z",
      completed_steps: [],
      notes: {},
      status: "in-progress",
      findings: [],
      handoff: null,
      total_steps: 3,
      completion_percent: 0,
      next_step: {
        order: 1,
        title: "Validate identity telemetry",
        description: "Review recent login anomalies for the principal.",
        api_pivot: "/api/identity/entity/user-1",
        recommended_actions: ["Confirm recent sign-ins", "Check MFA prompts"],
        evidence_to_collect: ["Authentication logs", "IP reputation"],
        auto_queries: [
          {
            name: "User activity",
            endpoint: "/api/search?q=user-1",
            description: "Recent user activity across telemetry sources",
          },
        ],
      },
      steps: [
        {
          order: 1,
          title: "Validate identity telemetry",
          description: "Review recent login anomalies for the principal.",
          api_pivot: "/api/identity/entity/user-1",
          recommended_actions: ["Confirm recent sign-ins", "Check MFA prompts"],
          evidence_to_collect: ["Authentication logs", "IP reputation"],
          auto_queries: [
            {
              name: "User activity",
              endpoint: "/api/search?q=user-1",
              description: "Recent user activity across telemetry sources",
            },
          ],
        },
      ],
      completion_criteria: ["Identity reset performed", "Sessions revoked"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.investigationStart(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/investigations/start",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("investigationActive() calls GET /api/investigations/active", async () => {
    const body = [
      {
        id: "inv-1",
        workflow_id: "credential-compromise",
        workflow_name: "Credential Compromise",
        workflow_description: "Investigate a suspected credential compromise.",
        workflow_severity: "high",
        mitre_techniques: ["T1078"],
        estimated_minutes: 35,
        case_id: "case-42",
        analyst: "analyst1",
        started_at: "2026-04-30T09:00:00Z",
        updated_at: "2026-04-30T09:05:00Z",
        completed_steps: [1],
        notes: { "1": "User confirmed MFA fatigue prompts." },
        status: "in-progress",
        findings: ["User account showed impossible travel"],
        handoff: null,
        total_steps: 3,
        completion_percent: 33,
        next_step: null,
        steps: [
          {
            order: 1,
            title: "Validate identity telemetry",
            description: "Review recent login anomalies for the principal.",
            api_pivot: "/api/identity/entity/user-1",
            recommended_actions: ["Confirm recent sign-ins", "Check MFA prompts"],
            evidence_to_collect: ["Authentication logs", "IP reputation"],
            auto_queries: [
              {
                name: "User activity",
                endpoint: "/api/search?q=user-1",
                description: "Recent user activity across telemetry sources",
              },
            ],
          },
        ],
        completion_criteria: ["Identity reset performed", "Sessions revoked"],
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.investigationActive();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/investigations/active",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("investigationProgress() posts the investigation progress update", async () => {
    const request = {
      investigation_id: "inv-1",
      step: 2,
      completed: true,
      note: "Collected Okta sign-in evidence.",
      finding: "Suspicious MFA resets were confirmed.",
    };
    const body = {
      id: "inv-1",
      workflow_id: "credential-compromise",
      workflow_name: "Credential Compromise",
      workflow_description: "Investigate a suspected credential compromise.",
      workflow_severity: "high",
      mitre_techniques: ["T1078"],
      estimated_minutes: 35,
      case_id: "case-42",
      analyst: "analyst1",
      started_at: "2026-04-30T09:00:00Z",
      updated_at: "2026-04-30T09:12:00Z",
      completed_steps: [1, 2],
      notes: {
        "1": "User confirmed MFA fatigue prompts.",
        "2": "Collected Okta sign-in evidence.",
      },
      status: "in-progress",
      findings: [
        "User account showed impossible travel",
        "Suspicious MFA resets were confirmed.",
      ],
      handoff: null,
      total_steps: 3,
      completion_percent: 67,
      next_step: {
        order: 3,
        title: "Contain account access",
        description: "Reset credentials and revoke active sessions.",
        api_pivot: "/api/remediation/change-reviews",
        recommended_actions: ["Reset password", "Revoke refresh tokens"],
        evidence_to_collect: ["Reset confirmation", "Session revocation audit trail"],
        auto_queries: [],
      },
      steps: [
        {
          order: 1,
          title: "Validate identity telemetry",
          description: "Review recent login anomalies for the principal.",
          api_pivot: "/api/identity/entity/user-1",
          recommended_actions: ["Confirm recent sign-ins", "Check MFA prompts"],
          evidence_to_collect: ["Authentication logs", "IP reputation"],
          auto_queries: [
            {
              name: "User activity",
              endpoint: "/api/search?q=user-1",
              description: "Recent user activity across telemetry sources",
            },
          ],
        },
      ],
      completion_criteria: ["Identity reset performed", "Sessions revoked"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.investigationProgress(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/investigations/progress",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("investigationHandoff() posts the investigation handoff request", async () => {
    const request = {
      investigation_id: "inv-1",
      to_analyst: "analyst2",
      summary: "Initial identity review completed; containment still pending.",
      next_actions: ["Revoke active sessions", "Reset password"],
      questions: ["Was the MFA device physically present?"],
      case_id: "42",
    };
    const body = {
      id: "inv-1",
      workflow_id: "credential-compromise",
      workflow_name: "Credential Compromise",
      workflow_description: "Investigate a suspected credential compromise.",
      workflow_severity: "high",
      mitre_techniques: ["T1078"],
      estimated_minutes: 35,
      case_id: "42",
      analyst: "analyst2",
      started_at: "2026-04-30T09:00:00Z",
      updated_at: "2026-04-30T09:20:00Z",
      completed_steps: [1, 2],
      notes: {
        "1": "User confirmed MFA fatigue prompts.",
        "2": "Collected Okta sign-in evidence.",
      },
      status: "handoff-ready",
      findings: [
        "User account showed impossible travel",
        "Suspicious MFA resets were confirmed.",
      ],
      handoff: {
        from_analyst: "analyst1",
        to_analyst: "analyst2",
        summary: "Initial identity review completed; containment still pending.",
        next_actions: ["Revoke active sessions", "Reset password"],
        questions: ["Was the MFA device physically present?"],
        updated_at: "2026-04-30T09:20:00Z",
      },
      total_steps: 3,
      completion_percent: 67,
      next_step: null,
      steps: [
        {
          order: 1,
          title: "Validate identity telemetry",
          description: "Review recent login anomalies for the principal.",
          api_pivot: "/api/identity/entity/user-1",
          recommended_actions: ["Confirm recent sign-ins", "Check MFA prompts"],
          evidence_to_collect: ["Authentication logs", "IP reputation"],
          auto_queries: [
            {
              name: "User activity",
              endpoint: "/api/search?q=user-1",
              description: "Recent user activity across telemetry sources",
            },
          ],
        },
      ],
      completion_criteria: ["Identity reset performed", "Sessions revoked"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.investigationHandoff(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/investigations/handoff",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("investigationSuggest() posts alert reasons and returns workflow suggestions", async () => {
    const request = {
      alert_reasons: ["impossible travel", "mfa fatigue"],
    };
    const body = [
      {
        id: "credential-compromise",
        name: "Credential Compromise",
        description: "Investigate a suspected credential compromise.",
        trigger_conditions: ["Impossible travel", "MFA fatigue"],
        severity: "high",
        mitre_techniques: ["T1078"],
        estimated_minutes: 35,
        steps: [
          {
            order: 1,
            title: "Validate identity telemetry",
            description: "Review recent login anomalies for the principal.",
            api_pivot: "/api/identity/entity/user-1",
            recommended_actions: ["Confirm recent sign-ins", "Check MFA prompts"],
            evidence_to_collect: ["Authentication logs", "IP reputation"],
            auto_queries: [
              {
                name: "User activity",
                endpoint: "/api/search?q=user-1",
                description: "Recent user activity across telemetry sources",
              },
            ],
          },
        ],
        completion_criteria: ["Identity reset performed", "Sessions revoked"],
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.investigationSuggest(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/investigations/suggest",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("investigationGraph() posts event ids and returns a graph response", async () => {
    const request = {
      event_ids: [42, 43],
    };
    const body = {
      nodes: [
        {
          id: "event-42",
          kind: "event",
          label: "Event #42 (score: 92.0)",
          metadata: {
            score: 92,
            level: "high",
            timestamp: "2026-04-30T08:12:00Z",
          },
        },
        {
          id: "host-host-7",
          kind: "host",
          label: "host-7",
          metadata: {
            platform: "macOS",
          },
        },
      ],
      edges: [
        {
          source: "event-42",
          target: "host-host-7",
          relation: "observed_on",
        },
      ],
      node_count: 2,
      edge_count: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.investigationGraph(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/investigation/graph",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("timelineHost() calls GET /api/timeline/host with hostname", async () => {
    const body = {
      timeline: [
        {
          timestamp: "2026-04-30T08:12:00Z",
          event_id: 42,
          event_type: "critical_alert",
          severity: "high",
          description: "impossible travel; mfa fatigue",
          agent_id: "agent-7",
        },
      ],
      host: "host-7",
      count: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.timelineHost("host-7");
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/timeline/host?hostname=host-7",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("timelineAgent() calls GET /api/timeline/agent with agent_id", async () => {
    const body = {
      timeline: [
        {
          timestamp: "2026-04-30T08:12:00Z",
          event_id: 42,
          event_type: "critical_alert",
          severity: "high",
          description: "impossible travel; mfa fatigue",
          agent_id: "agent-7",
        },
      ],
      agent_id: "agent-7",
      count: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.timelineAgent("agent-7");
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/timeline/agent?agent_id=agent-7",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("mlModels() calls GET /api/ml/models", async () => {
    const body = {
      loaded: [
        {
          name: "alert_triage_v1",
          version: "1.0.0",
          input_shape: [7],
          output_shape: [3],
          description: "Primary ONNX alert triage model",
        },
      ],
      available: [
        {
          name: "alert_triage_v1",
          version: "1.0.0",
          input_shape: [7],
          output_shape: [3],
          description: "Primary ONNX alert triage model",
        },
        {
          name: "entity_risk_v1",
          version: "0.9.0",
          input_shape: [12],
          output_shape: [4],
          description: "Planned entity risk model",
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.mlModels();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ml/models",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("mlModelsStatus() calls GET /api/ml/models/status", async () => {
    const body = {
      slot: "alert_triage",
      active_backend: "onnx",
      shadow_backend: "random_forest_fallback",
      shadow_mode: true,
      onnx_loaded: true,
      last_refreshed_at: "2026-04-30T07:40:00Z",
      discovered_models: ["alert_triage_v1.onnx"],
      loaded_models: [
        {
          name: "alert_triage_v1",
          version: "1.0.0",
          input_shape: [7],
          output_shape: [3],
          description: "Primary ONNX alert triage model",
        },
      ],
      available_models: [
        {
          name: "alert_triage_v1",
          version: "1.0.0",
          input_shape: [7],
          output_shape: [3],
          description: "Primary ONNX alert triage model",
        },
      ],
      recent_shadow_reports: [
        {
          slot: "alert_triage",
          timestamp: "2026-04-30T07:39:00Z",
          active_backend: "onnx",
          active_label: "NeedsReview",
          active_confidence: 0.81,
          shadow_backend: "random_forest_fallback",
          shadow_label: "TruePositive",
          shadow_confidence: 0.73,
          confidence_delta: 0.08,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.mlModelsStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ml/models/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("mlModelsRollback() calls POST /api/ml/models/rollback", async () => {
    const body = {
      status: {
        slot: "alert_triage",
        active_backend: "random_forest_fallback",
        shadow_backend: "onnx",
        shadow_mode: true,
        onnx_loaded: true,
        last_refreshed_at: "2026-04-30T07:40:00Z",
        discovered_models: ["alert_triage_v1.onnx"],
        loaded_models: [
          {
            name: "alert_triage_v1",
            version: "1.0.0",
            input_shape: [7],
            output_shape: [3],
            description: "Primary ONNX alert triage model",
          },
        ],
        available_models: [
          {
            name: "alert_triage_v1",
            version: "1.0.0",
            input_shape: [7],
            output_shape: [3],
            description: "Primary ONNX alert triage model",
          },
        ],
        recent_shadow_reports: [],
      },
      changed: true,
      rolled_back_at: "2026-04-30T07:41:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.mlModelsRollback();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ml/models/rollback",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("mlShadowRecent() calls GET /api/ml/shadow/recent with limit", async () => {
    const body = {
      count: 1,
      items: [
        {
          slot: "alert_triage",
          timestamp: "2026-04-30T08:10:00Z",
          active_backend: "onnx",
          active_label: "NeedsReview",
          active_confidence: 0.81,
          shadow_backend: "random_forest_fallback",
          shadow_label: "TruePositive",
          shadow_confidence: 0.73,
          confidence_delta: 0.08,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.mlShadowRecent(5);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ml/shadow/recent?limit=5",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("mlTriage() posts the ML triage features payload", async () => {
    const request = {
      anomaly_score: 0.92,
      confidence: 0.83,
      suspicious_axes: 3,
      hour_of_day: 2,
      day_of_week: 1,
      alert_frequency_1h: 6,
      device_risk_score: 0.71,
    };
    const body = {
      label: "NeedsReview",
      confidence: 0.83,
      model_version: "rf-v1",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.mlTriage(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ml/triage",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("mlTriageV2() posts the managed ML triage features payload", async () => {
    const request = {
      anomaly_score: 0.92,
      confidence: 0.83,
      suspicious_axes: 3,
      hour_of_day: 2,
      day_of_week: 1,
      alert_frequency_1h: 6,
      device_risk_score: 0.71,
    };
    const body = {
      result: {
        label: "NeedsReview",
        confidence: 0.81,
        model_version: "onnx-v1",
      },
      shadow: {
        label: "TruePositive",
        confidence: 0.73,
        model_version: "rf-v1",
      },
      fallback_used: false,
      active_backend: "onnx",
      shadow_backend: "random_forest_fallback",
      calibration: {
        raw_confidence: 0.81,
        calibrated_confidence: 0.78,
        band: "medium",
      },
      rationale: ["Anomaly score is elevated", "Device risk score exceeds baseline"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.mlTriageV2(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ml/triage/v2",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("wsStats() calls GET /api/ws/stats", async () => {
    const body = {
      connected_clients: 1,
      total_events: 21,
      subscribers: 2,
      native_websocket_supported: false,
      connections: [
        {
          subscriber_id: 7,
          uptime_secs: 12.5,
          frames_sent: 8,
          frames_received: 4,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.wsStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ws/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("alerts() calls GET /api/alerts", async () => {
    const alerts = [
      {
        timestamp: "2026-01-01T00:00:00Z",
        hostname: "prod-web-01",
        platform: "linux",
        score: 8.7,
        confidence: 0.96,
        level: "Critical",
        action: "isolate",
        reasons: ["credential reuse", "remote service pivot"],
        sample: {
          timestamp_ms: 1714507800000,
          cpu_load_pct: 82.4,
          memory_load_pct: 74.1,
          temperature_c: 61.2,
          network_kbps: 4200.5,
          auth_failures: 18,
          battery_pct: 100,
          integrity_drift: 0.12,
          process_count: 276,
          disk_pressure_pct: 33.5,
        },
        enforced: true,
        mitre: [
          {
            tactic: "Credential Access",
            technique: "Brute Force",
            technique_id: "T1110",
          },
        ],
        narrative: {
          headline: "Credential pivot detected",
          summary: "Repeated auth failures preceded remote service access.",
          observations: ["Auth failures spiked", "Remote service pivot followed"],
          baseline_comparison: "Auth failures are 6x above baseline.",
          time_window: "5m",
          involved_entities: ["prod-web-01", "prod-db-01"],
          suggested_queries: ["search auth failures for prod-web-01"],
        },
        id: 7,
        _index: 7,
        entities: [
          {
            entity_type: "Hostname",
            value: "prod-web-01",
            start: 0,
            end: 11,
          },
        ],
        process_resolution: "unique",
        process_names: ["ssh"],
        process_candidates: [
          {
            pid: 321,
            ppid: 1,
            name: "/usr/sbin/sshd",
            display_name: "sshd",
            user: "root",
            group: "wheel",
            cpu_percent: 4.2,
            mem_percent: 1.1,
            hostname: "prod-web-01",
            platform: "linux",
            cmd_line: "/usr/sbin/sshd -D",
            exe_path: "/usr/sbin/sshd",
          },
        ],
        process: {
          pid: 321,
          ppid: 1,
          name: "/usr/sbin/sshd",
          display_name: "sshd",
          user: "root",
          group: "wheel",
          cpu_percent: 4.2,
          mem_percent: 1.1,
          hostname: "prod-web-01",
          platform: "linux",
          cmd_line: "/usr/sbin/sshd -D",
          exe_path: "/usr/sbin/sshd",
        },
      },
    ];
    const mock = mockFetch(200, alerts);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.alerts();
    expect(result).toEqual(alerts);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("alertsCount() calls GET /api/alerts/count", async () => {
    const counts = {
      total: 12,
      critical: 3,
      severe: 4,
      elevated: 5,
    };
    const mock = mockFetch(200, counts);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.alertsCount();
    expect(result).toEqual(counts);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/count",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("clearAlerts() calls DELETE /api/alerts", async () => {
    const body = {
      status: "cleared",
      count: 42,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.clearAlerts();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts",
      expect.objectContaining({
        method: "DELETE",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("sampleAlert() posts the sample alert severity", async () => {
    const body = {
      status: "injected",
      severity: "critical",
      score: 6.5,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.sampleAlert({ severity: "critical" });
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/sample",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ severity: "critical" }),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("bulkAcknowledgeAlerts() posts alert ids", async () => {
    const body = {
      status: "ok",
      acknowledged: 2,
      not_found: 1,
      total_requested: 3,
    };
    const request = { ids: ["alert-1", "alert-2", "alert-999"] };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.bulkAcknowledgeAlerts(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/bulk/acknowledge",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("bulkResolveAlerts() posts alert ids", async () => {
    const body = {
      status: "ok",
      resolved: 2,
      not_found: 1,
      total_requested: 3,
    };
    const request = { ids: ["alert-1", "alert-2", "alert-999"] };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.bulkResolveAlerts(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/bulk/resolve",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("bulkCloseAlerts() posts alert ids", async () => {
    const body = {
      status: "ok",
      closed: 2,
      not_found: 1,
      total_requested: 3,
    };
    const request = { ids: ["alert-1", "alert-2", "alert-999"] };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.bulkCloseAlerts(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/bulk/close",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("getAlert() calls GET /api/alerts/:index", async () => {
    const alert = {
      id: 7,
      index: 7,
      timestamp: "2026-01-01T00:00:00Z",
      hostname: "prod-web-01",
      platform: "linux",
      score: 8.7,
      confidence: 0.96,
      level: "Critical",
      action: "isolate",
      reasons: ["credential reuse", "remote service pivot"],
      enforced: true,
      sample: {
        timestamp_ms: 1714507800000,
        cpu_load_pct: 82.4,
        memory_load_pct: 74.1,
        temperature_c: 61.2,
        network_kbps: 4200.5,
        auth_failures: 18,
        battery_pct: 100,
        integrity_drift: 0.12,
        process_count: 276,
        disk_pressure_pct: 33.5,
      },
      analysis: {
        severity_class: "critical",
        multi_axis: true,
        axis_count: 2,
        recommendation:
          "Immediate isolation recommended. Investigate all flagged axes and correlate with SIEM events.",
      },
    };
    const mock = mockFetch(200, alert);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.getAlert(7);
    expect(result).toEqual(alert);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/7",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("alertAnalysis() calls GET /api/alerts/analysis", async () => {
    const analysis = {
      window_start: "2026-01-01T00:00:00Z",
      window_end: "2026-01-01T00:05:00Z",
      total_alerts: 3,
      pattern: "Baseline",
      score_trend: "Stable",
      dominant_reasons: [["credential reuse", 2]],
      clusters: [],
      anomalies: [],
      severity_breakdown: {
        critical: 1,
        severe: 1,
        elevated: 1,
      },
      isolation_guidance: [],
      summary: "No significant drift detected.",
    };
    const mock = mockFetch(200, analysis);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.alertAnalysis();
    expect(result).toEqual(analysis);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/analysis",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("runAlertAnalysis() posts the analysis window request", async () => {
    const analysis = {
      window_start: "2026-01-01T00:00:00Z",
      window_end: "2026-01-01T00:15:00Z",
      total_alerts: 5,
      pattern: { Sustained: { severity: "Critical" } },
      score_trend: { Rising: { slope: 0.8 } },
      dominant_reasons: [["remote service pivot", 3]],
      clusters: [],
      anomalies: [],
      severity_breakdown: {
        critical: 3,
        severe: 1,
        elevated: 1,
      },
      isolation_guidance: [
        {
          reason: "remote service pivot",
          threat_description: "Potential lateral movement via remote service.",
          steps: ["Review process lineage", "Check neighboring hosts"],
        },
      ],
      summary: "Sustained high-severity activity detected.",
    };
    const mock = mockFetch(200, analysis);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.runAlertAnalysis({ window_minutes: 15 });
    expect(result).toEqual(analysis);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/analysis",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ window_minutes: 15 }),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("groupedAlerts() calls GET /api/alerts/grouped", async () => {
    const groups = [
      {
        id: 0,
        first_seen: "2026-01-01T00:00:00Z",
        last_seen: "2026-01-01T00:05:00Z",
        count: 3,
        avg_score: 5.4,
        max_score: 8.7,
        level: "Critical",
        reason_fingerprint: "credential reuse|remote service pivot|Critical",
        representative_reasons: ["credential reuse", "remote service pivot"],
        indices: [7, 8, 9],
      },
    ];
    const mock = mockFetch(200, groups);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.groupedAlerts();
    expect(result).toEqual(groups);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/grouped",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("queueStats() calls GET /api/queue/stats", async () => {
    const body = {
      total: 4,
      pending: 3,
      unacknowledged: 3,
      acknowledged: 1,
      assigned: 2,
      sla_breached: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.queueStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/queue/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("responseStats() calls GET /api/response/stats", async () => {
    const body = {
      auto_executed: 2,
      executed: 2,
      pending: 1,
      pending_approval: 1,
      ready_to_execute: 3,
      approved_ready: 3,
      total_requests: 6,
      denied: 1,
      protected_assets: 12,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.responseStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/response/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("responseRequests() calls GET /api/response/requests", async () => {
    const body = {
      requests: [
        {
          id: "rr_123",
          action: "BlockIp { ip: \"198.51.100.10\" }",
          action_label: "Block IP 198.51.100.10",
          target: {
            hostname: "web-01",
            agent_uid: "agent-1",
            asset_tags: ["prod", "edge"],
          },
          target_hostname: "web-01",
          target_agent_uid: "agent-1",
          tier: "DualApproval",
          status: "Approved",
          created_at: "2026-04-30T12:00:00Z",
          requested_at: "2026-04-30T12:00:00Z",
          requested_by: "analyst@example.com",
          reason: "Block malicious egress",
          severity: "high",
          approvals: [
            {
              approver: "lead@example.com",
              decision: "Approve",
              timestamp: "2026-04-30T12:05:00Z",
              comment: "Proceed",
            },
          ],
          approval_count: 1,
          approvals_required: 2,
          dry_run: false,
          is_protected_asset: false,
          blast_radius: {
            affected_services: 2,
            affected_endpoints: 14,
            risk_level: "medium",
            impact_summary: "May disrupt one edge pool",
          },
          blast_radius_summary: "May disrupt one edge pool",
          input_context: {
            target: {
              hostname: "web-01",
              agent_uid: "agent-1",
              asset_tags: ["prod", "edge"],
            },
            severity: "high",
            tier: "DualApproval",
            dry_run: false,
            protected_asset: false,
            requested_at: "2026-04-30T12:00:00Z",
          },
          dry_run_result: null,
          execution_result: null,
          reversal_path: "Remove network block and validate connectivity.",
        },
      ],
      count: 1,
      ready_to_execute: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.responseRequests();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/response/requests",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("responseRequest() posts the response request payload", async () => {
    const payload = {
      action: "block_ip" as const,
      hostname: "web-01",
      agent_uid: "agent-1",
      asset_tags: ["prod", "edge"],
      reason: "Block malicious egress",
      severity: "high",
      dry_run: false,
      ip: "198.51.100.10",
    };
    const body = {
      status: "submitted",
      request: {
        id: "rr_123",
        action: "BlockIp { ip: \"198.51.100.10\" }",
        action_label: "Block IP 198.51.100.10",
        target: {
          hostname: "web-01",
          agent_uid: "agent-1",
          asset_tags: ["prod", "edge"],
        },
        target_hostname: "web-01",
        target_agent_uid: "agent-1",
        tier: "DualApproval",
        status: "Pending",
        created_at: "2026-04-30T12:00:00Z",
        requested_at: "2026-04-30T12:00:00Z",
        requested_by: "analyst@example.com",
        reason: "Block malicious egress",
        severity: "high",
        approvals: [],
        approval_count: 0,
        approvals_required: 2,
        dry_run: false,
        is_protected_asset: false,
        blast_radius: null,
        blast_radius_summary: null,
        input_context: {
          target: {
            hostname: "web-01",
            agent_uid: "agent-1",
            asset_tags: ["prod", "edge"],
          },
          severity: "high",
          tier: "DualApproval",
          dry_run: false,
          protected_asset: false,
          requested_at: "2026-04-30T12:00:00Z",
        },
        dry_run_result: null,
        execution_result: null,
        reversal_path: "Remove network block and validate connectivity.",
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.responseRequest(payload);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/response/request",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
      })
    );
  });

  it("responseExecute() posts the optional request id", async () => {
    const body = {
      executed_count: 1,
      actions: ["Blocked IP 198.51.100.10 via web-01"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.responseExecute("rr_123");
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/response/execute",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ request_id: "rr_123" }),
      })
    );
  });

  it("casesStats() calls GET /api/cases/stats", async () => {
    const body = {
      total: 9,
      open: 5,
      resolved: 4,
      triaging: 2,
      investigating: 2,
      escalated: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.casesStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/cases/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("platform() calls GET /api/platform", async () => {
    const body = {
      platform: "Linux",
      has_tpm: true,
      has_seccomp: true,
      has_ebpf: true,
      has_firewall: true,
      max_threads: 4096,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.platform();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/platform",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("sloStatus() calls GET /api/slo/status", async () => {
    const body = {
      api_latency_p99_ms: 12,
      error_rate_pct: 0.5,
      availability_pct: 99.5,
      budget_remaining_pct: 99.4,
      uptime_seconds: 7200,
      total_requests: 1000,
      total_errors: 5,
      successful_requests: 995,
      request_count: 1000,
      error_count: 5,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.sloStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/slo/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("feedStats() calls GET /api/feeds/stats", async () => {
    const body = {
      total_sources: 4,
      active_sources: 3,
      total_polls: 20,
      total_iocs_ingested: 150,
      total_hashes_imported: 75,
      total_yara_imported: 12,
      last_poll_results: [
        {
          feed_id: "feed-1",
          new_iocs: 5,
          updated_iocs: 2,
          new_hashes: 3,
          new_yara_rules: 1,
          errors: [],
          poll_time_ms: 184,
          timestamp: "2026-04-30T12:00:00Z",
        },
      ],
      errors_last_24h: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.feedStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/feeds/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("threatIntelStats() calls GET /api/threat-intel/stats", async () => {
    const body = {
      total_iocs: 42,
      by_type: { domain: 10, ip: 32 },
      by_severity: { high: 8, medium: 20, low: 14 },
      by_source: { misp: 30, manual: 12 },
      avg_confidence: 0.87,
      active_feeds: 2,
      total_feeds: 3,
      match_history_size: 18,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.threatIntelStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/threat-intel/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("threatIntelStatus() calls GET /api/threat-intel/status", async () => {
    const body = { ioc_count: 42 };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.threatIntelStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/threat-intel/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("metrics() calls GET /api/metrics and returns plain text", async () => {
    const body = "# HELP wardex_requests_total Total requests\nwardex_requests_total 100\n";
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.metrics();
    expect(result).toBe(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/metrics",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("managerQueueDigest() calls GET /api/manager/queue-digest", async () => {
    const body = {
      generated_at: "2026-04-30T12:00:00Z",
      queue: {
        pending: 5,
        acknowledged: 2,
        assigned: 3,
        sla_breached: 1,
        critical_pending: 2,
      },
      stale_cases: 4,
      degraded_collectors: 1,
      pending_dry_run_approvals: 2,
      ready_to_execute: 1,
      recent_suppressions: [
        {
          id: "sup-1",
          name: "Suppress noisy scanner",
          created_at: "2026-04-30T11:00:00Z",
          active: true,
          justification: "Accepted maintenance noise",
        },
      ],
      noisy_reasons: ["Suspicious DNS (12)"],
      changes_since_last_shift: ["1 queue item(s) are now past SLA."],
      top_queue_items: [
        {
          event_id: 42,
          agent_id: "agent-1",
          score: 9.8,
          severity: "Critical",
          hostname: "web-01",
          status: "pending",
          assignee: "lead@example.com",
          timestamp: "2026-04-30T11:45:00Z",
          age_secs: 900,
          sla_deadline: "2026-04-30T12:15:00Z",
          sla_breached: false,
          reasons: ["Credential access", "Lateral movement"],
        },
      ],
      urgent_items: [
        {
          kind: "queue",
          severity: "Critical",
          title: "Queue item #42 on web-01",
          subtitle: "Credential access, Lateral movement",
          reference_id: "42",
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.managerQueueDigest();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/manager/queue-digest",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("managerOverview() calls GET /api/manager/overview", async () => {
    const body = {
      generated_at: "2026-04-30T12:00:00Z",
      fleet: {
        total_agents: 12,
        online: 9,
        stale: 2,
        offline: 1,
        coverage_pct: 75,
      },
      queue: {
        pending: 5,
        acknowledged: 2,
        assigned: 3,
        sla_breached: 1,
        critical_pending: 2,
      },
      incidents: {
        total: 8,
        open: 3,
        investigating: 2,
        contained: 1,
        resolved: 1,
        false_positive: 1,
      },
      deployments: {
        published_releases: 4,
        pending: 2,
        by_status: {
          assigned: 2,
          completed: 6,
        },
        by_ring: {
          canary: 3,
          stable: 5,
        },
      },
      reports: {
        total_reports: 10,
        total_alerts: 87,
        critical_alerts: 6,
        avg_score: 72.5,
        max_score: 99.1,
        open_incidents: 3,
      },
      siem: {
        enabled: true,
        siem_type: "generic",
        endpoint: "https://siem.example.test",
        pending_events: 4,
        total_pushed: 12,
        total_pulled: 3,
        last_error: null,
        pull_enabled: true,
      },
      compliance: {
        score: 97.5,
      },
      tenants: 2,
      operations: {
        pending_approvals: 3,
        ready_to_execute: 1,
        protected_assets: 42,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.managerOverview();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/manager/overview",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("onboardingReadiness() calls GET /api/onboarding/readiness", async () => {
    const body = {
      generated_at: "2026-04-30T12:00:00Z",
      ready: false,
      completed: 4,
      total: 7,
      estimated_minutes: 15,
      checks: [
        {
          key: "first_agent_online",
          label: "First agent online",
          ready: true,
          status: "complete",
          detail: "1 agent(s) are currently online.",
        },
        {
          key: "response_approval_dry_run_completed",
          label: "Response approval dry-run completed",
          ready: false,
          status: "pending",
          detail: "Submit one dry-run response request to validate approval and rollback readiness.",
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.onboardingReadiness();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/onboarding/readiness",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("authSsoConfig() calls GET /api/auth/sso/config", async () => {
    const body = {
      enabled: true,
      providers: [
        {
          id: "okta-main",
          display_name: "Okta Main",
          kind: "oidc",
          status: "ready",
          validation_status: "ready",
          login_path: "/api/auth/sso/login?provider=okta-main",
        },
      ],
      issuer: "https://id.example.com",
      scopes: ["openid", "profile", "email"],
      scim: {
        enabled: true,
        status: "ready",
        mapping_count: 6,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.authSsoConfig();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/auth/sso/config",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("authRotate() calls POST /api/auth/rotate", async () => {
    const body = {
      status: "rotated",
      new_token: "new-token-123",
      previous_prefix: "abcd1234...",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.authRotate();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/auth/rotate",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("assistantStatus() calls GET /api/assistant/status", async () => {
    const body = {
      enabled: true,
      provider: "openai",
      model: "gpt-4.1-mini",
      has_api_key: true,
      active_conversations: 3,
      endpoint: "https://api.openai.com/v1",
      mode: "llm",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.assistantStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/assistant/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("assistantQuery() posts the assistant query payload", async () => {
    const payload = {
      question: "Summarize the current case and cite the strongest evidence",
      case_id: 1,
      conversation_id: "conv-123",
      context_filter: {
        time_range_hours: 24,
        severity_min: "elevated",
        device_filter: "db-01",
        alert_types: ["credential_access"],
      },
      limit: 5,
    };
    const body = {
      answer: "Database credential theft needs immediate review.",
      citations: [
        {
          source_type: "alert",
          source_id: "1",
          summary: "credential dumping observed on privileged session",
          relevance_score: 0.91,
        },
      ],
      confidence: 0.72,
      model_used: "retrieval-only",
      tokens_used: {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
      },
      response_time_ms: 85,
      conversation_id: "conv-123",
      mode: "retrieval-only",
      case_context: {
        case: {
          id: 1,
          title: "Database credential theft",
          description: "Investigate suspicious admin activity on db-01",
          status: "Investigating",
          priority: "Critical",
          assignee: "analyst-1",
          created_at: "2026-04-30T11:00:00Z",
          updated_at: "2026-04-30T11:30:00Z",
          incident_ids: [7],
          event_ids: [1, 2],
          tags: ["identity", "database"],
          comments: [
            {
              author: "analyst-1",
              timestamp: "2026-04-30T11:20:00Z",
              text: "Credential theft path needs immediate review",
            },
          ],
          evidence: [
            {
              kind: "alert",
              reference_id: "1",
              description: "Primary credential dumping alert",
              added_at: "2026-04-30T11:05:00Z",
            },
          ],
          mitre_techniques: ["T1003"],
        },
        linked_events: [
          {
            id: "1",
            event_type: "alert",
            summary: "credential dumping observed on privileged session",
            severity: "Critical",
            timestamp: "2026-04-30T11:10:00Z",
            device: "db-01",
            raw_data: null,
            relevance: 0.91,
          },
        ],
      },
      context_events: [
        {
          id: "1",
          event_type: "alert",
          summary: "credential dumping observed on privileged session",
          severity: "Critical",
          timestamp: "2026-04-30T11:10:00Z",
          device: "db-01",
          raw_data: null,
          relevance: 0.91,
        },
      ],
      warnings: ["LLM assistant is not configured; using retrieval-only synthesis"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.assistantQuery(payload);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/assistant/query",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
      })
    );
  });

  it("detectionExplain() calls GET /api/detection/explain with query params", async () => {
    const body = {
      event_id: 42,
      alert_id: "42",
      severity: "Critical",
      title: "isolate on prod-db-01",
      summary: ["Critical alert from agent-7.", "Received at 2026-04-30T20:15:00Z."],
      why_fired: [
        "The detector attached 2 reason(s): credential dumping, remote service pivot.",
      ],
      why_safe_or_noisy: [
        "No prior analyst feedback is recorded for this event, so treat the signal as unsuppressed.",
      ],
      next_steps: ["Review the implicated host", "Check related identities"],
      evidence: [
        {
          kind: "score",
          label: "Alert Score",
          value: "8.70",
          confidence: 0.96,
          source: "detector",
        },
      ],
      entity_scores: [
        {
          entity_kind: "host",
          entity_id: "prod-db-01",
          score: 8.1,
          confidence: 0.9,
          rationale: ["Credential dumping observed"],
        },
      ],
      triage_status: "new",
      related_cases: ["case-9"],
      feedback: [],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.detectionExplain({ event_id: 42, alert_id: "42" });
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/detection/explain?event_id=42&alert_id=42",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("detectionFeedback() calls GET /api/detection/feedback with summary", async () => {
    const body = {
      items: [
        {
          id: 1,
          event_id: 42,
          alert_id: "42",
          rule_id: "credential-reuse",
          analyst: "analyst-1",
          verdict: "true_positive",
          reason_pattern: "credential dumping",
          notes: "Confirmed with identity logs",
          evidence: [
            {
              kind: "reason",
              label: "Detection Reason",
              value: "credential dumping",
              confidence: 0.96,
              source: "detector",
            },
          ],
          created_at: "2026-04-30T20:20:00Z",
        },
      ],
      summary: {
        total: 1,
        by_verdict: { true_positive: 1 },
        analysts: 1,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.detectionFeedback(42, 25);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/detection/feedback?event_id=42&limit=25",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("recordDetectionFeedback() posts the feedback payload", async () => {
    const payload = {
      event_id: 42,
      alert_id: "42",
      rule_id: "credential-reuse",
      analyst: "analyst-1",
      verdict: "true_positive",
      reason_pattern: "credential dumping",
      notes: "Confirmed with identity logs",
      evidence: [
        {
          kind: "reason",
          label: "Detection Reason",
          value: "credential dumping",
          confidence: 0.96,
          source: "detector",
        },
      ],
    };
    const body = {
      id: 1,
      created_at: "2026-04-30T20:20:00Z",
      ...payload,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.recordDetectionFeedback(payload);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/detection/feedback",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("detectionProfile() calls GET /api/detection/profile", async () => {
    const body = {
      profile: "balanced" as const,
      description: "Default — tuned for production with good precision/recall balance",
      threshold_multiplier: 1.0,
      learn_threshold: 2.5,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.detectionProfile();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/detection/profile",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("setDetectionProfile() sends PUT /api/detection/profile", async () => {
    const body = {
      profile: "quiet" as const,
      applied: true,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.setDetectionProfile({ profile: "quiet" });
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/detection/profile",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ profile: "quiet" }),
      })
    );
  });

  it("normalizeScore() calls GET /api/detection/score/normalize", async () => {
    const body = {
      raw_score: 15,
      normalized: 95,
      severity: "critical" as const,
      confidence: "high" as const,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.normalizeScore();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/detection/score/normalize",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("dlqStats() calls GET /api/dlq/stats", async () => {
    const body = { count: 3, empty: false };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.dlqStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/dlq/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("dlq() calls GET /api/dlq", async () => {
    const body = {
      dead_letters: [
        {
          original_payload: "{bad-json}",
          errors: ["invalid JSON"],
          received_at: "2026-04-30T12:00:00Z",
          source_agent: "agent-7",
        },
      ],
      count: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.dlq();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/dlq",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("dlqClear() calls DELETE /api/dlq", async () => {
    const body = { cleared: 3 };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.dlqClear();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/dlq",
      expect.objectContaining({ method: "DELETE" })
    );
  });

  it("scanHash() sends POST with hash body", async () => {
    const scanResult = { verdict: "Clean", confidence: 1.0, matches: [] };
    const mock = mockFetch(200, scanResult);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.scanHash("abc123");
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/scan/hash",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ hash: "abc123" }),
      })
    );
  });

  it("scanBufferV2() sends the deep scan payload", async () => {
    const body = {
      scan: { verdict: "suspicious" },
      static_profile: {
        file_type: "pe",
        platform_hint: "windows",
        executable_format: true,
        archive_format: false,
        script_like: false,
        magic: "MZ",
        probable_signed: false,
        imports: ["CreateRemoteThread"],
        section_hints: [".text"],
        suspicious_traits: ["packer-like entropy"],
        analyst_summary: ["Executable with suspicious imports"],
      },
      behavior_profile: {
        observed_tactics: ["defense_evasion"],
        severity: "high",
        recommended_actions: ["Isolate host"],
      },
      analyst_summary: ["Deep scan raised ransomware-adjacent signals"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.scanBufferV2(
      "ZGF0YQ==",
      "payload.exe",
      {
        suspicious_process_tree: true,
        defense_evasion: true,
      },
      {
        trusted_publishers: ["Contoso Ltd"],
      }
    );
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/scan/buffer/v2",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          data: "ZGF0YQ==",
          filename: "payload.exe",
          behavior: {
            suspicious_process_tree: true,
            defense_evasion: true,
          },
          allowlist: {
            trusted_publishers: ["Contoso Ltd"],
          },
        }),
      })
    );
  });

  it("memoryIndicatorsScanMaps() posts the memory maps payload", async () => {
    const request = {
      pid: 4242,
      process_name: "python3",
      maps_content: "7f000000-7f001000 rwxp 00000000 00:00 0 [anon]",
    };
    const body = {
      pid: 4242,
      process_name: "python3",
      rwx_regions: 1,
      anonymous_executable: 1,
      reflective_dll_suspects: [],
      shellcode_patterns: [
        {
          pattern_name: "NOP_sled_x86",
          offset: "0x0000",
          size: 8,
          description: "x86 NOP sled (8+ consecutive NOPs)",
        },
      ],
      hollowing_suspected: false,
      total_regions_scanned: 14,
      risk_score: 0.75,
      indicators: ["rwx_region", "shellcode_signature"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.memoryIndicatorsScanMaps(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/memory-indicators/scan-maps",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("memoryIndicatorsScanBuffer() posts the plain text scan body", async () => {
    const body = [
      {
        pattern_name: "NOP_sled_x86",
        offset: "0x0000",
        size: 8,
        description: "x86 NOP sled (8+ consecutive NOPs)",
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.memoryIndicatorsScanBuffer(
      Uint8Array.from([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90])
    );
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/memory-indicators/scan-buffer",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "text/plain",
        }),
        body: "kJCQkJCQkJA=",
      })
    );
  });

  it("analystQuery() posts the analyst event search payload", async () => {
    const request = {
      text: "impossible travel",
      hostname: "host-7",
      level: "high",
      agent_id: "agent-7",
      from_ts: "2026-04-30T08:00:00Z",
      to_ts: "2026-04-30T09:00:00Z",
      limit: 25,
    };
    const body = {
      results: [
        {
          id: 42,
          agent_id: "agent-7",
          hostname: "host-7",
          score: 92,
          level: "high",
          timestamp: "2026-04-30T08:12:00Z",
          reasons: ["impossible travel", "mfa fatigue"],
          action: "flag",
        },
      ],
      count: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.analystQuery(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/events/search",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("search() sends query and default limit", async () => {
    const mock = mockFetch(200, { total: 0, hits: [], took_ms: 1, query: "x" });
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.search("process.name:cmd.exe");
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/search",
      expect.objectContaining({
        body: JSON.stringify({ query: "process.name:cmd.exe", limit: 50 }),
      })
    );
  });

  it("sigmaStats() calls GET /api/sigma/stats", async () => {
    const body = { total_rules: 128, engine_status: "active" };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.sigmaStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/sigma/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("exportAlerts() sends format query param", async () => {
    const mock = mockFetch(200, "CEF:0|...");
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.exportAlerts("cef");
    expect(result).toBe("CEF:0|...");
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/export/alerts?format=cef",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("exportTla() calls GET /api/export/tla", async () => {
    const mock = mockFetch(200, "---- MODULE Wardex ----");
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.exportTla();
    expect(result).toBe("---- MODULE Wardex ----");
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/export/tla",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("exportAlloy() calls GET /api/export/alloy", async () => {
    const mock = mockFetch(200, "module wardex {}");
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.exportAlloy();
    expect(result).toBe("module wardex {}");
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/export/alloy",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("exportWitnesses() calls GET /api/export/witnesses", async () => {
    const body = [
      {
        backend: "sha256",
        label: "policy-transition",
        pre_digest: "abc",
        post_digest: "def",
        timestamp: "2026-04-30T12:00:00Z",
        witness_hex: "deadbeef",
        proof_hex: null,
        verified: true,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.exportWitnesses();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/export/witnesses",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("complianceReport() with frameworkId adds query param", async () => {
    const mock = mockFetch(200, {});
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.complianceReport("cis-v8");
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/compliance/report?framework=cis-v8",
      expect.anything()
    );
  });

  it("complianceSummary() calls GET /api/compliance/summary", async () => {
    const body = {
      generated_at: "2026-04-30T12:00:00Z",
      overall_score: 83.5,
      frameworks: [
        {
          framework: "CIS Controls v8",
          score: 88.2,
          passed: 142,
          failed: 11,
          total: 153,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.complianceSummary();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/compliance/summary",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("complianceStatus() calls GET /api/compliance/status", async () => {
    const body = {
      framework_id: "iec62443",
      framework_name: "IEC 62443",
      generated_at: "2026-04-30T12:00:00Z",
      total_controls: 24,
      passed: 18,
      failed: 6,
      score_percent: 75,
      findings: [],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.complianceStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/compliance/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("runPlaybook() sends correct body", async () => {
    const execution = {
      execution_id: "exec-1",
      playbook_id: "pb-1",
      status: "running",
      started_at: 0,
      step_results: [],
    };
    const mock = mockFetch(200, execution);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.runPlaybook("pb-1", "alert-1", { target: "host-1" });
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/playbooks/run",
      expect.objectContaining({
        body: JSON.stringify({
          playbook_id: "pb-1",
          alert_id: "alert-1",
          variables: { target: "host-1" },
        }),
      })
    );
  });

  it("fleetInstalls() calls GET /api/fleet/installs", async () => {
    const body = { attempts: [], total: 0 };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.fleetInstalls();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/fleet/installs",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("fleetInstallSsh() posts the SSH remote install payload", async () => {
    const body = {
      id: "install-ssh-1",
      transport: "ssh",
      hostname: "edge-02",
      address: "10.0.4.12",
      platform: "linux",
      manager_url: "http://localhost:8080",
      ssh_user: "root",
      ssh_port: 22,
      ssh_accept_new_host_key: true,
      use_sudo: true,
      actor: "admin",
      status: "awaiting_heartbeat",
      started_at: "2026-04-29T11:30:00Z",
    };
    const mock = mockFetch(202, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.fleetInstallSsh({
      hostname: "edge-02",
      address: "10.0.4.12",
      platform: "linux",
      manager_url: "http://localhost:8080",
      ssh_user: "root",
      ssh_port: 22,
      use_sudo: true,
    });
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/fleet/install/ssh",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          hostname: "edge-02",
          address: "10.0.4.12",
          platform: "linux",
          manager_url: "http://localhost:8080",
          ssh_user: "root",
          ssh_port: 22,
          use_sudo: true,
        }),
      })
    );
  });

  it("fleetInstallWinrm() posts the WinRM remote install payload", async () => {
    const body = {
      id: "install-winrm-1",
      transport: "winrm",
      hostname: "win-02",
      address: "10.0.4.30",
      platform: "windows",
      manager_url: "http://localhost:8080",
      ssh_user: "",
      ssh_port: 0,
      ssh_accept_new_host_key: false,
      use_sudo: false,
      actor: "admin",
      status: "awaiting_heartbeat",
      started_at: "2026-04-29T11:35:00Z",
      winrm_username: "Administrator",
      winrm_port: 5985,
      winrm_use_tls: false,
      winrm_skip_cert_check: false,
    };
    const mock = mockFetch(202, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.fleetInstallWinrm({
      hostname: "win-02",
      address: "10.0.4.30",
      platform: "windows",
      manager_url: "http://localhost:8080",
      winrm_username: "Administrator",
      winrm_password: "Sup3rSecret!",
      winrm_port: 5985,
      winrm_use_tls: false,
    });
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/fleet/install/winrm",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          hostname: "win-02",
          address: "10.0.4.30",
          platform: "windows",
          manager_url: "http://localhost:8080",
          winrm_username: "Administrator",
          winrm_password: "Sup3rSecret!",
          winrm_port: 5985,
          winrm_use_tls: false,
        }),
      })
    );
  });

  it("processThreads() calls GET /api/processes/threads", async () => {
    const body = {
      pid: 4242,
      hostname: "edge-1",
      platform: "linux",
      identifier_type: "tid",
      thread_count: 2,
      running_count: 1,
      sleeping_count: 1,
      blocked_count: 0,
      hot_thread_count: 1,
      top_cpu_percent: 12.5,
      wait_reason_count: 0,
      hot_threads: [],
      blocked_threads: [],
      threads: [],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.processThreads(4242);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/processes/threads?pid=4242",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("hostApps() calls GET /api/host/apps", async () => {
    const body = {
      apps: [
        {
          name: "Wardex Agent",
          path: "/Applications/Wardex Agent.app",
          version: "0.55.1",
          bundle_id: "systems.minh.wardex.agent",
          size_mb: 42.5,
          last_modified: "2026-05-01T08:00:00Z",
        },
      ],
      count: 1,
      platform: "macos",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.hostApps();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/host/apps",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("hostInventory() calls GET /api/host/inventory", async () => {
    const body = {
      collected_at: "2026-05-01T08:15:00Z",
      hardware: {
        cpu_model: "Apple M4",
        cpu_cores: 10,
        total_ram_mb: 32768,
        disks: [
          {
            name: "disk0s2",
            size_gb: 494.2,
            mount_point: "/",
          },
        ],
      },
      software: [
        {
          name: "wardex-agent",
          version: "0.55.1",
          source: "pkgutil",
        },
      ],
      services: [
        {
          name: "wardex-agent",
          status: "running",
          pid: 4242,
        },
      ],
      network: [
        {
          protocol: "tcp",
          port: 8080,
          state: "LISTEN",
          process: "wardex",
        },
      ],
      users: [
        {
          username: "analyst",
          uid: 501,
          groups: ["staff"],
          last_login: null,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.hostInventory();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/host/inventory",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("processTree() calls GET /api/process-tree", async () => {
    const body = {
      processes: [
        {
          pid: 1,
          ppid: 0,
          name: "launchd",
          cmd_line: "launchd",
          user: "root",
          exe_path: "/sbin/launchd",
          hostname: "edge-1",
          start_time: "2026-04-29T10:00:00Z",
          alive: true,
        },
      ],
      count: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.processTree();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/process-tree",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("processesLive() calls GET /api/processes/live", async () => {
    const body = {
      processes: [
        {
          pid: 4242,
          ppid: 321,
          name: "python3",
          user: "analyst",
          group: "staff",
          cpu_percent: 12.4,
          mem_percent: 3.2,
        },
      ],
      count: 1,
      total_cpu_percent: 12.4,
      total_mem_percent: 3.2,
      platform: "linux",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.processesLive();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/processes/live",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("processesAnalysis() calls GET /api/processes/analysis", async () => {
    const body = {
      findings: [
        {
          pid: 4242,
          name: "python3",
          user: "analyst",
          risk_level: "severe",
          reason: "Suspicious parent chain",
          cpu_percent: 12.4,
          mem_percent: 3.2,
        },
      ],
      total: 1,
      risk_summary: {
        critical: 0,
        severe: 1,
        elevated: 0,
      },
      process_count: 64,
      status: "warning",
      platform: "linux",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.processesAnalysis();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/processes/analysis",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("auditLogs() calls GET /api/audit/log with page parameters", async () => {
    const body = {
      entries: [
        {
          timestamp: "2026-04-30T20:10:00Z",
          method: "POST",
          path: "/api/incidents",
          source_ip: "127.0.0.1",
          status_code: 200,
          auth_used: true,
        },
      ],
      total: 1,
      offset: 0,
      limit: 25,
      count: 1,
      has_more: false,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.auditLogs(25);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/audit/log?limit=25&offset=0",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("deepChains() calls GET /api/process-tree/deep-chains", async () => {
    const body = {
      deep_chains: [
        {
          pid: 4242,
          name: "python3",
          cmd_line: "/usr/bin/python3 suspicious.py",
          depth: 4,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.deepChains();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/process-tree/deep-chains",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("processDetail() calls GET /api/processes/detail", async () => {
    const body = {
      pid: 4242,
      ppid: 321,
      name: "/usr/bin/python3",
      display_name: "python3",
      user: "analyst",
      group: "staff",
      cpu_percent: 12.4,
      mem_percent: 3.2,
      hostname: "edge-1",
      platform: "linux",
      cmd_line: "/usr/bin/python3 suspicious.py",
      exe_path: "/usr/bin/python3",
      cwd: "/tmp",
      start_time: null,
      elapsed: null,
      risk_level: "severe",
      findings: [
        {
          pid: 4242,
          name: "python3",
          user: "analyst",
          risk_level: "severe",
          reason: "Suspicious parent chain",
          cpu_percent: 12.4,
          mem_percent: 3.2,
        },
      ],
      network_activity: [
        { protocol: "tcp", endpoint: "10.0.0.1:443", state: "ESTABLISHED" },
      ],
      code_signature: { status: "unavailable" },
      analysis: {
        self_process: false,
        listener_count: 1,
        recommendations: ["Inspect parent lineage before isolation."],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.processDetail(4242);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/processes/detail?pid=4242",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("uebaObserve() posts a behavior observation payload", async () => {
    const body = {
      anomalies: [
        {
          anomaly_type: "UnusualLoginTime",
          entity_kind: "User",
          entity_id: "user-a",
          score: 72.5,
          description: "Observed an unusual login time for user-a.",
          timestamp_ms: 1714392000000,
          evidence: ["hour_of_day=3"],
          mitre_technique: null,
        },
      ],
    };
    const observation = {
      timestamp_ms: 1714392000000,
      entity_kind: "User" as const,
      entity_id: "user-a",
      hour_of_day: 3,
      peer_group: "engineering",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.uebaObserve(observation);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ueba/observe",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(observation),
      })
    );
  });

  it("uebaRiskyEntities() calls GET /api/ueba/risky", async () => {
    const body = [
      {
        entity_kind: "User",
        entity_id: "user-a",
        risk_score: 24.5,
        observation_count: 12,
        last_seen_ms: 1714392000000,
        anomaly_count: 2,
        peer_group: "engineering",
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.uebaRiskyEntities();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ueba/risky",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("uebaEntity() calls GET /api/ueba/entity/:id", async () => {
    const body = {
      entity_kind: "User",
      entity_id: "user-a",
      risk_score: 24.5,
      observation_count: 12,
      last_seen_ms: 1714392000000,
      anomaly_count: 2,
      peer_group: "engineering",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.uebaEntity("user-a");
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ueba/entity/user-a",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("ndrBeaconing() calls GET /api/ndr/beaconing", async () => {
    const body = [
      {
        src_addr: "10.0.0.10",
        dst_addr: "198.51.100.20",
        dst_port: 443,
        protocol: "tcp",
        avg_interval_ms: 60000,
        jitter_pct: 0.08,
        total_bytes: 8192,
        flow_count: 12,
        risk_score: 74.2,
        reason: "Consistent outbound cadence detected over repeated intervals.",
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.ndrBeaconing();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ndr/beaconing",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("ndrProtocolDistribution() calls GET /api/ndr/protocol-distribution", async () => {
    const body = [
      {
        protocol: "HTTPS",
        flow_count: 32,
        total_bytes: 1048576,
        encrypted_ratio: 1,
      },
      {
        protocol: "DNS",
        flow_count: 12,
        total_bytes: 16384,
        encrypted_ratio: 0,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.ndrProtocolDistribution();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ndr/protocol-distribution",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("ndrSelfSignedCerts() calls GET /api/ndr/self-signed-certs", async () => {
    const body = [
      {
        dst_addr: "198.51.100.20",
        dst_port: 443,
        tls_sni: "c2.bad.test",
        tls_issuer: "CN=c2.bad.test",
        tls_subject: "CN=c2.bad.test",
        flow_count: 6,
        risk_score: 8.4,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.ndrSelfSignedCerts();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ndr/self-signed-certs",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("ndrTopTalkers() calls GET /api/ndr/top-talkers and slices client-side", async () => {
    const body = [
      {
        addr: "10.0.0.10",
        total_bytes: 5242880,
        flow_count: 14,
        unique_destinations: 5,
        protocols: ["HTTPS", "DNS"],
      },
      {
        addr: "10.0.0.11",
        total_bytes: 1048576,
        flow_count: 8,
        unique_destinations: 3,
        protocols: ["SSH"],
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.ndrTopTalkers(1);
    expect(result).toEqual([body[0]]);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ndr/top-talkers",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("ndrTlsAnomalies() calls GET /api/ndr/tls-anomalies", async () => {
    const body = [
      {
        ja3_hash: "ja3bad",
        ja4_fingerprint: "ja4bad",
        src_addr: "10.0.0.12",
        dst_addr: "198.51.100.30",
        dst_port: 443,
        tls_sni: "suspicious.bad.test",
        tls_version: "TLS1.2",
        risk_score: 9.1,
        reason: "Known-malicious JA3 fingerprint",
        flow_count: 4,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.ndrTlsAnomalies();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ndr/tls-anomalies",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("ndrDpiAnomalies() calls GET /api/ndr/dpi-anomalies", async () => {
    const body = [
      {
        src_addr: "10.0.0.13",
        dst_addr: "198.51.100.31",
        dst_port: 8443,
        expected_protocol: "HTTPS",
        detected_protocol: "SSH",
        risk_score: 7.8,
        flow_count: 3,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.ndrDpiAnomalies();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ndr/dpi-anomalies",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("ndrEntropyAnomalies() calls GET /api/ndr/entropy-anomalies", async () => {
    const body = [
      {
        src_addr: "10.0.0.14",
        dst_addr: "198.51.100.32",
        dst_port: 9443,
        avg_entropy: 7.92,
        total_bytes: 262144,
        flow_count: 5,
        risk_score: 8.2,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.ndrEntropyAnomalies();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ndr/entropy-anomalies",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("ndrReport() calls GET /api/ndr/report", async () => {
    const body = {
      analysis_timestamp: "2026-04-30T17:00:00Z",
      total_flows_analysed: 42,
      total_bytes: 7340032,
      top_talkers: [
        {
          addr: "10.0.0.10",
          total_bytes: 5242880,
          flow_count: 14,
          unique_destinations: 5,
          protocols: ["HTTPS", "DNS"],
        },
      ],
      unusual_destinations: [
        {
          dst_addr: "198.51.100.40",
          dst_port: 8443,
          total_bytes: 1048576,
          flow_count: 3,
          first_seen_ms: 1710000000123,
          risk_score: 8.6,
          reason: "Large encrypted transfer to a new external destination",
        },
      ],
      protocol_anomalies: [
        {
          protocol: "SSH",
          port: 443,
          expected_protocol: "HTTPS",
          flow_count: 2,
          risk_score: 7.3,
        },
      ],
      encrypted_traffic: {
        total_flows: 42,
        encrypted_flows: 37,
        encrypted_ratio: 0.88,
        encrypted_bytes: 6291456,
        total_bytes: 7340032,
      },
      unique_external_destinations: 9,
      connections_per_second: 1.4,
      dns_threats: [
        {
          domain: "dga-bad-example.xyz",
          dga_score: 0.91,
          tunnel_score: 0.12,
          fast_flux_score: 0.33,
          verdict: "Suspicious",
          indicators: ["long SLD (15 chars)", "high-risk TLD"],
          tld_risk: 0.6,
          overall_score: 0.74,
          doh_bypass_detected: false,
        },
      ],
      tls_anomalies: [],
      dpi_anomalies: [],
      entropy_anomalies: [],
      beaconing_anomalies: [],
      self_signed_certs: [],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.ndrReport();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ndr/report",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("ndrIngest() posts the structured netflow payload", async () => {
    const payload = {
      timestamp_ms: 1710000000000,
      src_addr: "10.0.0.15",
      src_port: 51514,
      dst_addr: "198.51.100.33",
      dst_port: 443,
      protocol: "TCP",
      bytes_sent: 16384,
      bytes_received: 32768,
      packets: 42,
      duration_ms: 1800,
      hostname: "workstation-15",
      is_encrypted: true,
      ja3_hash: "0123456789abcdef0123456789abcdef",
      ja4_fingerprint: "t13d1516h2_8daaf6152771_b186095e22b6",
      tls_sni: "api.partner.test",
      tls_version: "TLSv1.3",
      tls_self_signed: false,
      payload_entropy: 7.41,
      dpi_protocol: "HTTP/2",
    };
    const body = { status: "ingested" };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.ndrIngest(payload);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ndr/netflow",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
      })
    );
  });

  it("listIncidents() calls GET /api/incidents", async () => {
    const body = [
      {
        id: 42,
        title: "Suspicious lateral movement",
        severity: "high",
        status: "Open",
        created_at: "2026-04-30T18:00:00Z",
        updated_at: "2026-04-30T18:05:00Z",
        event_ids: [101, 102],
        agent_ids: ["agent-7"],
        mitre_techniques: [
          {
            tactic: "Lateral Movement",
            technique_id: "T1021",
            technique_name: "Remote Services",
          },
        ],
        summary: "Multiple remote service pivots detected.",
        assignee: null,
        notes: [],
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.listIncidents();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/incidents",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("getIncident() calls GET /api/incidents/:id", async () => {
    const body = {
      id: 42,
      title: "Suspicious lateral movement",
      severity: "high",
      status: "Investigating",
      created_at: "2026-04-30T18:00:00Z",
      updated_at: "2026-04-30T18:07:00Z",
      event_ids: [101, 102],
      agent_ids: ["agent-7"],
      mitre_techniques: [
        {
          tactic: "Lateral Movement",
          technique_id: "T1021",
          technique_name: "Remote Services",
        },
      ],
      summary: "Multiple remote service pivots detected.",
      assignee: "analyst-1",
      notes: [
        {
          author: "analyst-1",
          timestamp: "2026-04-30T18:06:00Z",
          text: "Investigating remote service execution chain.",
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.getIncident("42");
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/incidents/42",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("createIncident() posts a backend-compatible incident payload", async () => {
    const body = {
      id: 43,
      title: "Suspicious lateral movement",
      severity: "high",
      status: "Open",
      created_at: "2026-04-30T18:10:00Z",
      updated_at: "2026-04-30T18:10:00Z",
      event_ids: [101, 102],
      agent_ids: ["agent-7"],
      mitre_techniques: [],
      summary: "Investigate host drift",
      assignee: null,
      notes: [],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.createIncident(
      "Suspicious lateral movement",
      "high",
      "Investigate host drift",
      { event_ids: [101, 102], agent_ids: ["agent-7"] }
    );
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/incidents",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          title: "Suspicious lateral movement",
          severity: "high",
          summary: "Investigate host drift",
          event_ids: [101, 102],
          agent_ids: ["agent-7"],
        }),
      })
    );
  });

  it("listAgents() calls GET /api/agents", async () => {
    const body = [
      {
        id: "local-console",
        hostname: "sentineledge.local",
        platform: "aarch64-apple-darwin",
        version: "0.55.1",
        current_version: "0.55.1",
        enrolled_at: "2026-04-30T19:00:00Z",
        last_seen: "2026-04-30T19:05:00Z",
        last_seen_age_secs: 0,
        status: "online",
        labels: { local_console: "true", role: "control-plane" },
        health: {
          pending_alerts: 2,
          telemetry_queue_depth: 14,
          update_state: null,
          update_target_version: null,
          last_update_error: null,
          last_update_at: null,
        },
        pending_alerts: 2,
        telemetry_queue_depth: 14,
        target_version: null,
        rollout_group: null,
        deployment_status: null,
        scope_override: false,
        local_console: true,
        local_monitoring: true,
        source: "local",
        os_version: "macOS 15.4",
        arch: "arm64",
        telemetry_samples: 128,
        process_count: 312,
        inventory_available: true,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.listAgents();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/agents",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("getAgent() calls GET /api/agents/:id/details", async () => {
    const body = {
      agent: {
        id: "agent-7",
        hostname: "prod-web-01",
        platform: "linux",
        version: "0.55.1",
        enrolled_at: "2026-04-30T18:00:00Z",
        last_seen: "2026-04-30T20:00:00Z",
        status: "online",
        labels: { role: "web" },
        health: {
          pending_alerts: 2,
          telemetry_queue_depth: 8,
          update_state: "pending",
          update_target_version: "0.55.2",
          last_update_error: null,
          last_update_at: "2026-04-30T19:45:00Z",
        },
        monitor_scope: {
          cpu_load: true,
          memory_pressure: true,
          network_activity: true,
          disk_pressure: true,
          process_activity: true,
          auth_events: true,
          thermal_state: false,
          battery_state: false,
          file_integrity: true,
          service_persistence: true,
          launch_agents: false,
          systemd_units: true,
          scheduled_tasks: false,
        },
      },
      local_console: false,
      computed_status: "online",
      heartbeat_age_secs: 12,
      deployment: {
        agent_id: "agent-7",
        version: "0.55.2",
        platform: "linux",
        mandatory: false,
        release_notes: "Security fixes",
        status: "assigned",
        status_reason: null,
        rollout_group: "stable",
        allow_downgrade: false,
        assigned_at: "2026-04-30T19:30:00Z",
        acknowledged_at: null,
        completed_at: null,
        last_heartbeat_at: "2026-04-30T20:00:00Z",
      },
      scope_override: true,
      effective_scope: {
        cpu_load: true,
        memory_pressure: true,
        network_activity: true,
        disk_pressure: true,
        process_activity: true,
        auth_events: true,
        thermal_state: false,
        battery_state: false,
        file_integrity: true,
        service_persistence: true,
        launch_agents: false,
        systemd_units: true,
        scheduled_tasks: false,
      },
      health: {
        pending_alerts: 2,
        telemetry_queue_depth: 8,
        update_state: "pending",
        update_target_version: "0.55.2",
        last_update_error: null,
        last_update_at: "2026-04-30T19:45:00Z",
      },
      analytics: {
        event_count: 14,
        correlated_count: 5,
        critical_count: 1,
        average_score: 6.2,
        max_score: 9.4,
        highest_level: "Critical",
        risk: "high",
        top_reasons: ["credential reuse", "remote service pivot"],
      },
      timeline: [
        {
          event_id: 101,
          received_at: "2026-04-30T19:58:00Z",
          level: "Critical",
          score: 9.4,
          correlated: true,
          reasons: ["credential reuse"],
          action: "isolate",
          triage: { status: "pending_review" },
        },
      ],
      risk_transitions: [
        {
          event_id: 101,
          received_at: "2026-04-30T19:58:00Z",
          from: "Elevated",
          to: "Critical",
        },
      ],
      inventory: {
        collected_at: "2026-04-30T19:50:00Z",
        software_count: 84,
        services_count: 26,
        network_ports: 18,
        users_count: 9,
        hardware: {
          cpu_model: "Apple M4",
          cpu_cores: 10,
          total_ram_mb: 32768,
          disks: [
            {
              name: "disk0s2",
              size_gb: 494.2,
              mount_point: "/",
            },
          ],
        },
      },
      log_summary: {
        total_records: 19,
        last_timestamp: "2026-04-30T19:59:30Z",
        by_level: { Info: 16, Warn: 2, Error: 1 },
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.getAgent("agent-7");
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/agents/agent-7/details",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("ingestEvents() posts the backend event batch payload", async () => {
    const events = [
      {
        timestamp: "2026-04-30T20:10:00Z",
        hostname: "prod-web-01",
        platform: "linux",
        score: 8.7,
        confidence: 0.96,
        level: "Critical",
        action: "isolate",
        reasons: ["credential reuse", "remote service pivot"],
        sample: {
          timestamp_ms: 1714507800000,
          cpu_load_pct: 82.4,
          memory_load_pct: 74.1,
          temperature_c: 61.2,
          network_kbps: 4200.5,
          auth_failures: 18,
          battery_pct: 100,
          integrity_drift: 0.12,
          process_count: 276,
          disk_pressure_pct: 33.5,
        },
        enforced: true,
        mitre: [
          {
            tactic: "Credential Access",
            technique: "Brute Force",
            technique_id: "T1110",
            technique_name: "Brute Force",
          },
        ],
        narrative: {
          headline: "Credential pivot detected",
          summary: "The host shows repeated auth failures followed by lateral activity.",
          observations: ["Authentication failures spiked", "Remote service access followed"],
          baseline_comparison: "Auth failures are 6x above baseline.",
          time_window: "5m",
          involved_entities: ["prod-web-01", "prod-db-01"],
          suggested_queries: ["search auth failures for prod-web-01"],
        },
      },
    ];
    const body = {
      ingested: 1,
      total: 42,
      correlations: [
        {
          reason: "credential reuse",
          agents: ["agent-7", "agent-9"],
          event_ids: [101, 109],
          severity: "Critical",
          description: "Related credential reuse alerts across multiple agents.",
        },
      ],
      sigma_matches: 2,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.ingestEvents("agent-7", events);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/events",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ agent_id: "agent-7", events }),
      })
    );
  });

  it("openApiSpec() calls GET /api/openapi.json", async () => {
    const body = {
      openapi: "3.0.3",
      info: {
        title: "Wardex API",
        version: "0.55.1",
        description: "Machine-readable REST API contract.",
        license: { name: "MIT", url: "https://example.test/license" },
        contact: { name: "Wardex", url: "https://example.test/support" },
      },
      servers: [{ url: "https://api.example.test", description: "Production" }],
      paths: {
        "/api/openapi.json": {
          get: {
            summary: "OpenAPI specification (JSON)",
          },
        },
      },
      components: {
        schemas: {
          Example: { type: "object" },
        },
      },
      security: [{ BearerAuth: [] }],
      tags: [{ name: "OpenAPI", description: "OpenAPI specification routes" }],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.openApiSpec();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/openapi.json",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("assets() calls GET /api/assets", async () => {
    const body = [
      {
        id: "asset-1",
        name: "prod-web-01",
        asset_type: "OnPremHost",
        cloud_provider: "None",
        region: null,
        account_id: null,
        hostname: "prod-web-01",
        ip_addresses: ["10.0.0.21"],
        os: "Linux",
        agent_id: "agent-7",
        owner: "alice@example.com",
        tags: { env: "prod", role: "web" },
        risk_score: 7.5,
        status: "Active",
        first_seen: "2026-04-29T08:00:00Z",
        last_seen: "2026-04-30T20:00:00Z",
        metadata: { kernel: "6.8.0" },
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.assets();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/assets",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("assetsSearch() calls GET /api/assets/search with query", async () => {
    const body = [
      {
        id: "asset-1",
        name: "prod-web-01",
        asset_type: "OnPremHost",
        cloud_provider: "None",
        region: null,
        account_id: null,
        hostname: "prod-web-01",
        ip_addresses: ["10.0.0.21"],
        os: "Linux",
        agent_id: "agent-7",
        owner: "alice@example.com",
        tags: { env: "prod", role: "web" },
        risk_score: 7.5,
        status: "Active",
        first_seen: "2026-04-29T08:00:00Z",
        last_seen: "2026-04-30T20:00:00Z",
        metadata: { kernel: "6.8.0" },
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.assetsSearch("prod/web 01");
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/assets/search?q=prod%2Fweb%2001",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("upsertAsset() posts the unified asset payload", async () => {
    const payload = {
      id: "asset-2",
      name: "prod-db-01",
      asset_type: "Database" as const,
      cloud_provider: "Aws" as const,
      region: "eu-central-1",
      account_id: "123456789012",
      hostname: "prod-db-01",
      ip_addresses: ["10.0.1.10"],
      os: "Amazon Linux 2023",
      agent_id: null,
      owner: "db-team@example.com",
      tags: { env: "prod", service: "orders" },
      risk_score: 8.1,
      status: "Active" as const,
      first_seen: "2026-04-28T08:00:00Z",
      last_seen: "2026-04-30T20:05:00Z",
      metadata: { engine: "postgres", version: "16" },
    };
    const body = { status: "upserted" };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.upsertAsset(payload);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/assets/upsert",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
      })
    );
  });

  it("assetsSummary() calls GET /api/assets/summary", async () => {
    const body = {
      total_assets: 18,
      by_type: { OnPremHost: 10, CloudVm: 6, Database: 2 },
      by_provider: { None: 10, Aws: 6, Azure: 2 },
      by_status: { Active: 16, Inactive: 1, Unknown: 1 },
      high_risk_count: 4,
      unmanaged_count: 3,
      average_risk: 5.42,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.assetsSummary();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/assets/summary",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("lifecycle() calls GET /api/lifecycle", async () => {
    const body = [
      {
        agent_id: "agent-1",
        hostname: "prod-web-01",
        state: "Active",
        last_heartbeat: "2026-05-01T10:00:00Z",
        state_changed_at: "2026-05-01T09:00:00Z",
        notes: null,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.lifecycle();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/lifecycle",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("lifecycleStats() calls GET /api/lifecycle/stats", async () => {
    const body = {
      total_agents: 1,
      active: 1,
      stale: 0,
      offline: 0,
      archived: 0,
      decommissioned: 0,
      transitions: [],
      timestamp: "2026-05-01T10:00:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.lifecycleStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/lifecycle/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("lifecycleSweep() calls POST /api/lifecycle/sweep", async () => {
    const body = {
      total_agents: 1,
      active: 0,
      stale: 1,
      offline: 0,
      archived: 0,
      decommissioned: 0,
      transitions: [
        {
          agent_id: "agent-1",
          from: "Active",
          to: "Stale",
          reason: "auto-sweep: 301s since last heartbeat",
        },
      ],
      timestamp: "2026-05-01T10:00:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.lifecycleSweep();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/lifecycle/sweep",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("iocDecayApply() calls POST /api/ioc-decay/apply", async () => {
    const body = {
      iocs_processed: 3,
      iocs_decayed: 2,
      iocs_removed: 1,
      avg_confidence_before: 0.7,
      avg_confidence_after: 0.42,
      timestamp: "2026-05-01T10:00:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.iocDecayApply();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ioc-decay/apply",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("iocDecayPreview() calls GET /api/ioc-decay/preview", async () => {
    const body = [
      {
        value: "198.51.100.10",
        ioc_type: "Ip",
        original_confidence: 0.8,
        decayed_confidence: 0.65,
        last_seen: "2026-04-01T10:00:00Z",
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.iocDecayPreview();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/ioc-decay/preview",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("certsRegister() posts a certificate record", async () => {
    const certificate = {
      hostname: "api.example.com",
      port: 443,
      subject: "CN=api.example.com",
      issuer: "CN=Example CA",
      serial_number: "01AB",
      not_before: "2026-01-01T00:00:00Z",
      not_after: "2026-12-31T23:59:59Z",
      days_until_expiry: 244,
      fingerprint_sha256: "abc123",
      san_domains: ["api.example.com"],
      key_algorithm: "RSA",
      key_size_bits: 2048,
      is_self_signed: false,
      is_expired: false,
      is_expiring_soon: false,
      agent_id: "agent-1",
      discovered_at: "2026-05-01T10:00:00Z",
    };
    const body = { status: "registered" };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.certsRegister(certificate);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/certs/register",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(certificate),
      })
    );
  });

  it("certsSummary() calls GET /api/certs/summary", async () => {
    const certificate = {
      hostname: "api.example.com",
      port: 443,
      subject: "CN=api.example.com",
      issuer: "CN=Example CA",
      serial_number: "01AB",
      not_before: "2026-01-01T00:00:00Z",
      not_after: "2026-12-31T23:59:59Z",
      days_until_expiry: 244,
      fingerprint_sha256: "abc123",
      san_domains: ["api.example.com"],
      key_algorithm: "RSA",
      key_size_bits: 2048,
      is_self_signed: false,
      is_expired: false,
      is_expiring_soon: false,
      agent_id: "agent-1",
      discovered_at: "2026-05-01T10:00:00Z",
    };
    const body = {
      total_certificates: 1,
      valid: 1,
      expiring_30d: 0,
      expiring_7d: 0,
      expired: 0,
      self_signed: 0,
      weak_key: 0,
      alerts: [],
      certificates: [certificate],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.certsSummary();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/certs/summary",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("certsAlerts() calls GET /api/certs/alerts", async () => {
    const body = [
      {
        certificate: {
          hostname: "api.example.com",
          port: 443,
          subject: "CN=api.example.com",
          issuer: "CN=Example CA",
          serial_number: "01AB",
          not_before: "2026-01-01T00:00:00Z",
          not_after: "2026-05-08T00:00:00Z",
          days_until_expiry: 7,
          fingerprint_sha256: "abc123",
          san_domains: ["api.example.com"],
          key_algorithm: "RSA",
          key_size_bits: 2048,
          is_self_signed: false,
          is_expired: false,
          is_expiring_soon: true,
          agent_id: "agent-1",
          discovered_at: "2026-05-01T10:00:00Z",
        },
        health: "ExpiringSoon",
        severity: "warning",
        message: "Certificate expires soon",
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.certsAlerts();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/certs/alerts",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("quarantineList() calls GET /api/quarantine", async () => {
    const body = [
      {
        id: "q-1",
        original_path: "/tmp/eicar.bin",
        filename: "eicar.bin",
        sha256: "abc123",
        md5: "def456",
        size_bytes: 68,
        quarantined_at: "2026-05-01T10:00:00Z",
        agent_id: "agent-1",
        hostname: "prod-web-01",
        verdict: "suspicious",
        malware_family: "eicar",
        scan_matches: ["EICAR-Test-File"],
        status: "Quarantined",
        analyst_notes: null,
        released_at: null,
        released_by: null,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.quarantineList();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/quarantine",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("quarantineAdd() posts the quarantine request", async () => {
    const request = {
      path: "/tmp/eicar.bin",
      agent_id: "agent-1",
      hostname: "prod-web-01",
      verdict: "suspicious",
      malware_family: "eicar",
    };
    const body = { id: "q-1" };
    const mock = mockFetch(201, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.quarantineAdd(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/quarantine",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("quarantineStats() calls GET /api/quarantine/stats", async () => {
    const body = {
      total_files: 1,
      quarantined: 1,
      under_analysis: 0,
      confirmed_malicious: 0,
      false_positives: 0,
      released: 0,
      total_size_bytes: 68,
      families: ["eicar"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.quarantineStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/quarantine/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("quarantineRelease() calls POST /api/quarantine/:id/release", async () => {
    const body = { released: true };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.quarantineRelease("q/1");
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/quarantine/q%2F1/release",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("quarantineDelete() handles DELETE /api/quarantine/:id 204 responses", async () => {
    const mock = mockFetch(204, undefined);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.quarantineDelete("q/1");
    expect(result).toBeUndefined();
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/quarantine/q%2F1",
      expect.objectContaining({ method: "DELETE" })
    );
  });

  it("entropyAnalyze() posts raw text for entropy analysis", async () => {
    const sample = "AAAAABBBBBCCCCCDDDDDEEEEE";
    const body = {
      overall_entropy: 2.3,
      sections: [
        {
          name: "whole_file",
          offset: 0,
          size: sample.length,
          entropy: 2.3,
          suspicious: false,
        },
      ],
      is_packed: false,
      packer_hint: null,
      suspicious: false,
      high_entropy_ratio: 0,
      file_size: sample.length,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.entropyAnalyze(sample);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/entropy/analyze",
      expect.objectContaining({
        method: "POST",
        body: sample,
        headers: expect.objectContaining({
          "Content-Type": "text/plain",
        }),
      })
    );
  });

  it("dnsThreatAnalyze() posts a domain request", async () => {
    const body = {
      domain: "example.tk",
      dga_score: 0.2,
      tunnel_score: 0.1,
      fast_flux_score: 0,
      verdict: "Suspicious",
      indicators: ["high-risk-tld"],
      tld_risk: 0.8,
      overall_score: 0.42,
      doh_bypass_detected: false,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.dnsThreatAnalyze("example.tk");
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/dns-threat/analyze",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ domain: "example.tk" }),
      })
    );
  });

  it("dnsThreatSummary() calls GET /api/dns-threat/summary", async () => {
    const report = {
      domain: "example.tk",
      dga_score: 0.2,
      tunnel_score: 0.1,
      fast_flux_score: 0,
      verdict: "Suspicious",
      indicators: ["high-risk-tld"],
      tld_risk: 0.8,
      overall_score: 0.42,
      doh_bypass_detected: false,
    };
    const body = {
      total_queries_analyzed: 4,
      suspicious_domains: [report],
      dga_candidates: 1,
      tunnel_candidates: 0,
      fast_flux_candidates: 0,
      top_queried: [["example.tk", 3]],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.dnsThreatSummary();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/dns-threat/summary",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("dnsThreatRecord() posts a DNS query", async () => {
    const query = {
      domain: "example.tk",
      query_type: "A",
      response_ips: ["203.0.113.10"],
      ttl: 60,
      timestamp: "2026-05-01T10:00:00Z",
      response_size: 128,
    };
    const body = { status: "recorded" };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.dnsThreatRecord(query);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/dns-threat/record",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(query),
      })
    );
  });

  it("images() calls GET /api/images", async () => {
    const body = [
      {
        id: "sha256:abc123",
        repository: "registry.example.com/wardex/agent",
        tag: "0.55.1",
        digest: "sha256:abc123",
        size_mb: 128.5,
        created: "2026-05-01T10:00:00Z",
        labels: { app: "wardex" },
        base_image: "debian:bookworm-slim",
        layers: 12,
        risk_score: 0.2,
        scan_status: "Clean",
        vulnerabilities: [],
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.images();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/images",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("imagesSummary() calls GET /api/images/summary", async () => {
    const body = {
      total_images: 1,
      scanned: 1,
      clean: 1,
      suspicious: 0,
      malicious: 0,
      total_vulnerabilities: 0,
      critical_vulns: 0,
      registries: ["registry.example.com"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.imagesSummary();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/images/summary",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("imagesCollect() calls POST /api/images/collect", async () => {
    const body = [
      {
        id: "sha256:abc123",
        repository: "registry.example.com/wardex/agent",
        tag: "0.55.1",
        digest: "sha256:abc123",
        size_mb: 128.5,
        created: "2026-05-01T10:00:00Z",
        labels: { app: "wardex" },
        base_image: "debian:bookworm-slim",
        layers: 12,
        risk_score: 0.2,
        scan_status: "Clean",
        vulnerabilities: [],
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.imagesCollect();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/images/collect",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("configDriftCheck() posts host config maps", async () => {
    const request = {
      host_id: "edge-1",
      configs: {
        "/etc/ssh/sshd_config": {
          PermitRootLogin: "yes",
          PasswordAuthentication: "yes",
        },
      },
    };
    const body = {
      host_id: "edge-1",
      scan_timestamp: "2026-05-01T10:00:00Z",
      baselines_checked: 2,
      drifts_found: 1,
      critical_drifts: 1,
      high_drifts: 0,
      changes: [
        {
          path: "/etc/ssh/sshd_config",
          category: "SshServer",
          key: "PermitRootLogin",
          expected: "no",
          actual: "yes",
          severity: "Critical",
          host_id: "edge-1",
          detected_at: "2026-05-01T10:00:00Z",
          mitre_techniques: ["T1021"],
        },
      ],
      compliant: false,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.configDriftCheck(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/config-drift/check",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("configDriftBaselines() calls GET /api/config-drift/baselines", async () => {
    const body = {
      total_hosts_scanned: 2,
      compliant_hosts: 1,
      non_compliant_hosts: 1,
      compliance_pct: 50,
      total_drifts: 3,
      critical_drifts: 1,
      baselines: 9,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.configDriftBaselines();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/config-drift/baselines",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("coverageGaps() calls GET /api/coverage/gaps", async () => {
    const body = {
      total_techniques: 12,
      covered: 8,
      uncovered: 4,
      coverage_pct: 66.7,
      gaps: [
        {
          technique_id: "T1059",
          technique_name: "Command and Scripting Interpreter",
          tactic: "execution",
          priority: "Critical",
          recommendation: "Add Sigma rules for shell usage",
          suggested_sources: ["process_creation"],
        },
      ],
      by_tactic: [
        {
          tactic: "execution",
          total: 3,
          covered: 2,
          uncovered: 1,
          pct: 66.7,
          gap_ids: ["T1059"],
        },
      ],
      top_recommendations: ["[T1059] Add command-line coverage"],
      generated_at: "2026-05-01T10:00:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.coverageGaps();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/coverage/gaps",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("detectorSlowAttack() calls GET /api/detectors/slow-attack", async () => {
    const body = {
      score: 3.8,
      alert: true,
      cumulative_auth_failures: 120,
      auth_failure_rate: 1.2,
      cumulative_network_kb: 640000,
      samples_observed: 1440,
      patterns: ["cumulative_auth_failures:120"],
      mitre_techniques: ["T1110"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.detectorSlowAttack();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/detectors/slow-attack",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("detectorRansomware() calls GET /api/detectors/ransomware", async () => {
    const body = {
      score: 6.4,
      alert: true,
      velocity: 70.2,
      extension_changes: 14,
      canaries_triggered: 1,
      canaries_total: 2,
      fim_drift: 0.3,
      contributions: [
        {
          signal: "file_velocity",
          raw_value: 70.2,
          weighted: 3.5,
        },
      ],
      mitre_techniques: ["T1486"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.detectorRansomware();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/detectors/ransomware",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("retentionStatus() calls GET /api/retention/status", async () => {
    const body = {
      audit_max_records: 10000,
      alert_max_records: 5000,
      event_max_records: 100000,
      audit_max_age_secs: 2592000,
      remote_syslog_endpoint: null,
      current_counts: {
        audit_entries: 42,
        alerts: 7,
        events: 900,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.retentionStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/retention/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("retentionApply() calls POST /api/retention/apply", async () => {
    const body = {
      status: "applied",
      trimmed_alerts: 3,
      trimmed_events: 25,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.retentionApply();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/retention/apply",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("evidencePlanLinux() calls GET /api/evidence/plan/linux", async () => {
    const body = {
      platform: "linux",
      artifacts: [
        {
          name: "process_list",
          path: "/proc",
          description: "Running processes and open fds",
          volatile: true,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.evidencePlanLinux();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/evidence/plan/linux",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("evidencePlanMacos() calls GET /api/evidence/plan/macos", async () => {
    const body = {
      platform: "macos",
      artifacts: [
        {
          name: "tcc_db",
          path: "/Library/Application Support/com.apple.TCC/TCC.db",
          description: "TCC permissions database",
          volatile: false,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.evidencePlanMacos();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/evidence/plan/macos",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("evidencePlanWindows() calls GET /api/evidence/plan/windows", async () => {
    const body = {
      platform: "windows",
      artifacts: [
        {
          name: "security_evtx",
          path: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
          description: "Security event log",
          volatile: false,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.evidencePlanWindows();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/evidence/plan/windows",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("campaigns() calls GET /api/correlation/campaigns", async () => {
    const body = {
      campaigns: [
        {
          campaign_id: "campaign-1",
          name: "Credential pivot cluster",
          hosts: ["prod-web-01", "prod-db-01"],
          alert_count: 4,
          first_seen_ms: 1714500000000,
          last_seen_ms: 1714500300000,
          avg_score: 8.3,
          max_score: 9.4,
          shared_techniques: ["T1110", "T1021"],
          shared_reasons: ["credential reuse", "remote service pivot"],
          severity: "critical",
          alert_ids: ["101", "102", "103", "104"],
        },
      ],
      temporal_chains: [],
      summary: {
        campaign_count: 1,
        temporal_chain_count: 0,
        temporal_chain_alerts: 0,
        total_alerts: 4,
        unclustered_alerts: 0,
        fleet_coverage: 0.5,
      },
      sequence_summaries: [
        {
          campaign_id: "campaign-1",
          name: "Credential pivot cluster",
          severity: "critical",
          host_count: 2,
          alert_count: 4,
          max_score: 9.4,
          avg_score: 8.3,
          shared_techniques: ["T1110", "T1021"],
          shared_reasons: ["credential reuse", "remote service pivot"],
          sequence_signals: ["shared_credentials", "remote_execution"],
          graph_context: ["prod-web-01 -> prod-db-01"],
          recommended_pivots: ["Open SOC campaigns for campaign-1."],
        },
      ],
      graph: {
        nodes: [
          {
            id: "prod-web-01",
            label: "prod-web-01",
            type: "host",
            risk_score: 94,
            campaign_id: "campaign-1",
            campaign_severity: "critical",
            sequence_signals: ["shared_credentials", "remote_execution"],
          },
        ],
        edges: [
          {
            source: "prod-web-01",
            target: "prod-db-01",
            type: "lateral_movement",
            weight: 4,
            campaign_id: "campaign-1",
            shared_reasons: ["credential reuse", "remote service pivot"],
          },
        ],
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.campaigns();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/correlation/campaigns",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("threatIntelSightings() calls GET /api/threat-intel/sightings", async () => {
    const body = {
      count: 1,
      items: [
        {
          ioc_type: "Domain",
          value: "bad.example",
          severity: "high",
          confidence: 0.92,
          timestamp: "2026-04-30T20:20:00Z",
          source: "feed:osint",
          context: "Seen in phishing redirect chain",
          weight: 1.0,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.threatIntelSightings(25);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/threat-intel/sightings?limit=25",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("threatIntelLibraryV2() calls GET /api/threat-intel/library/v2", async () => {
    const body = {
      count: 1,
      indicators: [
        {
          ioc_type: "Domain",
          value: "bad.example",
          confidence: 0.92,
          severity: "high",
          source: "feed:osint",
          first_seen: "2026-04-29T10:00:00Z",
          last_seen: "2026-04-30T20:20:00Z",
          tags: ["phishing"],
          related_iocs: ["198.51.100.7"],
          metadata: {
            normalized_value: "bad.example",
            ttl_days: 90,
            source_weight: 1,
            confidence_decay: 0.98,
            last_sighting: "2026-04-30T20:20:00Z",
            sightings: 3,
          },
          sightings: [
            {
              timestamp: "2026-04-30T20:20:00Z",
              source: "sensor-1",
              context: "Seen in redirect chain",
              weight: 1,
            },
          ],
        },
      ],
      feeds: [
        {
          feed_id: "osint-1",
          name: "OSINT Feed",
          url: "https://feeds.example.test/osint",
          format: "jsonl",
          last_updated: "2026-04-30T19:00:00Z",
          ioc_count: 128,
          active: true,
        },
      ],
      recent_matches: [
        {
          matched: true,
          ioc: {
            ioc_type: "Domain",
            value: "bad.example",
            confidence: 0.92,
            severity: "high",
            source: "feed:osint",
            first_seen: "2026-04-29T10:00:00Z",
            last_seen: "2026-04-30T20:20:00Z",
            tags: ["phishing"],
            related_iocs: ["198.51.100.7"],
            metadata: {
              normalized_value: "bad.example",
              ttl_days: 90,
              source_weight: 1,
              confidence_decay: 0.98,
              last_sighting: "2026-04-30T20:20:00Z",
              sightings: 3,
            },
            sightings: [
              {
                timestamp: "2026-04-30T20:20:00Z",
                source: "sensor-1",
                context: "Seen in redirect chain",
                weight: 1,
              },
            ],
          },
          match_type: "domain",
          context: "Matched on outbound DNS request",
        },
      ],
      recent_sightings: [
        {
          ioc_type: "Domain",
          value: "bad.example",
          severity: "high",
          confidence: 0.92,
          timestamp: "2026-04-30T20:20:00Z",
          source: "sensor-1",
          context: "Seen in redirect chain",
          weight: 1,
        },
      ],
      stats: {
        total_iocs: 1,
        by_type: { Domain: 1 },
        by_severity: { high: 1 },
        by_source: { "feed:osint": 1 },
        avg_confidence: 0.92,
        active_feeds: 1,
        total_feeds: 1,
        match_history_size: 4,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.threatIntelLibraryV2();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/threat-intel/library/v2",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("addIoc() posts the backend-backed IoC payload", async () => {
    const request = {
      ioc_type: "domain" as const,
      value: "bad.example",
      confidence: 0.91,
    };
    const body = {
      status: "added",
      value: "bad.example",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.addIoc(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/threat-intel/ioc",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("containerAlerts() calls GET /api/container/alerts", async () => {
    const body = [
      {
        id: "ctr-1",
        timestamp: "2026-04-30T20:30:00Z",
        severity: "High",
        kind: "ContainerEscape",
        container_id: "abc123",
        container_name: "payments",
        image: "registry.example/payments:1.2.3",
        hostname: "node-1",
        description: "Process escape attempt detected",
        risk_score: 8.9,
        mitre_techniques: ["T1611"],
        recommendations: ["Isolate the host and inspect runtime activity."],
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.containerAlerts();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/container/alerts",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("containerStats() calls GET /api/container/stats", async () => {
    const body = {
      total_events: 18,
      total_alerts: 3,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.containerStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/container/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("dedupAlerts() calls GET /api/alerts/dedup", async () => {
    const body = [
      {
        incident_id: "dedup-1",
        first_seen: "2026-04-30T20:00:00Z",
        last_seen: "2026-04-30T20:05:00Z",
        alert_count: 3,
        merged_alert_ids: [11, 12, 13],
        device_ids: ["edge-1"],
        level: "high",
        representative_reasons: ["credential reuse", "remote service pivot"],
        avg_score: 7.8,
        max_score: 9.1,
        fingerprint: "credential_reuse@edge-1",
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.dedupAlerts();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/dedup",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("autoCreateDedupIncidents() calls POST /api/alerts/dedup/auto-create", async () => {
    const body = {
      status: "ok",
      created_incidents: ["INC-0001", "INC-0004"],
      count: 2,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.autoCreateDedupIncidents();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/alerts/dedup/auto-create",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("apiAnalytics() calls GET /api/analytics", async () => {
    const body = {
      total_requests: 120,
      total_errors: 4,
      error_rate: 0.0333,
      unique_endpoints: 18,
      top_endpoints: [
        {
          path: "/api/alerts",
          method: "GET",
          request_count: 42,
          error_count: 1,
          avg_latency_ms: 18.4,
          p95_latency_ms: 29.0,
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.apiAnalytics();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/analytics",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("traces() calls GET /api/traces", async () => {
    const body = {
      stats: {
        total_spans: 24,
        error_spans: 2,
        avg_duration_ms: 18.75,
      },
      recent: [
        {
          trace_id: "00000000000000000000000000000001",
          span_id: "0000000000000001",
          parent_span_id: null,
          operation_name: "GET /api/alerts",
          service_name: "wardex",
          start_time_ms: 1714507800000,
          end_time_ms: 1714507800019,
          status: "Ok",
          attributes: [
            ["http.method", "GET"],
            ["http.route", "/api/alerts"],
          ],
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.traces();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/traces",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("listBackups() calls GET /api/backups", async () => {
    const body = [
      {
        name: "wardex_backup_20260430_223500.db",
        timestamp: "2026-04-30T22:35:00Z",
        size_bytes: 4096,
        checksum: "0123456789abcdef",
        verified: true,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.listBackups();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/backups",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("createBackup() calls POST /api/backups", async () => {
    const body = {
      name: "wardex_backup_20260430_223500.db",
      timestamp: "2026-04-30T22:35:00Z",
      size_bytes: 4096,
      checksum: "0123456789abcdef",
      verified: true,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.createBackup();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/backups",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("adminBackup() calls POST /api/admin/backup", async () => {
    const body = {
      status: "completed",
      path: "var/backups/wardex_backup_20260430_223500.db",
      timestamp: "2026-04-30T22:35:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.adminBackup();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/admin/backup",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("adminDbVersion() calls GET /api/admin/db/version", async () => {
    const body = {
      current_version: 3,
      migrations: [
        {
          version: 1,
          name: "initial_schema",
          sql_up: "",
          sql_down: "",
          applied_at: "2026-05-01T00:00:00Z",
        },
      ],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.adminDbVersion();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/admin/db/version",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("adminDbSizes() calls GET /api/admin/db/sizes", async () => {
    const body = {
      db_bytes: 1048576,
      wal_bytes: 65536,
      shm_bytes: 32768,
      total_bytes: 1146880,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.adminDbSizes();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/admin/db/sizes",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("adminDbRollback() calls POST /api/admin/db/rollback", async () => {
    const body = {
      status: "rolled_back",
      version: 3,
      current_version: 2,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.adminDbRollback();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/admin/db/rollback",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("adminDbCompact() calls POST /api/admin/db/compact", async () => {
    const body = {
      status: "completed",
      size_before_bytes: 2097152,
      size_after_bytes: 1572864,
      bytes_reclaimed: 524288,
      timestamp: "2026-05-01T10:10:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.adminDbCompact();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/admin/db/compact",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("adminDbReset() posts the reset confirmation payload", async () => {
    const payload = {
      confirm: "RESET_ALL_DATA",
    };
    const body = {
      status: "completed",
      records_purged: 128,
      timestamp: "2026-05-01T10:10:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.adminDbReset(payload);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/admin/db/reset",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("adminDbPurge() posts the retention payload", async () => {
    const payload = {
      retention_days: 30,
    };
    const body = {
      status: "completed",
      retention_days: 30,
      alerts_purged: 42,
      audit_purged: 14,
      metrics_purged: 7,
      timestamp: "2026-05-01T10:10:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.adminDbPurge(payload);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/admin/db/purge",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("adminCleanupLegacy() calls POST /api/admin/cleanup-legacy", async () => {
    const body = {
      status: "completed",
      files_removed: ["alerts.jsonl", "cases.json"],
      count: 2,
      timestamp: "2026-05-01T10:15:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.adminCleanupLegacy();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/admin/cleanup-legacy",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("sbom() calls GET /api/sbom", async () => {
    const body = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      serialNumber: "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
      version: 1,
      metadata: {
        timestamp: "2026-05-01T10:20:00Z",
        tools: [{ name: "Wardex SBOM Generator", version: "0.55.1" }],
        component: {
          type: "application",
          name: "wardex",
          version: "0.55.1",
        },
      },
      components: [
        {
          type: "library",
          name: "serde",
          version: "1.0.228",
          purl: "pkg:cargo/serde@1.0.228",
          hashes: [{ alg: "SHA-256", content: "abc123" }],
        },
      ],
      dependencies: [],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.sbom();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/sbom",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("sbomHost() calls GET /api/sbom/host", async () => {
    const body = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      serialNumber: "urn:uuid:123e4567-e89b-12d3-a456-426614174001",
      version: 1,
      metadata: {
        timestamp: "2026-05-01T10:20:00Z",
        tools: [{ name: "Wardex SBOM Generator", version: "0.55.1" }],
        component: {
          type: "application",
          name: "wardex",
          version: "0.55.1",
        },
      },
      components: [
        {
          type: "device",
          name: "Apple-M3",
          version: "8-core",
          purl: "pkg:generic/Apple-M3@8-core",
        },
      ],
      dependencies: [],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.sbomHost();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/sbom/host",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("piiScan() posts the raw text sample", async () => {
    const sample = "Contact alice@example.com at 203.0.113.7.";
    const body = {
      has_pii: true,
      finding_count: 2,
      categories: ["email", "ipv4"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.piiScan(sample);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/pii/scan",
      expect.objectContaining({
        method: "POST",
        body: sample,
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
          "Content-Type": "text/plain",
        }),
      })
    );
  });

  it("license() calls GET /api/license", async () => {
    const body = {
      status: "active",
      edition: "professional",
      features: ["xdr", "siem", "soar", "ueba", "threat_intel"],
      max_agents: 10000,
      expires: "2026-12-31T23:59:59Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.license();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/license",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("validateLicense() posts the validation payload", async () => {
    const request = { key: "ABCD-1234-EFGH-5678" };
    const body = {
      valid: true,
      key_prefix: "ABCD-123",
      validated_at: "2026-05-01T10:30:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.validateLicense(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/license/validate",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
          "Content-Type": "application/json",
        }),
      })
    );
  });

  it("meteringUsage() calls GET /api/metering/usage", async () => {
    const body = {
      events_ingested: 0,
      api_calls: 0,
      storage_bytes: 0,
      plan: "professional",
      period_start: "2026-05-01T10:30:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.meteringUsage();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/metering/usage",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("billingSubscription() calls GET /api/billing/subscription", async () => {
    const body = {
      plan: "professional",
      status: "active",
      monthly_price: "$99",
      next_billing: "2026-05-01T10:30:00Z",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.billingSubscription();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/billing/subscription",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("billingInvoices() calls GET /api/billing/invoices", async () => {
    const body = { invoices: [] };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.billingInvoices();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/billing/invoices",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("listMarketplacePacks() calls GET /api/marketplace/packs", async () => {
    const body = [
      {
        id: "pci-dss",
        name: "PCI-DSS Compliance Pack",
        version: "1.0.0",
        author: "Wardex Team",
        description: "Pre-built rules and reports for PCI-DSS compliance",
        category: "ComplianceTemplates",
        tags: [],
        status: "Available",
        downloads: 0,
        rating: 0,
        created: "2026-05-01T10:45:00Z",
        updated: "2026-05-01T10:45:00Z",
        size_bytes: 0,
        checksum: "builtin-pci-dss",
        dependencies: [],
        min_wardex_version: "0.1.0",
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.listMarketplacePacks();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/marketplace/packs",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("getMarketplacePack() calls GET /api/marketplace/packs/:id", async () => {
    const packId = "pci dss/1";
    const body = {
      id: packId,
      name: "PCI-DSS Compliance Pack",
      version: "1.0.0",
      author: "Wardex Team",
      description: "Pre-built rules and reports for PCI-DSS compliance",
      category: "ComplianceTemplates",
      tags: [],
      status: "Available",
      downloads: 0,
      rating: 0,
      created: "2026-05-01T10:45:00Z",
      updated: "2026-05-01T10:45:00Z",
      size_bytes: 0,
      checksum: "builtin-pci-dss",
      dependencies: [],
      min_wardex_version: "0.1.0",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.getMarketplacePack(packId);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/marketplace/packs/pci%20dss%2F1",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("preventionPolicies() calls GET /api/prevention/policies", async () => {
    const body = [
      {
        id: "default-prevention",
        name: "Default Prevention Policy",
        enabled: true,
        mode: "Prevent",
        rules: [
          {
            id: "block-mimikatz",
            name: "Block Mimikatz",
            condition: { ProcessName: "mimikatz.exe" },
            action: "Kill",
            severity: 10,
            confidence_threshold: 0.8,
            enabled: true,
          },
        ],
        created: "2026-05-01T10:55:00Z",
        updated: "2026-05-01T10:55:00Z",
        description: "Built-in prevention rules for known attack tools",
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.preventionPolicies();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/prevention/policies",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("preventionStats() calls GET /api/prevention/stats", async () => {
    const body = {
      events_evaluated: 0,
      events_blocked: 0,
      events_allowed: 0,
      events_quarantined: 0,
      false_positives_reported: 0,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.preventionStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/prevention/stats",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("pipelineStatus() calls GET /api/pipeline/status", async () => {
    const body = {
      status: {
        running: false,
        metrics: {
          events_ingested: 0,
          events_normalized: 0,
          events_enriched: 0,
          events_detected: 0,
          events_stored: 0,
          events_forwarded: 0,
          backpressure_count: 0,
          dlq_count: 0,
          errors: 0,
          avg_latency_ms: 0,
        },
        dlq_size: 0,
        config: {
          channel_capacity: 10000,
          batch_size: 1000,
          backpressure_threshold: 8000,
        },
      },
      metrics: {
        events_ingested: 0,
        events_normalized: 0,
        events_detected: 0,
        events_stored: 0,
        dlq_count: 0,
      },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.pipelineStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/pipeline/status",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("backupStatus() calls GET /api/backup/status", async () => {
    const body = {
      enabled: false,
      retention_count: 7,
      path: "var/backups/",
      schedule_cron: "0 2 * * *",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.backupStatus();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/backup/status",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("backupEncrypt() posts the encryption payload", async () => {
    const payload = {
      data: "sensitive payload",
      passphrase: "correct horse battery staple",
    };
    const body = {
      encrypted: "ZW5jcnlwdGVkLWJ5dGVz",
      size: 32,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.backupEncrypt(payload);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/backup/encrypt",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("backupDecrypt() posts the decrypt payload", async () => {
    const payload = {
      data: "ZW5jcnlwdGVkLWJ5dGVz",
      passphrase: "correct horse battery staple",
    };
    const body = {
      data: "sensitive payload",
      size: 17,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "secret",
    });
    const result = await client.backupDecrypt(payload);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/backup/decrypt",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
        headers: expect.objectContaining({
          Authorization: "Bearer secret",
        }),
      })
    );
  });

  it("vulnerabilityScan() calls GET /api/vulnerability/scan", async () => {
    const body = [
      {
        host_id: "edge-01",
        scan_timestamp: "2026-04-30T20:25:00Z",
        total_packages: 120,
        vulnerable_packages: 2,
        total_cves: 3,
        critical_count: 1,
        high_count: 1,
        medium_count: 1,
        low_count: 0,
        exploit_available_count: 1,
        risk_score: 7.8,
        matches: [
          {
            advisory: {
              id: "CVE-2026-1000",
              title: "Critical OpenSSL issue",
              package: "openssl",
              affected_below: "3.0.14",
              fixed_version: "3.0.14",
              cvss: 9.8,
              severity: "Critical",
              exploit_known: true,
              mitre_techniques: ["T1190"],
              published: "2026-04-01T00:00:00Z",
            },
            installed_version: "3.0.12",
            package_source: "apt",
            risk_score: 9.9,
            remediation: "Upgrade openssl to 3.0.14 or newer",
          },
        ],
        top_actions: ["Patch openssl on edge-01"],
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.vulnerabilityScan();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/vulnerability/scan",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("vulnerabilitySummary() calls GET /api/vulnerability/summary", async () => {
    const body = {
      total_hosts: 4,
      vulnerable_hosts: 2,
      total_cves: 7,
      critical_cves: 2,
      high_cves: 3,
      exploit_available: 1,
      average_risk_score: 5.25,
      advisory_database_size: 42,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.vulnerabilitySummary();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/vulnerability/summary",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("emailAnalyze() posts the structured email analysis payload", async () => {
    const request = {
      from: "attacker@evil.example",
      subject: "Urgent password reset",
      authentication_results: "spf=fail; dkim=fail; dmarc=fail",
      body_text: "Reset your password immediately: https://evil.example/reset",
    };
    const body = {
      message_id: "msg-1",
      auth_results: {
        spf: "fail",
        dkim: "fail",
        dmarc: "fail",
        auth_score: 0.05,
      },
      sender_mismatch: true,
      url_findings: [
        {
          url: "https://evil.example/reset",
          risk_score: 0.91,
          indicators: ["suspicious_domain"],
        },
      ],
      attachment_findings: [],
      urgency_score: 0.75,
      phishing_score: 0.93,
      indicators: ["urgency_language", "auth_failures"],
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.emailAnalyze(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/email/analyze",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          ...request,
          received_chain: [],
          attachments: [],
        }),
      })
    );
  });

  it("currentPolicy() calls GET /api/policy/current", async () => {
    const body = {
      version: 1,
      published_at: "2026-04-30T18:00:00Z",
      alert_threshold: 4.5,
      interval_secs: 15,
      watch_paths: ["/etc", "/var/log"],
      dry_run: false,
      syslog: true,
      cef: false,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.currentPolicy();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/policy/current",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("publishPolicy() posts a backend-compatible policy payload", async () => {
    const request = {
      alert_threshold: 4.5,
      interval_secs: 15,
      watch_paths: ["/etc", "/var/log"],
      dry_run: false,
      syslog: true,
      cef: false,
    };
    const body = {
      version: 1,
      published_at: "2026-04-30T18:05:00Z",
      ...request,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.publishPolicy(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/policy/publish",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          version: 0,
          published_at: "",
          ...request,
        }),
      })
    );
  });

  it("approveResponseAction() posts the canonical approval payload", async () => {
    const body = {
      request_id: "resp-42",
      decision: "Approve",
      status: "Approved",
      approvals: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.approveResponseAction("resp-42", true);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/response/approve",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          request_id: "resp-42",
          decision: "approved",
        }),
      })
    );
  });

  it("beaconConnection() posts a beacon connection payload", async () => {
    const body = { status: "recorded" };
    const connection = {
      timestamp_ms: 1714392000000,
      dst_addr: "198.51.100.20",
      dst_port: 443,
      hostname: "edge-1",
      process: "curl",
      bytes_sent: 1024,
      bytes_received: 4096,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.beaconConnection(connection);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/beacon/connection",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(connection),
      })
    );
  });

  it("beaconDns() posts a beacon DNS payload", async () => {
    const body = { status: "recorded" };
    const dns = {
      timestamp_ms: 1714392000000,
      domain: "api.example.test",
      query_type: "A",
      response_code: "NoError" as const,
      hostname: "edge-1",
      process: "curl",
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.beaconDns(dns);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/beacon/dns",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(dns),
      })
    );
  });

  it("beaconAnalyze() calls GET /api/beacon/analyze", async () => {
    const body = {
      beacons: [
        {
          dst_addr: "198.51.100.20",
          dst_port: 443,
          interval_ms: 60000,
          jitter: 0.08,
          score: 0.91,
          sample_count: 8,
          hostname: "edge-1",
          process: "curl",
          total_bytes: 9216,
        },
      ],
      dga_domains: [
        {
          domain: "asdkjhqwe.example",
          entropy: 3.9,
          consonant_ratio: 0.78,
          score: 0.72,
          query_count: 6,
          nxdomain: true,
        },
      ],
      tunnel_indicators: [
        {
          domain: "txt.example",
          avg_query_length: 72.5,
          txt_ratio: 0.85,
          nxdomain_ratio: 0.1,
          score: 0.69,
          query_count: 4,
        },
      ],
      total_connections_analysed: 8,
      total_dns_queries_analysed: 10,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.beaconAnalyze();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/beacon/analyze",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("remediationPlan() posts a remediation plan request", async () => {
    const request = {
      action: "block_ip" as const,
      platform: "linux" as const,
      addr: "203.0.113.77",
    };
    const body = {
      action: { BlockIp: { addr: "203.0.113.77" } },
      platform: "Linux",
      commands: [
        {
          program: "iptables",
          args: ["-A", "INPUT", "-s", "203.0.113.77", "-j", "DROP"],
          requires_elevation: true,
        },
      ],
      prerequisites: ["IP 203.0.113.77 is not in allow-list"],
      needs_approval: false,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.remediationPlan(request);
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/remediation/plan",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
      })
    );
  });

  it("remediationResults() calls GET /api/remediation/results", async () => {
    const body = [
      {
        action: "FlushDns",
        status: "RolledBack",
        commands_run: [],
        snapshot_id: "snap-1",
        output: "rollback dry-run planned through remediation adapter",
        error: null,
        duration_ms: 0,
      },
    ];
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.remediationResults();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/remediation/results",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("remediationStats() calls GET /api/remediation/stats", async () => {
    const body = {
      succeeded: 4,
      partial: 1,
      failed: 2,
      rolled_back: 3,
      skipped: 0,
      pending: 1,
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.remediationStats();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/remediation/stats",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("remediationChangeReviews() calls GET /api/remediation/change-reviews", async () => {
    const body = { summary: { total: 0 }, reviews: [] };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    const result = await client.remediationChangeReviews();
    expect(result).toEqual(body);
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/remediation/change-reviews",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("recordRemediationChangeReview() posts the review payload", async () => {
    const body = {
      status: "recorded",
      review: { id: "review-1", title: "Review host-1", approvals: [], evidence: {} },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.recordRemediationChangeReview({
      title: "Review host-1",
      asset_id: "host-1",
      evidence: { src_ip: "10.0.0.5" },
    });
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/remediation/change-reviews",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          title: "Review host-1",
          asset_id: "host-1",
          evidence: { src_ip: "10.0.0.5" },
        }),
      })
    );
  });

  it("approveRemediationChangeReview() posts the approval payload", async () => {
    const body = {
      status: "approved",
      review: { id: "review-1", title: "Review host-1", approvals: [], evidence: {} },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.approveRemediationChangeReview("review-1", {
      decision: "approve",
      comment: "Signed from test",
    });
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/remediation/change-reviews/review-1/approval",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          decision: "approve",
          comment: "Signed from test",
        }),
      })
    );
  });

  it("executeRemediationRollback() posts rollback verification input", async () => {
    const body = {
      status: "rollback_recorded",
      review: { id: "review-1", title: "Review host-1", approvals: [], evidence: {} },
    };
    const mock = mockFetch(200, body);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.executeRemediationRollback("review-1", {
      dry_run: false,
      platform: "linux",
      confirm_hostname: "host-1",
    });
    expect(mock).toHaveBeenCalledWith(
      "http://localhost:8080/api/remediation/change-reviews/review-1/rollback",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          dry_run: false,
          platform: "linux",
          confirm_hostname: "host-1",
        }),
      })
    );
  });

  // ── Error mapping ────────────────────────────────────────────────────

  it("throws AuthenticationError on 401", async () => {
    globalThis.fetch = mockFetch(401, "Unauthorized", false);
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await expect(client.health()).rejects.toThrow(AuthenticationError);
  });

  it("throws AuthenticationError on 403", async () => {
    globalThis.fetch = mockFetch(403, "Forbidden", false);
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await expect(client.health()).rejects.toThrow(AuthenticationError);
  });

  it("throws NotFoundError on 404", async () => {
    globalThis.fetch = mockFetch(404, "Not Found", false);
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await expect(client.health()).rejects.toThrow(NotFoundError);
  });

  it("throws RateLimitError on 429", async () => {
    globalThis.fetch = mockFetch(429, "Too Many Requests", false);
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await expect(client.health()).rejects.toThrow(RateLimitError);
  });

  it("throws ServerError on 500", async () => {
    globalThis.fetch = mockFetch(500, "Internal Server Error", false);
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await expect(client.health()).rejects.toThrow(ServerError);
  });

  it("throws ServerError on 503", async () => {
    globalThis.fetch = mockFetch(503, "Service Unavailable", false);
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await expect(client.health()).rejects.toThrow(ServerError);
  });

  it("throws WardexError on 400 (generic client error)", async () => {
    globalThis.fetch = mockFetch(400, "Bad Request", false);
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await expect(client.health()).rejects.toThrow(WardexError);
    try {
      await client.health();
    } catch (e) {
      expect(e).toBeInstanceOf(WardexError);
      expect(e).not.toBeInstanceOf(AuthenticationError);
      expect((e as WardexError).statusCode).toBe(400);
    }
  });

  it("error body is preserved", async () => {
    globalThis.fetch = mockFetch(401, "invalid token", false);
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    try {
      await client.health();
    } catch (e) {
      expect((e as AuthenticationError).body).toContain("invalid token");
      expect((e as AuthenticationError).statusCode).toBe(401);
    }
  });

  // ── Auth header ──────────────────────────────────────────────────────

  it("includes Authorization header when apiKey is set", async () => {
    const mock = mockFetch(200, []);
    globalThis.fetch = mock;
    const client = new WardexClient({
      baseUrl: "http://localhost:8080",
      apiKey: "my-token",
    });
    await client.alerts();
    const callHeaders = mock.mock.calls[0][1].headers;
    expect(callHeaders["Authorization"]).toBe("Bearer my-token");
  });

  it("omits Authorization header when apiKey is not set", async () => {
    const mock = mockFetch(200, []);
    globalThis.fetch = mock;
    const client = new WardexClient({ baseUrl: "http://localhost:8080" });
    await client.alerts();
    const callHeaders = mock.mock.calls[0][1].headers;
    expect(callHeaders["Authorization"]).toBeUndefined();
  });
});
