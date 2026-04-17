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

  it("alerts() calls GET /api/alerts", async () => {
    const alerts = [{ timestamp: "2026-01-01", hostname: "h", score: 5 }];
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
