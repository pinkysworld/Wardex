import { describe, expect, it } from "vitest";

import { WardexClient } from "./index";

const liveBaseUrl =
  process.env.WDX_BASE_URL ?? process.env.WARDEX_LIVE_BASE_URL;
const liveApiKey =
  process.env.WDX_API_KEY ?? process.env.WARDEX_LIVE_API_KEY;

const describeLive = liveBaseUrl ? describe : describe.skip;
const itAuthenticated = liveApiKey ? it : it.skip;

describeLive("WardexClient live smoke", () => {
  const publicClient = new WardexClient({ baseUrl: liveBaseUrl! });

  itAuthenticated("reads authenticated health endpoints", async () => {
    const authenticatedClient = new WardexClient({
      baseUrl: liveBaseUrl!,
      apiKey: liveApiKey,
    });

    const health = await authenticatedClient.health();
    expect(health.status).toBe("ok");
    expect(typeof health.version).toBe("string");

    const live = await authenticatedClient.healthLive();
    expect(live.status).toBe("alive");

    const ready = await authenticatedClient.healthReady();
    expect(ready.status).toBe("ready");
  });

  it("fetches the live OpenAPI document", async () => {
    const spec = await publicClient.openApiSpec();
    expect(spec.openapi.startsWith("3.")).toBe(true);
    expect(spec.paths).toHaveProperty("/api/health");
    expect(spec.paths).toHaveProperty("/api/openapi.json");
  });
});