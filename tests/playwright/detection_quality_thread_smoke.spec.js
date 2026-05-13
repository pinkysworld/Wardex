const { test, expect } = require("@playwright/test");

const BASE = process.env.WARDEX_BASE_URL || "http://127.0.0.1:8080";
const TOKEN = process.env.WARDEX_ADMIN_TOKEN || "wardex-live-token";

async function authenticate(page) {
  await page.context().clearCookies();
  await page.goto(`${BASE}/admin/`, { waitUntil: "domcontentloaded" });
  await page.getByPlaceholder("API token").fill(TOKEN);
  await page.getByRole("button", { name: "Connect" }).click();
  const authBadge = page.locator(".auth-badge");
  await expect(authBadge).toContainText(/Connected/i, { timeout: 15000 });

  const onboardingDialog = page.getByRole("dialog", {
    name: "Set up the Wardex admin console",
  });
  if (await onboardingDialog.isVisible().catch(() => false)) {
    await onboardingDialog
      .getByRole("button", { name: "Skip for now" })
      .click();
    await expect(onboardingDialog).toBeHidden();
  }
}

async function expectApiOk(page, path) {
  const response = await page.request.get(`${BASE}${path}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  expect(response.ok(), `${path} returned ${response.status()}`).toBeTruthy();
  return response.json();
}

async function expectApiPostOk(page, path, body = {}) {
  const response = await page.request.post(`${BASE}${path}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
    data: body,
  });
  expect(response.ok(), `${path} returned ${response.status()}`).toBeTruthy();
  return response.json();
}

test("live detection quality and thread evidence routes stay wired", async ({
  page,
}) => {
  test.setTimeout(180000);

  const consoleErrors = [];
  const pageErrors = [];
  const badResponses = [];

  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => pageErrors.push(String(err)));
  page.on("response", (response) => {
    if (response.url().startsWith(`${BASE}/api/`) && response.status() >= 400) {
      badResponses.push(`${response.status()} ${response.url()}`);
    }
  });

  await authenticate(page);
  consoleErrors.length = 0;
  badResponses.length = 0;
  pageErrors.length = 0;

  const evidencePack = await expectApiOk(page, "/api/launchpad/evidence-pack");
  expect(evidencePack).toHaveProperty("digest");
  await expectApiOk(page, "/api/operational/snapshots");
  await expectApiOk(page, "/api/operational/snapshots/verify");
  await expectApiOk(page, "/api/launchpad/release-diff");
  await expectApiOk(page, "/api/launchpad/demo-status");
  await expectApiOk(page, "/api/release/doctor");
  await expectApiOk(page, "/api/release/clean-cut");
  await expectApiOk(page, "/api/containers/release-parity");
  await expectApiOk(page, "/api/release/verification-center");
  await expectApiOk(page, "/api/deployment/self-hosted-wizard");
  await expectApiOk(page, "/api/data-quality/dashboard");
  await expectApiOk(page, "/api/performance/scale-baseline");
  await expectApiOk(page, "/api/cluster/failover-execution");
  await expectApiOk(page, "/api/secrets/rotation-operations");
  await expectApiOk(page, "/api/operator/task-automation");
  await expectApiOk(page, "/api/detection/validation-packs");
  await expectApiOk(page, "/api/detection/recommendations");
  await expectApiOk(page, "/api/detection/readiness");
  await expectApiOk(page, "/api/response/approval-overview");
  await expectApiOk(page, "/api/remediation/safety");
  await expectApiOk(page, "/api/support/bundle");
  await expectApiOk(page, "/api/ws/health");
  await expectApiOk(page, "/api/stream/readiness");
  await expectApiOk(page, "/api/stream/reliability-lab");
  await expectApiOk(page, "/api/sdk/contract-status");
  await expectApiOk(page, "/api/alerts/histogram");
  const subscription = await expectApiPostOk(page, "/api/subscriptions", {
    lanes: ["alerts"],
    filters: {},
  });
  await expectApiOk(
    page,
    `/api/subscriptions/resume?subscription_id=${subscription.subscription.subscription_id}&cursor=0&limit=5`,
  );

  await page.goto(`${BASE}/admin/launchpad`, { waitUntil: "domcontentloaded" });
  await expect(
    page.getByRole("heading", {
      name: "Run the first incident with confidence",
    }),
  ).toBeVisible();
  await expect(page.getByText("Promotion confidence")).toBeVisible();
  await expect(page.getByText("Acceptance readiness")).toBeVisible();
  await expect(page.getByText("Release verification")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Clean release and deployment" }),
  ).toBeVisible();
  await expect(page.getByText("Artifact rows")).toBeVisible();
  const deploymentConfidence = page.locator("#deployment-confidence");
  await expect(
    deploymentConfidence.getByText("Install plans", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Quality score", { exact: true })).toBeVisible();
  await expect(page.getByText("Dry-run actions")).toBeVisible();
  await expect(page.getByText("Promotion guard")).toBeVisible();
  await expect(page.getByText("Operational snapshots")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Support Bundle" }),
  ).toBeVisible();
  await expect(page.getByText("Process evidence")).toBeVisible();
  await expect(page.getByText("Evaluation scenarios")).toBeVisible();

  await page.goto(`${BASE}/admin/launchpad#demo-mode`, {
    waitUntil: "domcontentloaded",
  });
  const demoModeCard = page.locator("#demo-mode");
  await expect(
    demoModeCard.getByRole("heading", { name: "Evaluation scenarios" }),
  ).toBeVisible();
  await expect(demoModeCard).not.toContainText("Approvals and dry-runs");

  await page.goto(`${BASE}/admin/detection?panel=quality`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.locator(".auth-badge")).toContainText(/Connected/i, {
    timeout: 30000,
  });
  await expect(page.getByText("Detection Quality Score")).toBeVisible({
    timeout: 15000,
  });
  await expect(page.getByText("Backend recommendation")).toBeVisible();
  await expect(page.getByText("Collector readiness")).toBeVisible();
  await expect(page.getByText("Stream guard")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Run Action" }).first(),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Quality" })).toHaveClass(
    /active/,
  );

  await page.goto(`${BASE}/admin/monitor?monitorTab=stream`, {
    waitUntil: "domcontentloaded",
  });
  await expect(
    page.locator(".summary-label", { hasText: "Readiness Score" }),
  ).toBeVisible({
    timeout: 15000,
  });
  await expect(page.getByText("Reliability Lab")).toBeVisible();
  await expect(page.getByText("24h Histogram")).toBeVisible();
  await expect(
    page.locator(".summary-label", { hasText: "Cursor Replay" }),
  ).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${BASE}/admin/launchpad`, { waitUntil: "domcontentloaded" });
  await expect(
    page.getByRole("heading", {
      name: "Run the first incident with confidence",
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Evidence Pack" }),
  ).toBeVisible();
  await authenticate(page);
  consoleErrors.length = 0;
  badResponses.length = 0;
  pageErrors.length = 0;
  await page.goto(`${BASE}/admin/detection?panel=quality`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.locator(".auth-badge")).toContainText(/Connected/i, {
    timeout: 30000,
  });
  await expect(page.getByText("Detection Quality Score")).toBeVisible({
    timeout: 15000,
  });
  await page.setViewportSize({ width: 1280, height: 900 });

  await authenticate(page);
  consoleErrors.length = 0;
  badResponses.length = 0;
  pageErrors.length = 0;

  await page.goto(`${BASE}/admin/monitor?monitorTab=processes`, {
    waitUntil: "domcontentloaded",
  });
  await expect(
    page.getByRole("heading", { name: "Running Processes" }),
  ).toBeVisible({
    timeout: 15000,
  });
  await expect(page.getByText("Process Count")).toBeVisible();

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});
