const { test, expect } = require("@playwright/test");

const BASE = process.env.WARDEX_BASE_URL || "http://127.0.0.1:8095";
const TOKEN = process.env.WARDEX_ADMIN_TOKEN || "";

async function loginToConsole(page) {
  await page.goto(`${BASE}/admin/`, { waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/admin\/?$/);

  await page.getByPlaceholder("API token").fill(TOKEN);
  await page.getByRole("button", { name: "Connect" }).click();
  await expect(page.locator(".auth-badge")).toContainText(/Connected/i);

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

test("mobile topbar more-menu smoke", async ({ page }) => {
  test.skip(!TOKEN, "Set WARDEX_ADMIN_TOKEN to run the mobile topbar smoke.");
  test.setTimeout(60000);

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

  await page.setViewportSize({ width: 390, height: 844 });
  await loginToConsole(page);

  consoleErrors.length = 0;
  badResponses.length = 0;
  pageErrors.length = 0;

  await expect(
    page.getByRole("heading", { name: "Security Overview" }),
  ).toBeVisible();

  const authBadge = page.locator(".auth-badge");
  await expect(authBadge).toBeVisible();
  const authBadgeBox = await authBadge.boundingBox();
  expect(authBadgeBox).not.toBeNull();
  expect(authBadgeBox.width).toBeLessThan(84);

  const moreButton = page.getByRole("button", { name: "More", exact: true });
  await expect(moreButton).toBeVisible();
  await moreButton.click();

  const menu = page.getByRole("menu", { name: "More actions" });
  await expect(menu).toBeVisible();
  await expect(menu.getByRole("menuitem", { name: "Search" })).toBeVisible();
  await expect(
    menu.getByRole("menuitem", { name: "Help For View" }),
  ).toBeVisible();
  await expect(
    menu.getByRole("menuitem", { name: "Share Link" }),
  ).toBeVisible();
  await expect(menu.getByRole("menuitem", { name: "Pin View" })).toBeVisible();

  const menuBox = await menu.boundingBox();
  expect(menuBox).not.toBeNull();
  expect(menuBox.height).toBeGreaterThan(120);
  expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(844);

  await menu.getByRole("menuitem", { name: "Search" }).click();
  await expect(page.locator(".search-palette")).toBeVisible();

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});

test("mobile help action preserves threat-detection route scope", async ({
  page,
}) => {
  test.skip(!TOKEN, "Set WARDEX_ADMIN_TOKEN to run the mobile topbar smoke.");
  test.setTimeout(60000);

  await page.setViewportSize({ width: 390, height: 844 });
  await loginToConsole(page);

  await page.goto(
    `${BASE}/admin/detection?intent=run-hunt&huntName=Mobile%20Topbar%20Pivot`,
    { waitUntil: "domcontentloaded" },
  );
  await expect(page).toHaveURL(/\/admin\/detection\?.*rule=/);

  await page.getByRole("button", { name: "More", exact: true }).click();
  await expect(page.getByRole("menu", { name: "More actions" })).toBeVisible();
  await Promise.all([
    page.waitForURL(/\/admin\/help\?/),
    page.getByRole("menuitem", { name: "Help For View" }).click(),
  ]);

  await expect(page).toHaveURL(/\/admin\/help\?/);
  await expect(page).toHaveURL(/intent=run-hunt/);
  await expect(page).toHaveURL(
    /huntName=Mobile(?:\+|%20)Topbar(?:\+|%20)Pivot/,
  );
  await expect(page).toHaveURL(/context=threat-detection/);
  await expect(
    page.getByText(
      "Context-aware help is using the selected scope from the URL.",
    ),
  ).toBeVisible();
});
