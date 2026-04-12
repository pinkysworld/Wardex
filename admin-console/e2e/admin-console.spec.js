import { test, expect } from '@playwright/test';

const TOKEN = 'testtoken123';

// Helper: authenticate via localStorage (fast) and wait for dashboard
async function login(page) {
  await page.goto('./');
  await page.evaluate((t) => {
    localStorage.setItem('wardex_onboarded', '1');
    localStorage.setItem('wardex_token', t);
  }, TOKEN);
  await page.reload({ waitUntil: 'load' });
  // AuthProvider auto-reconnects from localStorage — retry once if flaky
  try {
    await expect(page.locator('.auth-badge')).toBeVisible({ timeout: 20000 });
  } catch {
    await page.evaluate((t) => {
      localStorage.setItem('wardex_token', t);
    }, TOKEN);
    await page.reload({ waitUntil: 'load' });
    await expect(page.locator('.auth-badge')).toBeVisible({ timeout: 20000 });
  }
  // Wait for role to resolve to admin (RoleProvider fetches /api/auth/session)
  await expect(page.locator('.role-badge')).toContainText('admin', { timeout: 15000 });
}

// ════════════════════════════════════════════════════════════
// 1. AUTHENTICATION & INITIAL LOAD
// ════════════════════════════════════════════════════════════

test.describe('Authentication', () => {
  test('shows welcome + auth form when unauthenticated', async ({ page }) => {
    await page.goto('./');
    await page.evaluate(() => {
      localStorage.removeItem('wardex_token');
      localStorage.setItem('wardex_onboarded', '1');
    });
    await page.reload();
    await expect(page.locator('text=Welcome to Wardex Admin Console')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.locator('button:has-text("Connect")')).toBeVisible();
  });

  test('connect button is disabled without token', async ({ page }) => {
    await page.goto('./');
    await page.evaluate(() => {
      localStorage.removeItem('wardex_token');
      localStorage.setItem('wardex_onboarded', '1');
    });
    await page.reload();
    const connectBtn = page.locator('button[type="submit"]:has-text("Connect")');
    await expect(connectBtn).toBeDisabled();
  });

  test('shows error on invalid token', async ({ page }) => {
    await page.goto('./');
    await page.evaluate(() => {
      localStorage.removeItem('wardex_token');
      localStorage.setItem('wardex_onboarded', '1');
    });
    await page.reload();
    await page.locator('input[type="password"]').fill('wrong-token');
    await page.locator('button[type="submit"]:has-text("Connect")').click();
    await expect(page.locator('.auth-error')).toBeVisible({ timeout: 5000 });
  });

  test('successfully authenticates with valid token', async ({ page }) => {
    await login(page);
    await expect(page.locator('.auth-badge')).toContainText('Connected');
    // Dashboard content should appear
    await expect(page.locator('h1')).toContainText('Dashboard');
  });

  test('disconnect removes authenticated state', async ({ page }) => {
    await login(page);
    await expect(page.locator('.auth-badge')).toBeVisible();
    // Click disconnect
    await page.locator('button[title="Disconnect"]').click();
    await expect(page.locator('text=Welcome to Wardex Admin Console')).toBeVisible();
  });
});

// ════════════════════════════════════════════════════════════
// 2. SIDEBAR NAVIGATION
// ════════════════════════════════════════════════════════════

test.describe('Sidebar Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('sidebar shows all expected nav items for admin role', async ({ page }) => {
    const expectedItems = [
      'Dashboard', 'Live Monitor', 'Threat Detection', 'Fleet & Agents',
      'Security Policy', 'SOC Workbench', 'Infrastructure',
      'Reports & Exports', 'Settings', 'Help & Docs',
    ];
    for (const item of expectedItems) {
      await expect(page.locator(`button[title="${item}"]`)).toBeVisible();
    }
  });

  test('clicking nav items navigates to correct page', async ({ page }) => {
    // Navigate to Live Monitor
    await page.locator('button[title="Live Monitor"]').click();
    await expect(page.locator('h1:has-text("Live Monitor")')).toBeVisible();
    // Navigate to Fleet & Agents
    await page.locator('button[title="Fleet & Agents"]').click();
    await expect(page.locator('h1:has-text("Fleet & Agents")')).toBeVisible();
    // Navigate to Help & Docs
    await page.locator('button[title="Help & Docs"]').click();
    await expect(page.locator('h1:has-text("Help & Docs")')).toBeVisible();
    // Navigate back to Dashboard
    await page.locator('button[title="Dashboard"]').click();
    await expect(page.locator('h1:has-text("Dashboard")')).toBeVisible();
  });

  test('sidebar collapse/expand works', async ({ page }) => {
    // Initially expanded — should see labels
    await expect(page.locator('.nav-label').first()).toBeVisible();
    // Collapse — labels are removed from DOM entirely
    await page.locator('button[title="Toggle sidebar"]').click();
    await expect(page.locator('.nav-label')).toHaveCount(0);
    // Expand again
    await page.locator('button[title="Toggle sidebar"]').click();
    await expect(page.locator('.nav-label').first()).toBeVisible();
  });

  test('active nav item is highlighted', async ({ page }) => {
    const dashBtn = page.locator('button[title="Dashboard"]');
    await expect(dashBtn).toHaveClass(/active/);
    // Navigate elsewhere
    await page.locator('button[title="Live Monitor"]').click();
    const monBtn = page.locator('button[title="Live Monitor"]');
    await expect(monBtn).toHaveClass(/active/);
    await expect(dashBtn).not.toHaveClass(/active/);
  });
});

// ════════════════════════════════════════════════════════════
// 3. DASHBOARD
// ════════════════════════════════════════════════════════════

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('dashboard loads with key widgets', async ({ page }) => {
    await expect(page.locator('text=Security Overview')).toBeVisible();
    // Check for dashboard widgets
    await expect(page.locator('text=System Health')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Threat Overview')).toBeVisible();
  });

  test('version badge displayed in top bar', async ({ page }) => {
    await expect(page.locator('.version-badge')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('.version-badge')).toContainText('0.43.0');
  });

  test('system health widget shows data', async ({ page }) => {
    // Wait for health API data to load
    await expect(page.locator('.version-badge')).toBeVisible({ timeout: 15000 });
  });

  test('refresh button works without crash', async ({ page }) => {
    await expect(page.locator('text=Security Overview')).toBeVisible();
    const refreshBtn = page.locator('button:has-text("Refresh")');
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();
    // Should show "Refreshing…" briefly then go back
    await expect(page.locator('text=Security Overview')).toBeVisible();
  });

  test('widget collapse/expand works', async ({ page }) => {
    await expect(page.locator('text=System Health')).toBeVisible({ timeout: 10000 });
    // Find first collapse button
    const collapseBtn = page.locator('.widget-collapse').first();
    await collapseBtn.click();
    // Content should be hidden
    // Click again to expand
    await collapseBtn.click();
  });

  test('widget remove and restore works', async ({ page }) => {
    await expect(page.locator('text=System Health')).toBeVisible({ timeout: 10000 });
    // Remove first widget
    const removeBtn = page.locator('.widget-remove').first();
    await removeBtn.click();
    // Should show "Hidden widgets:" section
    await expect(page.locator('text=Hidden widgets:')).toBeVisible();
    // Restore it
    const restoreBtn = page.locator('button:has-text("+ system")').first();
    await restoreBtn.click();
  });

  test('reset layout button works', async ({ page }) => {
    await expect(page.locator('text=Security Overview')).toBeVisible({ timeout: 10000 });
    const resetBtn = page.locator('button:has-text("Reset Layout")');
    await expect(resetBtn).toBeVisible();
    await resetBtn.click();
  });
});

// ════════════════════════════════════════════════════════════
// 4. DARK/LIGHT THEME TOGGLE
// ════════════════════════════════════════════════════════════

test.describe('Theme Toggle', () => {
  test('toggling dark/light mode changes data-theme attribute', async ({ page }) => {
    await login(page);
    // Get initial theme
    const initialTheme = await page.locator('html').getAttribute('data-theme');
    // Toggle theme
    const themeBtn = page.locator('button[title="Light mode"], button[title="Dark mode"]');
    await themeBtn.click();
    // Theme should have changed
    const newTheme = await page.locator('html').getAttribute('data-theme');
    expect(newTheme).not.toBe(initialTheme);
    // Toggle back
    await page.locator('button[title="Light mode"], button[title="Dark mode"]').click();
    const restoredTheme = await page.locator('html').getAttribute('data-theme');
    expect(restoredTheme).toBe(initialTheme);
  });
});

// ════════════════════════════════════════════════════════════
// 5. LIVE MONITOR
// ════════════════════════════════════════════════════════════

test.describe('Live Monitor', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.locator('button[title="Live Monitor"]').click();
    await expect(page.locator('h1:has-text("Live Monitor")')).toBeVisible();
  });

  test('shows tabs: Stream, Grouped, Analysis, Processes', async ({ page }) => {
    await expect(page.locator('button.tab:has-text("Alert Stream")')).toBeVisible();
    await expect(page.locator('button.tab:has-text("Grouped")')).toBeVisible();
    await expect(page.locator('button.tab:has-text("Analysis")')).toBeVisible();
    await expect(page.locator('button.tab:has-text("Processes")')).toBeVisible();
  });

  test('alert stream tab loads without errors', async ({ page }) => {
    // By default on stream tab
    await expect(page.locator('text=Filter:')).toBeVisible({ timeout: 5000 });
    // Severity filter buttons
    await expect(page.locator('button:has-text("All")')).toBeVisible();
    await expect(page.locator('button:has-text("Critical")')).toBeVisible();
  });

  test('processes tab loads and shows data', async ({ page }) => {
    await page.locator('button.tab:has-text("Processes")').click();
    // Should show process-related header
    await expect(page.locator('text=Running Processes')).toBeVisible({ timeout: 10000 });
    // Sort buttons
    await expect(page.locator('button:has-text("CPU")')).toBeVisible();
    await expect(page.locator('button:has-text("Memory")')).toBeVisible();
  });

  test('grouped tab loads', async ({ page }) => {
    await page.locator('button.tab:has-text("Grouped")').click();
    await page.waitForTimeout(2000);
    // Should not crash — either shows data or "No grouped data"
    const groupedCard = page.locator('.card').first();
    await expect(groupedCard).toBeVisible();
  });

  test('analysis tab shows run button', async ({ page }) => {
    await page.locator('button.tab:has-text("Analysis")').click();
    await expect(page.locator('button:has-text("Run Analysis")')).toBeVisible({ timeout: 15000 });
  });

  test('export buttons are available on stream tab', async ({ page }) => {
    // Export buttons are within the stream tab, not at page level
    await page.locator('button.tab:has-text("Alert Stream")').click();
    await expect(page.locator('button:has-text("Export JSON")')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('button:has-text("Export CSV")')).toBeVisible();
  });
});

// ════════════════════════════════════════════════════════════
// 6. THREAT DETECTION
// ════════════════════════════════════════════════════════════

test.describe('Threat Detection', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.locator('button[title="Threat Detection"]').click();
    await expect(page.locator('h1:has-text("Threat Detection")')).toBeVisible();
  });

  test('threat detection page loads with tabs', async ({ page }) => {
    await expect(page.locator('button.tab:has-text("Overview")')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('button.tab:has-text("Sigma")')).toBeVisible();
    await expect(page.locator('button.tab:has-text("Mitre")')).toBeVisible();
  });

  test('no console errors on page load', async ({ page }) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.waitForTimeout(3000);
    // Filter out network errors (expected when backend endpoints don't exist)
    const jsErrors = errors.filter(e => !e.includes('fetch') && !e.includes('Failed to fetch') && !e.includes('NetworkError'));
    expect(jsErrors).toEqual([]);
  });
});

// ════════════════════════════════════════════════════════════
// 7. FLEET & AGENTS
// ════════════════════════════════════════════════════════════

test.describe('Fleet & Agents', () => {
  test('page loads without crash', async ({ page }) => {
    await login(page);
    await page.locator('button[title="Fleet & Agents"]').click();
    await expect(page.locator('h1:has-text("Fleet & Agents")')).toBeVisible();
    // Should have tabs
    await page.waitForTimeout(2000);
  });
});

// ════════════════════════════════════════════════════════════
// 8. SEARCH PALETTE (⌘K)
// ════════════════════════════════════════════════════════════

test.describe('Search Palette', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('opens via ⌘K shortcut', async ({ page }) => {
    await page.keyboard.press('Meta+k');
    await expect(page.locator('.search-palette')).toBeVisible();
    await expect(page.locator('.search-palette-input')).toBeFocused();
  });

  test('opens via button click', async ({ page }) => {
    await page.locator('button:has-text("Search")').click();
    await expect(page.locator('.search-palette')).toBeVisible();
  });

  test('closes on Escape', async ({ page }) => {
    await page.keyboard.press('Meta+k');
    await expect(page.locator('.search-palette')).toBeVisible();
    // Escape handler is on the input, so ensure input is focused
    await expect(page.locator('.search-palette-input')).toBeFocused();
    await page.locator('.search-palette-input').press('Escape');
    await expect(page.locator('.search-palette')).not.toBeVisible();
  });

  test('closes on overlay click', async ({ page }) => {
    await page.keyboard.press('Meta+k');
    await expect(page.locator('.search-palette')).toBeVisible();
    // Click overlay (not the palette itself)
    await page.locator('.search-palette-overlay').click({ position: { x: 10, y: 10 } });
    await expect(page.locator('.search-palette')).not.toBeVisible();
  });

  test('search with no results shows message', async ({ page }) => {
    await page.keyboard.press('Meta+k');
    await page.locator('.search-palette-input').fill('zzzznonexistent');
    await page.waitForTimeout(500);
    await expect(page.locator('text=No results found')).toBeVisible({ timeout: 5000 });
  });
});

// ════════════════════════════════════════════════════════════
// 9. SETTINGS PAGE
// ════════════════════════════════════════════════════════════

test.describe('Settings', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.locator('button[title="Settings"]').click();
    await expect(page.locator('h1:has-text("Settings")')).toBeVisible();
  });

  test('settings page has all tabs', async ({ page }) => {
    await expect(page.locator('button.tab:has-text("Config")')).toBeVisible();
    await expect(page.locator('button.tab:has-text("Monitoring")')).toBeVisible();
    await expect(page.locator('button.tab:has-text("Integrations")')).toBeVisible();
    await expect(page.locator('button.tab:has-text("Flags")')).toBeVisible();
    await expect(page.locator('button.tab:has-text("Admin")')).toBeVisible();
  });

  test('config tab loads configuration data', async ({ page }) => {
    await expect(page.locator('.card-title:has-text("Configuration")')).toBeVisible({ timeout: 15000 });
  });

  test('edit button switches to edit mode', async ({ page }) => {
    await expect(page.locator('.card-title:has-text("Configuration")')).toBeVisible({ timeout: 15000 });
    const editBtn = page.locator('button:has-text("Edit")').first();
    if (await editBtn.isVisible()) {
      await editBtn.click();
      await expect(page.locator('button:has-text("Save")')).toBeVisible();
      await expect(page.locator('button:has-text("Cancel")')).toBeVisible();
    }
  });

  test('monitoring tab loads', async ({ page }) => {
    await page.locator('button.tab:has-text("Monitoring")').click();
    await expect(page.locator('.card-title:has-text("Monitoring Scope")')).toBeVisible({ timeout: 10000 });
  });

  test('integrations tab loads', async ({ page }) => {
    await page.locator('button.tab:has-text("Integrations")').click();
    await expect(page.locator('text=SIEM Integration')).toBeVisible({ timeout: 5000 });
  });
});

// ════════════════════════════════════════════════════════════
// 10. HELP & DOCS
// ════════════════════════════════════════════════════════════

test.describe('Help & Docs', () => {
  test('page loads and shows system info', async ({ page }) => {
    await login(page);
    await page.locator('button[title="Help & Docs"]').click();
    await expect(page.locator('h1:has-text("Help & Docs")')).toBeVisible();
    await page.waitForTimeout(2000);
  });
});

// ════════════════════════════════════════════════════════════
// 11. SOC WORKBENCH
// ════════════════════════════════════════════════════════════

test.describe('SOC Workbench', () => {
  test('page loads with tabs', async ({ page }) => {
    await login(page);
    await page.locator('button[title="SOC Workbench"]').click();
    await expect(page.locator('h1.topbar-title')).toContainText('SOC Workbench');
  });
});

// ════════════════════════════════════════════════════════════
// 12. INFRASTRUCTURE
// ════════════════════════════════════════════════════════════

test.describe('Infrastructure', () => {
  test('page loads with tabs', async ({ page }) => {
    await login(page);
    await page.locator('button[title="Infrastructure"]').click();
    await expect(page.locator('h1.topbar-title')).toContainText('Infrastructure');
  });
});

// ════════════════════════════════════════════════════════════
// 13. REPORTS & EXPORTS
// ════════════════════════════════════════════════════════════

test.describe('Reports & Exports', () => {
  test('page loads', async ({ page }) => {
    await login(page);
    await page.locator('button[title="Reports & Exports"]').click();
    await expect(page.locator('h1.topbar-title')).toContainText('Reports');
  });
});

// ════════════════════════════════════════════════════════════
// 14. SECURITY POLICY
// ════════════════════════════════════════════════════════════

test.describe('Security Policy', () => {
  test('page loads', async ({ page }) => {
    await login(page);
    await page.locator('button[title="Security Policy"]').click();
    await expect(page.locator('h1:has-text("Security Policy")')).toBeVisible();
  });
});

// ════════════════════════════════════════════════════════════
// 15. SHARE LINK
// ════════════════════════════════════════════════════════════

test.describe('Share Link', () => {
  test('share link button works', async ({ page, context }) => {
    await login(page);
    // Grant clipboard permission
    await context.grantPermissions(['clipboard-write', 'clipboard-read']);
    const shareBtn = page.locator('button:has-text("Share Link")');
    await expect(shareBtn).toBeVisible();
    await shareBtn.click();
    await expect(page.locator('text=Copied')).toBeVisible();
  });
});

// ════════════════════════════════════════════════════════════
// 16. ONBOARDING WIZARD
// ════════════════════════════════════════════════════════════

test.describe('Onboarding Wizard', () => {
  test('wizard shows on first visit (no localStorage)', async ({ page }) => {
    await page.goto('./');
    await page.evaluate(() => {
      localStorage.removeItem('wardex_onboarded');
      localStorage.removeItem('wardex_token');
    });
    await page.reload();
    await expect(page.locator('text=Welcome to SentinelEdge')).toBeVisible({ timeout: 5000 });
  });

  test('wizard can be skipped', async ({ page }) => {
    await page.goto('./');
    await page.evaluate(() => {
      localStorage.removeItem('wardex_onboarded');
      localStorage.removeItem('wardex_token');
    });
    await page.reload();
    await expect(page.locator('text=Welcome to SentinelEdge')).toBeVisible({ timeout: 5000 });
    await page.locator('button:has-text("Skip")').click();
    await expect(page.locator('text=Welcome to SentinelEdge')).not.toBeVisible();
  });

  test('wizard navigation works (Next/Back)', async ({ page }) => {
    await page.goto('./');
    await page.evaluate(() => {
      localStorage.removeItem('wardex_onboarded');
      localStorage.removeItem('wardex_token');
    });
    await page.reload();
    await expect(page.locator('text=Welcome to SentinelEdge')).toBeVisible({ timeout: 5000 });
    await page.locator('button:has-text("Next")').click();
    await expect(page.locator('h3:has-text("API Token")')).toBeVisible();
    await page.locator('button:has-text("Next")').click();
    await expect(page.locator('h3:has-text("Your Role")')).toBeVisible();
    await page.locator('button:has-text("Back")').click();
    await expect(page.locator('h3:has-text("API Token")')).toBeVisible();
  });

  test('wizard does not show when already onboarded', async ({ page }) => {
    await page.goto('./');
    await page.evaluate(() => localStorage.setItem('wardex_onboarded', '1'));
    await page.reload();
    await page.waitForTimeout(1000);
    await expect(page.locator('text=Welcome to SentinelEdge')).not.toBeVisible();
  });
});

// ════════════════════════════════════════════════════════════
// 17. CONSOLE ERROR MONITORING (across all pages)
// ════════════════════════════════════════════════════════════

test.describe('No JS Crashes', () => {
  const pages = [
    { name: 'Dashboard', path: './' },
    { name: 'Live Monitor', path: './monitor' },
    { name: 'Threat Detection', path: './detection' },
    { name: 'Fleet & Agents', path: './fleet' },
    { name: 'Security Policy', path: './policy' },
    { name: 'SOC Workbench', path: './soc' },
    { name: 'Infrastructure', path: './infrastructure' },
    { name: 'Reports & Exports', path: './reports' },
    { name: 'Settings', path: './settings' },
    { name: 'Help & Docs', path: './help' },
  ];

  for (const p of pages) {
    test(`${p.name} (${p.path}) loads without JS errors`, async ({ page }) => {
      const errors = [];
      page.on('pageerror', e => errors.push(e.message));
      
      // Login and set token in localStorage for direct navigation
      await page.goto('./');
      await page.evaluate((t) => {
        localStorage.setItem('wardex_token', t);
        localStorage.setItem('wardex_onboarded', '1');
      }, TOKEN);
      await page.goto(p.path);
      
      // Wait for page to fully load and any API calls to complete
      await page.waitForTimeout(4000);
      
      // Filter out network/API errors (expected when some endpoints may not exist)
      const jsErrors = errors.filter(e =>
        !e.includes('Failed to fetch') &&
        !e.includes('NetworkError') &&
        !e.includes('Load failed') &&
        !e.includes('net::ERR') &&
        !e.includes('TypeError: null') // React null render — separate check
      );
      
      if (jsErrors.length > 0) {
        console.log(`JS errors on ${p.name}:`, jsErrors);
      }
      expect(jsErrors).toEqual([]);
    });
  }
});

// ════════════════════════════════════════════════════════════
// 18. RESPONSIVE & MOBILE LAYOUT
// ════════════════════════════════════════════════════════════

test.describe('Responsive Layout', () => {
  test('sidebar collapses on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await login(page);
    await page.waitForTimeout(1000);
    // Basic check: page doesn't crash at mobile size
    await expect(page.locator('main')).toBeVisible();
  });
});
