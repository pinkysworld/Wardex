/* ═══════════════════════════════════════════════════════════════════════════
   Wardex — Site Logic v6
   Product-oriented landing page with lightweight progressive enhancement.
   ═══════════════════════════════════════════════════════════════════════════ */

const RELEASE_VERSION = "0.56.0";
const MODULE_COUNT = "139";
const API_COUNT = "163";
const TEST_COUNT = "1500+";

const SITE_ROUTES = [
  { id: "overview", label: "Overview", file: "index.html", slug: "", nav: "primary" },
  { id: "features", label: "Features", file: "features.html", slug: "features", nav: "primary" },
  { id: "architecture", label: "Architecture", file: "architecture.html", slug: "architecture", nav: "primary" },
  { id: "rules", label: "Rules", file: "rules.html", slug: "rules", nav: "primary" },
  { id: "resources", label: "Resources", file: "resources.html", slug: "resources", nav: "primary" },
  { id: "pricing", label: "Pricing", file: "pricing.html", slug: "pricing", nav: "primary" },
  { id: "support", label: "Support", file: "donate.html", slug: "support", nav: "primary" },
  { id: "comparison", label: "Comparison", file: "comparison.html", slug: "comparison", nav: "secondary" },
  { id: "integrations", label: "Integrations", file: "integrations.html", slug: "integrations", nav: "secondary" },
  { id: "api", label: "API", file: "api.html", slug: "api", nav: "secondary" },
  { id: "status", label: "Status", file: "status.html", slug: "status", nav: "secondary" },
  { id: "changelog", label: "Changelog", file: "changelog.html", slug: "changelog", nav: "secondary" },
];

const SITE_ROUTE_BY_FILE = new Map(SITE_ROUTES.map((route) => [route.file, route]));
const SITE_ROUTE_BY_SLUG = new Map(
  SITE_ROUTES.filter((route) => route.slug).map((route) => [route.slug, route]),
);
const SITE_STANDALONE_FILES = new Set(["404.html", "checkout.html"]);

const stats = [
  { value: RELEASE_VERSION, label: "current version" },
  { value: MODULE_COUNT, label: "Rust modules" },
  { value: API_COUNT, label: "API paths" },
  { value: TEST_COUNT, label: "automated tests" },
];

function setText(selector, value) {
  const node = document.querySelector(selector);
  if (node) node.textContent = value;
}

function stripTrailingSlash(path) {
  if (!path) return "/";
  const trimmed = path.replace(/\/+$/, "");
  return trimmed || "/";
}

function isHttpUrl(value) {
  return /^https?:\/\//i.test(value);
}

function splitHref(value) {
  const [pathAndQuery, hash = ""] = String(value || "").split("#", 2);
  const [path = "", query = ""] = pathAndQuery.split("?", 2);
  return {
    path,
    query: query ? `?${query}` : "",
    hash: hash ? `#${hash}` : "",
  };
}

function siteContext(pathname = window.location.pathname) {
  const rawPath = pathname || "/";
  const trimmedPath = stripTrailingSlash(rawPath);
  const segments = trimmedPath.split("/").filter(Boolean);
  const leaf = segments.at(-1) || "";

  if (leaf && leaf.endsWith(".html")) {
    const route = SITE_ROUTE_BY_FILE.get(leaf) || null;
    const baseSegments = segments.slice(0, -1);
    return {
      basePath: baseSegments.length ? `/${baseSegments.join("/")}` : "/",
      rawPath,
      trimmedPath,
      leaf,
      route,
      file: leaf,
    };
  }

  if (leaf && SITE_ROUTE_BY_SLUG.has(leaf)) {
    const route = SITE_ROUTE_BY_SLUG.get(leaf);
    const baseSegments = segments.slice(0, -1);
    return {
      basePath: baseSegments.length ? `/${baseSegments.join("/")}` : "/",
      rawPath,
      trimmedPath,
      leaf,
      route,
      file: route.file,
    };
  }

  const route = SITE_ROUTE_BY_FILE.get("index.html");
  return {
    basePath: trimmedPath,
    rawPath,
    trimmedPath,
    leaf,
    route: null,
    file: null,
  };
}

function siteRouteHref(route, basePath = siteContext().basePath) {
  const normalizedBase = stripTrailingSlash(basePath);
  const prefix = normalizedBase === "/" ? "" : normalizedBase;
  return route.slug ? `${prefix}/${route.slug}/` : `${prefix}/`;
}

function siteFileHref(route, basePath = siteContext().basePath) {
  const normalizedBase = stripTrailingSlash(basePath);
  const prefix = normalizedBase === "/" ? "" : normalizedBase;
  return `${prefix}/${route.file}`;
}

function resolveKnownSiteHref(rawHref) {
  const { path, query, hash } = splitHref(rawHref);
  if (!path || path.startsWith("#") || path.startsWith("mailto:") || path.startsWith("tel:")) {
    return null;
  }
  if (isHttpUrl(path)) return null;

  const normalizedPath = path.replace(/^\.\//, "");
  const route = SITE_ROUTE_BY_FILE.get(normalizedPath);
  if (!route) return null;

  return `${siteRouteHref(route)}${query}${hash}`;
}

function syncSiteMetadata() {
  if (!/^https?:$/i.test(window.location.protocol)) return;

  const context = siteContext();
  const route = context.route || SITE_ROUTE_BY_FILE.get("index.html");
  const canonicalHref = route ? siteRouteHref(route, context.basePath) : `${context.basePath}/`;
  const canonicalUrl = new URL(canonicalHref, window.location.origin).toString();

  const canonical = document.querySelector('link[rel="canonical"]');
  if (canonical) canonical.setAttribute("href", canonicalUrl);

  const ogUrl = document.querySelector('meta[property="og:url"]');
  if (ogUrl) ogUrl.setAttribute("content", canonicalUrl);
}

function buildSharedNav() {
  const nav = document.getElementById("site-nav");
  if (!nav) return;

  const context = siteContext();
  if (SITE_STANDALONE_FILES.has(context.file)) return;
  if (nav.dataset.sharedNav === "true") return;

  const activeId = context.route?.id || "overview";
  const primary = SITE_ROUTES.filter((route) => route.nav === "primary");
  const secondary = SITE_ROUTES.filter((route) => route.nav === "secondary");

  const primaryLinks = primary
    .map((route) => {
      const active = route.id === activeId ? " active" : "";
      return `<a href="${siteRouteHref(route, context.basePath)}" class="nav-link${active}">${route.label}</a>`;
    })
    .join("");

  const moreIsActive = secondary.some((route) => route.id === activeId);
  const secondaryLinks = secondary
    .map((route) => {
      const active = route.id === activeId ? ' class="active"' : "";
      return `<a href="${siteRouteHref(route, context.basePath)}"${active}>${route.label}</a>`;
    })
    .join("");

  nav.innerHTML = `
    <div class="nav-inner">
      <a class="nav-brand" href="${siteRouteHref(SITE_ROUTE_BY_FILE.get("index.html"), context.basePath)}">
        <span class="nav-logo">WX</span>
        <span class="nav-title">Wardex</span>
      </a>
      <button class="nav-toggle" id="nav-toggle" aria-label="Toggle navigation" aria-expanded="false">
        <span></span><span></span><span></span>
      </button>
      <div class="nav-links" id="nav-links">
        ${primaryLinks}
        <div class="nav-dropdown">
          <button type="button" class="nav-link nav-dropdown-trigger${moreIsActive ? " active" : ""}" aria-haspopup="true" aria-expanded="false">
            More
            <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M4.47 6.97a.75.75 0 0 1 1.06 0L8 9.44l2.47-2.47a.75.75 0 1 1 1.06 1.06l-3 3a.75.75 0 0 1-1.06 0l-3-3a.75.75 0 0 1 0-1.06z"/></svg>
          </button>
          <div class="nav-dropdown-menu">
            ${secondaryLinks}
          </div>
        </div>
        <a href="https://github.com/pinkysworld/Wardex" class="nav-link nav-link-icon" target="_blank" rel="noopener" aria-label="GitHub">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
        </a>
      </div>
    </div>
  `;
  nav.dataset.sharedNav = "true";
}

function rewriteKnownSiteLinks() {
  document.querySelectorAll("a[href]").forEach((link) => {
    const rawHref = link.getAttribute("href");
    const resolved = resolveKnownSiteHref(rawHref);
    if (resolved) link.setAttribute("href", resolved);
  });
}

function maybeRedirectKnownSiteRoute() {
  const isNotFoundPage = Boolean(document.querySelector(".notfound"));
  if (!isNotFoundPage) return;

  const path = window.location.pathname;
  const context = siteContext(path);
  const { search, hash } = window.location;

  if (context.route && context.file !== "404.html") {
    const target = siteFileHref(context.route, context.basePath);
    if (stripTrailingSlash(target) !== stripTrailingSlash(path)) {
      window.location.replace(`${target}${search}${hash}`);
      return;
    }
  }

  if (context.leaf === "site") {
    window.location.replace(`${stripTrailingSlash(path)}/index.html${search}${hash}`);
    return;
  }

  if (!path.endsWith("/") && !path.endsWith(".html")) {
    window.location.replace(`${path}/${search}${hash}`);
  }
}

function applyReleaseCopy() {
  setText("#license-version", `v${RELEASE_VERSION}`);
  setText("#footer-version", `v${RELEASE_VERSION}`);
  setText("#footer-about-module-count", MODULE_COUNT);
  setText("#footer-about-api-count", API_COUNT);
  setText("#footer-about-test-count", TEST_COUNT);
  setText("#footer-release-module-count", MODULE_COUNT);
  setText("#footer-release-test-count", TEST_COUNT);
}

const pipelineDetails = [
  {
    num: "01",
    title: "Detection Engineering",
    body: "Manage Sigma and native rules, test against retained events, promote or roll back, maintain suppressions, schedule hunts, and bridge kernel-level events directly into your Sigma rule library.",
    note: "Includes hunts, content lifecycle, suppressions, MITRE coverage, false-positive advisor actions, and a route-driven hunt drawer for inline run/save workflows."
  },
  {
    num: "02",
    title: "SOC Workbench",
    body: "Queue, cases, incident pivots, timelines, process trees, storyline views, and entity extraction keep analysts inside one investigation surface with full context.",
    note: "Investigation planners can now suggest builtin workflows from incident or alert context and pivot directly into a prefilled hunt."
  },
  {
    num: "03",
    title: "Threat Hunting & Intelligence",
    body: "Fleet campaign clustering, deception engine with randomized canary deployment, attacker behavior profiling, threat-feed polling, and named entity extraction power proactive threat hunts.",
    note: "Campaign detection uses Jaccard similarity to correlate fleet-wide attack patterns across agents."
  },
  {
    num: "04",
    title: "Fleet Operations",
    body: "Enrollment, heartbeat freshness, policy distribution, deployment assignment, rollout groups, rollback, file integrity monitoring, and per-agent activity snapshots.",
    note: "FIM continuously monitors critical system paths and detects unauthorized changes with SHA-256 verification."
  },
  {
    num: "05",
    title: "Advanced Analytics & AI",
    body: "Side-channel score fusion, UEBA geo-validation with impossible-travel detection, EWMA drift tracking, digital twin calibration, federated learning convergence, and memory forensics.",
    note: "Memory forensics detects code injection, process hollowing, and RWX regions across platforms."
  },
  {
    num: "06",
    title: "Enterprise Governance",
    body: "RBAC, session rotation, IDP/SCIM configuration, admin audit export, change control, diagnostics, dependency health, and privacy-preserving federated model training.",
    note: "Private-cloud and self-hosted, with documentation, runbooks, and release automation shipped in-repo."
  },
];

const interfaceFields = [
  { name: "CLI", desc: "Single binary for serve, analyze, report, bench, status, and attestation workflows." },
  { name: "Admin UI", desc: "Static and live browser console with dashboard, workbench, fleet, detection, and settings views." },
  { name: "REST API", desc: "Authenticated HTTP control plane documented by the versioned OpenAPI specification." },
  { name: "Runbooks", desc: "Operator guides for agents, SIEM integrations, and incident response workflows." },
  { name: "Releases", desc: "Tagged builds package Linux, macOS, and Windows archives through GitHub Actions." },
  { name: "Docs", desc: "Deployment, threat model, disaster recovery, SLO, and roadmap docs are shipped with the repo." },
];

function renderStats() {
  const targets = [
    document.getElementById("stats-grid"),
    document.getElementById("stat-strip"),
  ].filter(Boolean);
  if (targets.length === 0) return;
  targets.forEach((el) => {
    stats.forEach((s) => {
      const div = document.createElement("div");
      div.className = "stat-item";
      div.innerHTML = `<span class="stat-value">${s.value}</span><span class="stat-label">${s.label}</span>`;
      el.appendChild(div);
    });
  });
}

function renderPipelineDetails() {
  const el = document.getElementById("pipeline-details");
  if (!el) return;
  pipelineDetails.forEach((d, i) => {
    const card = document.createElement("div");
    card.className = "detail-card";
    card.style.setProperty("--stagger", `${i * 80}ms`);
    card.setAttribute("data-delay", "");
    card.innerHTML = `
      <h3><span class="detail-num">${d.num}</span>${d.title}</h3>
      <p>${d.body}</p>
      ${d.note ? `<p class="detail-note">${d.note}</p>` : ""}
    `;
    el.appendChild(card);
  });
}

function renderInterfaces() {
  const el = document.getElementById("field-grid");
  if (!el) return;
  interfaceFields.forEach((f) => {
    const div = document.createElement("div");
    div.className = "field-item";
    div.innerHTML = `<code>${f.name}</code><span>${f.desc}</span>`;
    el.appendChild(div);
  });
}

function initResourceSearch() {
  const input = document.getElementById("resource-search");
  if (!input) return;

  const cards = Array.from(document.querySelectorAll("[data-resource-card]"));
  const count = document.getElementById("resource-count");
  const empty = document.getElementById("resource-empty");

  const applyFilter = () => {
    const query = input.value.trim().toLowerCase();
    let visible = 0;

    cards.forEach((card) => {
      const haystack = `${card.dataset.search || ""} ${card.textContent || ""}`.toLowerCase();
      const match = !query || haystack.includes(query);
      card.hidden = !match;
      if (match) visible += 1;
    });

    if (count) {
      count.textContent = `${visible} resource${visible === 1 ? "" : "s"} visible`;
    }
    if (empty) {
      empty.hidden = visible !== 0;
    }
  };

  input.addEventListener("input", applyFilter);
  applyFilter();
}

function initNav() {
  const nav = document.getElementById("site-nav");
  const toggle = document.getElementById("nav-toggle");
  const links = document.getElementById("nav-links");
  const dropdowns = Array.from(document.querySelectorAll(".nav-dropdown"));

  const closeDropdowns = () => {
    dropdowns.forEach((dropdown) => {
      dropdown.classList.remove("open");
      const trigger = dropdown.querySelector(".nav-dropdown-trigger");
      if (trigger) trigger.setAttribute("aria-expanded", "false");
    });
  };

  if (toggle && links) {
    toggle.addEventListener("click", () => {
      const open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
      if (!open) closeDropdowns();
    });
  }

  document.querySelectorAll(".nav-dropdown-trigger").forEach((trigger) => {
    trigger.addEventListener("click", (e) => {
      const dropdown = trigger.closest(".nav-dropdown");
      if (!dropdown) return;
      if (window.innerWidth <= 768) {
        e.preventDefault();
        const open = dropdown.classList.toggle("open");
        trigger.setAttribute("aria-expanded", String(open));
      }
    });
  });

  document.querySelectorAll(".nav-dropdown-menu a, .nav-links > .nav-link").forEach((link) => {
    link.addEventListener("click", () => {
      if (links) links.classList.remove("open");
      if (toggle) toggle.setAttribute("aria-expanded", "false");
      closeDropdowns();
    });
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest(".nav-dropdown")) closeDropdowns();
  });

  const sections = document.querySelectorAll("section[id]");
  const allNavLinks = document.querySelectorAll("[data-section]");

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        const id = entry.target.id;
        allNavLinks.forEach((link) => link.classList.remove("active"));
        const match = document.querySelector(`[data-section="${id}"]`);
        if (match) match.classList.add("active");
      }
    });
  }, { rootMargin: "-30% 0px -60% 0px" });

  sections.forEach((section) => observer.observe(section));

  window.addEventListener("scroll", () => {
    if (!nav) return;
    if (window.scrollY > 80) nav.classList.add("scrolled");
    else nav.classList.remove("scrolled");
  }, { passive: true });
}

function initScrollReveal() {
  const targets = document.querySelectorAll(
    ".section-header, .detail-card, .status-col, .start-card, " +
    ".stat-card, .console-preview, .module-table, .csv-format, " +
    ".capability-card, .hunting-card, .analytics-item, .license-card, .license-notice, " +
    ".support-card, .impact-card, .faq-card, " +
    ".pillar-card, .trust-card, .feature-cell"
  );

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("visible");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.08, rootMargin: "0px 0px -40px 0px" });

  targets.forEach((target) => {
    target.classList.add("reveal");
    const siblings = target.parentElement ? target.parentElement.querySelectorAll(":scope > .reveal") : [];
    if (siblings.length > 1) {
      const idx = Array.from(siblings).indexOf(target);
      target.style.transitionDelay = `${idx * 80}ms`;
    }
    observer.observe(target);
  });
}

function initCopyButtons() {
  const targets = document.querySelectorAll(".terminal-snippet, .console-output, pre.copyable");
  targets.forEach((el) => {
    if (el.querySelector(".copy-btn")) return;
    const code = el.querySelector("code") || el;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.setAttribute("aria-label", "Copy to clipboard");
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M4 1.5A1.5 1.5 0 0 1 5.5 0h7A1.5 1.5 0 0 1 14 1.5v10a1.5 1.5 0 0 1-1.5 1.5H10v1.5A1.5 1.5 0 0 1 8.5 16h-7A1.5 1.5 0 0 1 0 14.5v-10A1.5 1.5 0 0 1 1.5 3H4V1.5zm1 0v1h7.5a1.5 1.5 0 0 1 1.5 1.5V11h.5a.5.5 0 0 0 .5-.5v-9a.5.5 0 0 0-.5-.5h-7a.5.5 0 0 0-.5.5zM1.5 4a.5.5 0 0 0-.5.5v10a.5.5 0 0 0 .5.5h7a.5.5 0 0 0 .5-.5v-10a.5.5 0 0 0-.5-.5h-7z"/></svg><span>Copy</span>`;
    btn.addEventListener("click", async () => {
      const text = (code.innerText || code.textContent || "").trim();
      try {
        await navigator.clipboard.writeText(text);
        btn.classList.add("copied");
        const label = btn.querySelector("span");
        if (label) label.textContent = "Copied";
        setTimeout(() => {
          btn.classList.remove("copied");
          if (label) label.textContent = "Copy";
        }, 1600);
      } catch (_err) {
        const range = document.createRange();
        range.selectNodeContents(code);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
    });
    el.appendChild(btn);
  });
}

function initPricingToggle() {
  const buttons = document.querySelectorAll(".pricing-toggle-btn");
  if (buttons.length === 0) return;
  const amounts = document.querySelectorAll(".tier-amount[data-price-monthly]");
  const apply = (period) => {
    buttons.forEach((b) => {
      const on = b.dataset.period === period;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", String(on));
    });
    amounts.forEach((el) => {
      const v = period === "annual" ? el.dataset.priceAnnual : el.dataset.priceMonthly;
      if (v) el.textContent = v;
    });
  };
  buttons.forEach((b) => b.addEventListener("click", () => apply(b.dataset.period)));
}

document.addEventListener("DOMContentLoaded", () => {
  buildSharedNav();
  rewriteKnownSiteLinks();
  syncSiteMetadata();
  renderStats();
  applyReleaseCopy();
  renderPipelineDetails();
  renderInterfaces();
  initResourceSearch();
  initNav();
  initCopyButtons();
  initPricingToggle();
  requestAnimationFrame(() => initScrollReveal());
});

maybeRedirectKnownSiteRoute();
