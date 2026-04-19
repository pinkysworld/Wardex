/* ═══════════════════════════════════════════════════════════════════════════
   Wardex — Site Logic v6
   Product-oriented landing page with lightweight progressive enhancement.
   ═══════════════════════════════════════════════════════════════════════════ */

const RELEASE_VERSION = "0.52.5";
const MODULE_COUNT = "134";
const API_COUNT = "138";
const TEST_COUNT = "1500+";

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

  if (toggle && links) {
    toggle.addEventListener("click", () => {
      const open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
  }

  document.querySelectorAll(".nav-dropdown-trigger").forEach((trigger) => {
    trigger.addEventListener("click", (e) => {
      if (window.innerWidth <= 768) {
        e.preventDefault();
        const dropdown = trigger.closest(".nav-dropdown");
        if (dropdown) dropdown.classList.toggle("open");
      }
    });
  });

  document.querySelectorAll(".nav-dropdown-menu a, .nav-links > .nav-link").forEach((link) => {
    link.addEventListener("click", () => {
      if (links) links.classList.remove("open");
      if (toggle) toggle.setAttribute("aria-expanded", "false");
    });
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
    ".section-header, .arch-stage, .detail-card, .status-col, .start-card, " +
    ".stat-card, .console-preview, .module-table, .csv-format, " +
    ".capability-card, .hunting-card, .analytics-item, .license-card, .license-notice, " +
    ".support-card, .impact-card, .faq-card, " +
    ".pillar-card, .trust-card, .deploy-model, .component-card, .feature-cell"
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

document.addEventListener("DOMContentLoaded", () => {
  renderStats();
  applyReleaseCopy();
  renderPipelineDetails();
  renderInterfaces();
  initResourceSearch();
  initNav();
  requestAnimationFrame(() => initScrollReveal());
});
