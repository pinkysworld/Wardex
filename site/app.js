/* ═══════════════════════════════════════════════════════════════════════════
   Wardex — Site Logic v6
   Product-oriented landing page with lightweight progressive enhancement.
   ═══════════════════════════════════════════════════════════════════════════ */

const stats = [
  { value: "61", label: "Rust modules" },
  { value: "117", label: "OpenAPI paths" },
  { value: "692", label: "automated tests" },
  { value: "3", label: "release targets" },
];

const pipelineDetails = [
  {
    num: "01",
    title: "Detection Engineering",
    body: "Operators can manage Sigma and native rules, test them against retained events, promote or roll them back, maintain suppressions, and schedule saved hunts from the same control plane.",
    note: "The enterprise release adds hunts, content lifecycle, suppressions, packs, and MITRE coverage views."
  },
  {
    num: "02",
    title: "SOC Workbench",
    body: "Queue, cases, incident pivots, timelines, process trees, and storyline views keep analysts inside one investigation surface instead of bouncing across disconnected pages.",
    note: "Investigation state carries forward into evidence export and approval-aware response actions."
  },
  {
    num: "03",
    title: "Fleet Operations",
    body: "Enrollment, heartbeat freshness, policy distribution, deployment assignment, rollout groups, rollback, and per-agent activity snapshots give operators concrete control over endpoint lifecycle.",
    note: "Release operations are exposed in both the API and the browser console."
  },
  {
    num: "04",
    title: "Enterprise Governance",
    body: "RBAC, session rotation, IDP and SCIM configuration, admin audit export, change control, diagnostics, and dependency health are treated as first-class product surfaces.",
    note: "The release posture is private-cloud and self-hosted, with documentation and runbooks shipped in-repo."
  },
  {
    num: "05",
    title: "Integrations & Evidence",
    body: "SIEM connectors, TAXII pull, threat-intel enrichment, ticket sync, compliance evidence, and forensic exports keep Wardex useful inside broader enterprise tooling and reporting workflows.",
    note: "Evidence packages and storyline exports make incident handoff far easier."
  },
  {
    num: "06",
    title: "Supportability",
    body: "Diagnostics bundles, dependency health, operator docs, deployment models, and release packaging reduce the gap between a powerful prototype and a product teams can actually run.",
    note: "The public site now emphasizes those product surfaces instead of backlog-history sections."
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
  const el = document.getElementById("stats-grid");
  if (!el) return;
  stats.forEach((s) => {
    const div = document.createElement("div");
    div.className = "stat-item";
    div.innerHTML = `<span class="stat-value">${s.value}</span><span class="stat-label">${s.label}</span>`;
    el.appendChild(div);
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
    ".stat-card, .console-preview, .module-table, .csv-format"
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
  renderPipelineDetails();
  renderInterfaces();
  initNav();
  requestAnimationFrame(() => initScrollReveal());
});
