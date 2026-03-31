/* ═══════════════════════════════════════════════════════════════════════════
   Wardex — Admin Console v2
   Sidebar dashboard with overview, status, and report views.
   ═══════════════════════════════════════════════════════════════════════════ */

const STATUS_URL = "data/status.json";
const REPORT_URL = "data/demo-report.json";

const CMD_INFO = {
  demo:          { desc: "Run built-in demo trace and write audit output", mode: "CLI" },
  analyze:       { desc: "Analyze CSV or JSONL telemetry", mode: "CLI" },
  report:        { desc: "Export structured JSON report", mode: "CLI" },
  "init-config": { desc: "Write default TOML config", mode: "CLI" },
  status:        { desc: "Human-readable implementation snapshot", mode: "CLI" },
  "status-json": { desc: "Export structured JSON for browser console", mode: "CLI + Browser" },
};

// ── State ────────────────────────────────────────────────────────────────────

let currentStatus = null;
let currentReport = null;
let selectedIdx   = -1;

// ── Helpers ──────────────────────────────────────────────────────────────────

const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html !== undefined) e.innerHTML = html; return e; };
const clear = (e) => { if (e) e.replaceChildren(); };
const fmt = (v, d = 2) => Number(v).toFixed(d);
const pct = (a, b) => b === 0 ? 0 : Math.round((a / b) * 100);

function sevClass(level) {
  const l = String(level || "").toLowerCase();
  if (l === "critical") return "sev-critical";
  if (l === "severe")   return "sev-severe";
  if (l === "elevated") return "sev-elevated";
  return "sev-nominal";
}

function setBanner(text, kind = "info") {
  const b = $("#console-banner");
  if (!b) return;
  b.textContent = text;
  b.dataset.kind = kind;
  b.hidden = false;
  clearTimeout(setBanner._t);
  setBanner._t = setTimeout(() => { b.hidden = true; }, 6000);
}

// ── SVG Progress Ring ────────────────────────────────────────────────────────

function renderRing(container, completed, total) {
  clear(container);
  const p = pct(completed, total);
  const r = 60, cx = 75, cy = 75;
  const circ = 2 * Math.PI * r;
  const offset = circ - (circ * p / 100);

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", "150");
  svg.setAttribute("height", "150");
  svg.setAttribute("viewBox", "0 0 150 150");
  svg.innerHTML = `
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#eef0f3" stroke-width="10"/>
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--accent)" stroke-width="10"
      stroke-linecap="round" stroke-dasharray="${circ}" stroke-dashoffset="${offset}"
      transform="rotate(-90 ${cx} ${cy})"
      style="--ring-circ:${circ};--ring-offset:${offset};animation:ringDraw 1s ease forwards;"/>
    <text x="${cx}" y="${cy - 4}" text-anchor="middle" class="ring-label">${p}%</text>
    <text x="${cx}" y="${cy + 14}" text-anchor="middle" class="ring-sub">${completed}/${total} tasks</text>
  `;
  container.appendChild(svg);
}

// ── Metric Cards ─────────────────────────────────────────────────────────────

function metricCard(label, value, sub, accent) {
  const c = el("div", `metric-card${accent ? " metric-accent" : ""}`);
  c.innerHTML = `
    <div class="metric-label">${label}</div>
    <div class="metric-value">${value}</div>
    ${sub ? `<div class="metric-sub">${sub}</div>` : ""}
  `;
  return c;
}

// ── CMD Grid ─────────────────────────────────────────────────────────────────

function renderCmds(container, commands) {
  clear(container);
  (commands || []).forEach(cmd => {
    const info = CMD_INFO[cmd] || { desc: "Command available", mode: "CLI" };
    const c = el("div", "cmd-card");
    c.innerHTML = `
      <div class="cmd-name">${cmd}</div>
      <div class="cmd-desc">${info.desc}</div>
      <span class="cmd-mode">${info.mode}</span>
    `;
    container.appendChild(c);
  });
}

// ── Implementation Lists ─────────────────────────────────────────────────────

function renderImplLists(container, manifest) {
  clear(container);

  const sections = [
    { title: "Implemented",      dot: "dot-green",  items: manifest.implemented || [] },
    { title: "Partially Wired",  dot: "dot-orange", items: manifest.partially_wired || [] },
    { title: "Not Implemented",  dot: "dot-gray",   items: manifest.not_implemented || [] },
  ];

  sections.forEach(sec => {
    if (!sec.items.length) return;
    const div = el("div");
    div.innerHTML = `<div class="impl-section-title"><span class="impl-dot ${sec.dot}"></span>${sec.title} (${sec.items.length})</div>`;
    const ul = el("ul", "impl-list");
    sec.items.forEach(text => {
      const li = el("li", "", "");
      li.textContent = text;
      ul.appendChild(li);
    });
    div.appendChild(ul);
    container.appendChild(div);
  });
}

// ── Status Columns ───────────────────────────────────────────────────────────

function renderStatusColumns(container, manifest) {
  clear(container);

  const cols = [
    { title: "Implemented",     cls: "green",  items: manifest.implemented || [] },
    { title: "Partially Wired", cls: "orange", items: manifest.partially_wired || [] },
    { title: "Not Implemented", cls: "gray",   items: manifest.not_implemented || [] },
  ];

  cols.forEach(c => {
    const col = el("div", "status-col");
    col.innerHTML = `
      <div class="status-col-head ${c.cls}">
        <span class="impl-dot dot-${c.cls}"></span>
        ${c.title} (${c.items.length})
      </div>
    `;
    const body = el("ul", "status-col-body");
    c.items.forEach(text => {
      const li = el("li", "", "");
      li.textContent = text;
      body.appendChild(li);
    });
    col.appendChild(body);
    container.appendChild(col);
  });
}

// ── Report Mini Bars ─────────────────────────────────────────────────────────

function renderReportMini(container, report) {
  clear(container);
  if (!report || !report.samples) {
    container.innerHTML = `<p class="empty-msg">No report loaded yet.</p>`;
    return;
  }

  const maxScore = report.summary.max_score || 1;
  const bars = el("div", "mini-bars");

  report.samples.forEach(s => {
    const p = Math.min(100, (s.anomaly.score / maxScore) * 100);
    const fillCls = s.decision.threat_level === "critical" ? "fill-red"
      : s.decision.threat_level === "severe" ? "fill-orange"
      : s.decision.threat_level === "elevated" ? "fill-orange"
      : "fill-neutral";

    const row = el("div", "mini-bar-row");
    row.innerHTML = `
      <span class="mini-bar-label">#${s.index}</span>
      <div class="mini-bar-track"><div class="mini-bar-fill ${fillCls}" style="width:${p}%"></div></div>
      <span class="mini-bar-value">${fmt(s.anomaly.score, 1)}</span>
    `;
    bars.appendChild(row);
  });

  container.appendChild(bars);
}

// ── Sample Detail ────────────────────────────────────────────────────────────

function kvGrid(entries) {
  const grid = el("div", "kv-grid");
  entries.forEach(([key, val]) => {
    const item = el("div", "kv-item");
    item.innerHTML = `<span class="kv-key">${key}</span><span class="kv-val">${val}</span>`;
    grid.appendChild(item);
  });
  return grid;
}

function renderDetail(sample) {
  const dc = $("#detail-content");
  clear(dc);

  if (!sample) {
    dc.innerHTML = `<p class="empty-msg">Select a sample from the list.</p>`;
    return;
  }

  const meta = el("div", "detail-meta");
  meta.innerHTML = `
    <span class="severity ${sevClass(sample.decision.threat_level)}">${sample.decision.threat_level}</span>
    <span>Sample #${sample.index}</span>
    <span>t = ${sample.timestamp_ms}</span>
  `;
  dc.appendChild(meta);

  // Telemetry
  const tb = el("div", "detail-block");
  tb.innerHTML = `<h3>Telemetry</h3>`;
  tb.appendChild(kvGrid([
    ["CPU", `${fmt(sample.telemetry.cpu_load_pct, 1)}%`],
    ["Memory", `${fmt(sample.telemetry.memory_load_pct, 1)}%`],
    ["Temp", `${fmt(sample.telemetry.temperature_c, 1)} °C`],
    ["Network", `${fmt(sample.telemetry.network_kbps, 0)} kbps`],
    ["Auth Failures", sample.telemetry.auth_failures],
    ["Battery", `${fmt(sample.telemetry.battery_pct, 1)}%`],
    ["Integrity Drift", fmt(sample.telemetry.integrity_drift, 3)],
  ]));
  dc.appendChild(tb);

  // Anomaly
  const ab = el("div", "detail-block");
  ab.innerHTML = `<h3>Anomaly Signal</h3>`;
  ab.appendChild(kvGrid([
    ["Score", fmt(sample.anomaly.score, 2)],
    ["Confidence", fmt(sample.anomaly.confidence, 2)],
    ["Suspicious Axes", sample.anomaly.suspicious_axes],
  ]));
  if (sample.anomaly.reasons?.length) {
    const rl = el("ul", "reason-list");
    sample.anomaly.reasons.forEach(r => {
      const li = el("li", "", "");
      li.textContent = r;
      rl.appendChild(li);
    });
    ab.appendChild(rl);
  }
  dc.appendChild(ab);

  // Decision
  const db = el("div", "detail-block");
  db.innerHTML = `<h3>Decision</h3>`;
  db.appendChild(kvGrid([
    ["Threat", sample.decision.threat_level],
    ["Action", sample.decision.action],
    ["Isolation", `${sample.decision.isolation_pct}%`],
    ["Rationale", sample.decision.rationale],
  ]));
  dc.appendChild(db);
}

function selectSample(idx) {
  selectedIdx = idx;
  const sample = currentReport?.samples?.[idx];
  renderDetail(sample);
  $$(".sample-row").forEach((r, i) => r.classList.toggle("selected", i === idx));
}

// ── Render Status ────────────────────────────────────────────────────────────

function renderStatus(manifest) {
  currentStatus = manifest;

  const bp = pct(manifest.backlog_completed, manifest.backlog_total);
  const pp = pct(manifest.completed_phases, manifest.total_phases);

  // Overview metrics
  const om = $("#overview-metrics");
  clear(om);
  om.append(
    metricCard("Updated", manifest.updated_at, "", false),
    metricCard("Backlog", `${manifest.backlog_completed}/${manifest.backlog_total}`, `${bp}% complete`, true),
    metricCard("Phases", `${manifest.completed_phases}/${manifest.total_phases}`, `${pp}% complete`, false),
    metricCard("CLI Commands", manifest.cli_commands.length, "Read-only console", false),
  );

  // Status view metrics
  const sm = $("#status-metrics");
  clear(sm);
  sm.append(
    metricCard("Updated", manifest.updated_at, "", false),
    metricCard("Backlog", `${manifest.backlog_completed}/${manifest.backlog_total}`, `${bp}% complete`, true),
    metricCard("Phases", `${manifest.completed_phases}/${manifest.total_phases}`, `${pp}% complete`, false),
    metricCard("CLI Commands", manifest.cli_commands.length, "", false),
  );

  // Ring
  renderRing($("#backlog-ring"), manifest.backlog_completed, manifest.backlog_total);

  // Tags
  const implTag = $("#impl-pct-tag");
  implTag.textContent = `${bp}%`;
  implTag.className = bp >= 75 ? "tag tag-green" : bp >= 50 ? "tag tag-orange" : "tag tag-red";

  // Impl lists
  renderImplLists($("#impl-lists"), manifest);

  // Status columns
  renderStatusColumns($("#status-columns"), manifest);

  // CMD grids
  renderCmds($("#cmd-grid"), manifest.cli_commands);
  renderCmds($("#cmd-grid-status"), manifest.cli_commands);

  // Topbar badge
  const tb = $("#topbar-status");
  if (tb) { tb.textContent = `${bp}% complete`; }
}

// ── Render Report ────────────────────────────────────────────────────────────

function renderReport(report) {
  currentReport = report;
  const s = report.summary;

  // Report view metrics
  const rm = $("#report-metrics");
  clear(rm);
  rm.append(
    metricCard("Samples", s.total_samples, report.generated_at || "", false),
    metricCard("Alerts", s.alert_count, `${s.critical_count} critical`, true),
    metricCard("Avg Score", fmt(s.average_score, 2), "", false),
    metricCard("Max Score", fmt(s.max_score, 2), "", false),
  );

  // Report tag in overview
  const rt = $("#report-tag");
  if (rt) {
    rt.textContent = `${s.alert_count} alerts`;
    rt.className = s.critical_count > 0 ? "tag tag-red" : s.alert_count > 0 ? "tag tag-orange" : "tag tag-green";
  }

  // Mini bars in overview
  renderReportMini($("#report-mini"), report);

  // Sample list
  const sl = $("#sample-list");
  clear(sl);

  (report.samples || []).forEach((sample, idx) => {
    const row = el("button", "sample-row");
    row.type = "button";
    row.innerHTML = `
      <span class="sample-idx">#${sample.index}</span>
      <span class="sample-score">
        <span class="severity ${sevClass(sample.decision.threat_level)}">${sample.decision.threat_level}</span>
        &nbsp; score ${fmt(sample.anomaly.score, 2)}
      </span>
      <span class="sample-action">${sample.decision.action}</span>
    `;
    row.addEventListener("click", () => selectSample(idx));
    sl.appendChild(row);
  });

  selectSample(report.samples?.length ? 0 : -1);
}

// ── Navigation ───────────────────────────────────────────────────────────────

function switchView(name) {
  $$(".dash-view").forEach(v => v.classList.remove("active"));
  const target = $(`#view-${name}`);
  if (target) target.classList.add("active");
  $$(".sidebar-link[data-view]").forEach(l => l.classList.toggle("active", l.dataset.view === name));
}

// ── File Loading ─────────────────────────────────────────────────────────────

async function fetchJson(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function readFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => { try { resolve(JSON.parse(String(reader.result))); } catch (e) { reject(e); } };
    reader.onerror = () => reject(reader.error || new Error("read error"));
    reader.readAsText(file);
  });
}

// ── Init ─────────────────────────────────────────────────────────────────────

function init() {
  // Sidebar nav
  $$(".sidebar-link[data-view]").forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      switchView(link.dataset.view);
      // Close mobile sidebar
      $("#sidebar").classList.remove("open");
    });
  });

  // Mobile toggle
  $("#sidebar-toggle")?.addEventListener("click", () => {
    $("#sidebar").classList.toggle("open");
  });

  // File inputs
  $("#status-file")?.addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      renderStatus(await readFile(file));
      setBanner(`Status loaded from ${file.name}`, "success");
    } catch (err) {
      setBanner(`Failed to parse status: ${err.message}`, "error");
    }
  });

  $("#report-file")?.addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      renderReport(await readFile(file));
      setBanner(`Report loaded from ${file.name}`, "success");
    } catch (err) {
      setBanner(`Failed to parse report: ${err.message}`, "error");
    }
  });

  // Buttons
  $("#load-default-all")?.addEventListener("click", loadAll);
  $("#load-default-status")?.addEventListener("click", async () => {
    try { renderStatus(await fetchJson(STATUS_URL)); setBanner("Bundled status loaded.", "success"); }
    catch (e) { setBanner(`Failed: ${e.message}`, "error"); }
  });
  $("#load-default-report")?.addEventListener("click", async () => {
    try { renderReport(await fetchJson(REPORT_URL)); setBanner("Bundled report loaded.", "success"); }
    catch (e) { setBanner(`Failed: ${e.message}`, "error"); }
  });

  // Hash-based initial view
  const hash = window.location.hash.replace("#", "");
  if (hash === "status") switchView("status");
  else if (hash === "reports") switchView("reports");

  // Auto-load bundled data
  loadAll();
}

async function loadAll() {
  try {
    const [status, report] = await Promise.all([fetchJson(STATUS_URL), fetchJson(REPORT_URL)]);
    renderStatus(status);
    renderReport(report);
    setBanner("Bundled status and demo report loaded.", "success");
  } catch (e) {
    setBanner(`Loaded without bundled data: ${e.message}`, "error");
  }
}

init();
