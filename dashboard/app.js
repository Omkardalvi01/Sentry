"use strict";
const $ = (s) => document.querySelector(s);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const names = {
  overview: "Overview",
  endpoints: "Endpoints",
  scans: "Scans",
  requests: "Scan requests",
  findings: "Findings",
  traffic: "Traffic",
  health: "System health",
};
const checks = {
  deprecated_alive: "Deprecated operation",
  version_probe: "Version variant",
  method_probe: "Method check",
  shadow_path: "Shadow endpoint",
  auth_bypass: "Authentication comparison",
  baseline: "Baseline control",
};
let state = {},
  specs = [],
  targets = [],
  operations = [],
  page = { items: [], total: 0 },
  health = null,
  detail = null,
  detailTab = "summary",
  returnFocus = null,
  requestSerial = 0,
  searchTimer,
  toastTimer,
  activeScan = null;
const defaults = {
  view: "overview",
  api: "",
  target: "",
  scanId: "",
  operationKey: "",
  offset: 0,
  limit: 50,
  sort: "",
  direction: "",
  snapshot: 0,
};
function readState() {
  const [view, query = ""] = location.hash.slice(1).split("?");
  const values = Object.fromEntries(new URLSearchParams(query));
  return {
    ...defaults,
    ...values,
    view: names[view] ? view : "overview",
    offset: Math.max(0, Number(values.offset) || 0),
    limit: [25, 50, 100].includes(Number(values.limit))
      ? Number(values.limit)
      : 50,
    snapshot: Number(values.snapshot) || 0,
  };
}
function writeState(push = false) {
  const query = new URLSearchParams();
  for (const [k, v] of Object.entries(state)) {
    if (k === "view" || v === "" || v === 0 || v == null) continue;
    if (k === "limit" && v === 50) continue;
    query.set(k, String(v));
  }
  const hash = "#" + state.view + (query.size ? "?" + query : "");
  history[push ? "pushState" : "replaceState"](null, "", hash);
}
function navigate(view, extra = {}) {
  state = {
    ...defaults,
    api: state.api,
    target: state.target,
    limit: state.limit,
    view,
    ...(view === "requests" ? { kind: "check" } : {}),
    ...extra,
  };
  writeState(true);
  closeDetail();
  load();
}
function scope() {
  let result = {};
  if (state.api) {
    try {
      const [title, version] = JSON.parse(state.api);
      result = { specTitle: title, specVersion: version };
    } catch {}
  }
  if (state.target) result.target = state.target;
  return result;
}
function query(extra = {}) {
  const out = { ...scope(), ...extra };
  for (const key of [
    "scanId",
    "operationKey",
    "method",
    "endpoint",
    "path",
    "q",
    "status",
    "strategy",
    "severity",
    "confidence",
    "verification",
    "outcome",
    "kind",
    "auth",
    "schema",
    "from",
    "to",
    "documented",
    "deprecated",
    "scanned",
    "anomaly",
    "sort",
    "direction",
    "snapshot",
    "limit",
    "offset",
  ])
    if (state[key] !== undefined && state[key] !== "") out[key] = state[key];
  Object.assign(out, extra);
  return new URLSearchParams(
    Object.entries(out).filter(([, v]) => v !== "" && v != null),
  );
}
async function api(path, options = {}) {
  const response = await fetch(path, options);
  let data;
  try {
    data = await response.json();
  } catch {
    throw Error("The backend returned an unreadable response");
  }
  if (!response.ok)
    throw Error(
      data.error || data.detail || `Request failed (${response.status})`,
    );
  return data;
}
function notify(message) {
  $("#toast").textContent = message;
  $("#toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($("#toast").hidden = true), 4500);
}
function badge(value) {
  const name = String(value || "unknown");
  return `<span class="badge ${esc(name.toLowerCase())}">${esc(name.replaceAll("_", " "))}</span>`;
}
function endpoint(method, path) {
  return `<span class="method">${esc(method)}</span><span class="path">${esc(path)}</span>`;
}
function date(value) {
  if (!value || value.startsWith?.("0001")) return "—";
  const d = new Date(value);
  return Number.isNaN(d.valueOf())
    ? value
    : d.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
}
function duration(ms) {
  if (!Number.isFinite(ms)) return "—";
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(2)} s`;
}
function scanDuration(row) {
  if (row.status === "running") return "Running";
  const start = new Date(row.startedAt),
    end = new Date(row.completedAt);
  return duration(end - start);
}
function originLabel(row) {
  return `${esc(row.specTitle || "Unknown API")} · ${esc(row.specVersion || "?")}<small>${esc(row.scanTarget || row.target || "Target not recorded")}</small>`;
}
function operationParts(key) {
  try {
    return JSON.parse(key);
  } catch {
    return [];
  }
}
function currentResource() {
  return state.view === "requests" ? "requests" : state.view;
}
const option = (value, label = value) => ({ value, label });
const methodOptions = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
].map((v) => option(v));
const statusOptions = [
  option("2xx", "2xx success"),
  option("3xx", "3xx redirect"),
  option("4xx", "4xx client error"),
  option("5xx", "5xx server error"),
];
const strategyOptions = Object.entries(checks).map(([v, l]) => option(v, l));
const endpointFilter = () =>
  operations.map((o) => option(o.operation_key, `${o.method} ${o.path}`));
const filters = {
  endpoints: [
    ["method", "Method", methodOptions],
    [
      "documented",
      "Inventory",
      [option("true", "Documented"), option("false", "Undocumented")],
    ],
    [
      "deprecated",
      "Lifecycle",
      [option("true", "Deprecated"), option("false", "Current")],
    ],
    [
      "auth",
      "Authentication",
      [
        option("required", "Required"),
        option("public", "Public"),
        option("unknown", "Unknown"),
      ],
    ],
    [
      "scanned",
      "Scan history",
      [option("true", "Scanned"), option("false", "Never scanned")],
    ],
  ],
  scans: [
    [
      "status",
      "State",
      [
        "running",
        "completed",
        "partial",
        "failed",
        "cancelled",
        "dry_run",
        "budget_exhausted",
      ].map((v) => option(v)),
    ],
    ["from", "Since", "date"],
    ["to", "Until", "date"],
  ],
  requests: [
    ["operationKey", "Originating endpoint", endpointFilter],
    ["method", "Actual method", methodOptions],
    ["strategy", "Check", strategyOptions],
    [
      "outcome",
      "Result",
      [
        "finding",
        "no_finding",
        "suppressed",
        "error",
        "skipped",
        "planned",
      ].map((v) => option(v)),
    ],
    ["status", "HTTP status", statusOptions],
    [
      "kind",
      "Request kind",
      [
        option("check", "Detection check"),
        option("baseline", "Baseline control"),
      ],
    ],
    [
      "auth",
      "Authentication",
      ["public", "credentials supplied", "credential-free"].map((v) =>
        option(v),
      ),
    ],
  ],
  findings: [
    ["operationKey", "Endpoint", endpointFilter],
    ["scanId", "Scan", () => targets.scanOptions || []],
    [
      "severity",
      "Severity",
      ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((v) => option(v)),
    ],
    [
      "confidence",
      "Confidence",
      ["high", "medium", "low"].map((v) => option(v)),
    ],
    [
      "strategy",
      "Check",
      strategyOptions.filter((o) => o.value !== "baseline"),
    ],
    [
      "verification",
      "Verification",
      [
        "reachable",
        "response_verified",
        "candidate",
        "authentication_exposure",
      ].map((v) => option(v)),
    ],
    ["from", "Since", "date"],
    ["to", "Until", "date"],
  ],
  traffic: [
    ["operationKey", "Endpoint / template", endpointFilter],
    ["path", "Exact concrete path", "text"],
    ["method", "Method", methodOptions],
    ["status", "HTTP status", statusOptions],
    [
      "anomaly",
      "Detection",
      [
        option("normal", "No flags"),
        option("any", "Any flag"),
        option("behavioral", "Behavioral"),
        option("shadow_candidate", "Shadow candidate"),
        option("deprecated_observed", "Deprecated observed"),
      ],
    ],
    ["outcome", "Evaluation", ["evaluated", "pending"].map((v) => option(v))],
    ["from", "Since", "date"],
    ["to", "Until", "date"],
  ],
};
const columns = {
  endpoints: [
    ["method", "Method", (r) => `<span class="method">${esc(r.method)}</span>`],
    [
      "endpoint",
      "Endpoint",
      (r) =>
        `<span class="path">${esc(r.path)}</span><small>${esc(r.specTitle)} · ${esc(r.specVersion)}</small>`,
    ],
    [
      "",
      "Inventory",
      (r) =>
        badge(r.documented ? "documented" : "undocumented") +
        (r.deprecated ? " " + badge("deprecated") : ""),
    ],
    ["", "Auth", (r) => esc(r.authentication)],
    [
      "requests",
      "Checks sent",
      (r) => `${r.requests}<small>${esc(r.scanStatus)}</small>`,
    ],
    ["findings", "Findings", (r) => String(r.findings)],
    ["observed", "Last observed", (r) => date(r.lastObserved)],
  ],
  scans: [
    [
      "time",
      "Started",
      (r) => `${date(r.startedAt)}<small>${esc(r.id.slice(0, 8))}</small>`,
    ],
    [
      "target",
      "Target / API",
      (r) =>
        `${esc(r.target)}<small>${esc(r.specTitle)} · ${esc(r.specVersion)}</small>`,
    ],
    ["status", "State", (r) => badge(r.status)],
    ["duration", "Duration", scanDuration],
    [
      "requests",
      "Requests",
      (r) =>
        `${r.probesSent}<small>${r.baselineRequests || 0} controls · ${r.requestErrors || 0} errors</small>`,
    ],
    ["findings", "Findings", (r) => String(r.findingsCount)],
  ],
  requests: [
    ["method", "Method", (r) => `<span class="method">${esc(r.method)}</span>`],
    [
      "endpoint",
      "Actual endpoint",
      (r) =>
        `<span class="path">${esc(r.path)}</span><small>${esc(r.origins?.map((o) => `${o.method} ${o.path}`).join(", ") || "Control request")}</small>`,
    ],
    [
      "strategy",
      "Check",
      (r) =>
        `${esc(checks[r.strategy] || r.strategy)}<small>${esc(r.authContext)}</small>`,
    ],
    ["outcome", "Result", (r) => badge(r.outcome)],
    ["status", "HTTP", (r) => r.statusCode || "—"],
    ["duration", "Duration", (r) => duration(r.durationMs)],
    [
      "time",
      "Order / scan",
      (r) =>
        `${date(r.completedAt)}<small>${esc(r.scanId?.slice(0, 8))}</small>`,
    ],
  ],
  findings: [
    ["severity", "Severity", (r) => badge(r.severity)],
    ["endpoint", "Endpoint", (r) => endpoint(r.method, r.path)],
    [
      "",
      "Finding",
      (r) =>
        `${esc(r.title)}<small>${esc(r.verification?.replaceAll("_", " "))}</small>`,
    ],
    ["strategy", "Check", (r) => esc(checks[r.strategy] || r.strategy)],
    ["confidence", "Confidence", (r) => esc(r.confidence)],
    ["status", "HTTP", (r) => r.statusCode || "—"],
    [
      "time",
      "Scan / context",
      (r) =>
        `${originLabel(r)}<small>${esc(r.scanId?.slice(0, 8))} · ${date(r.timestamp)}</small>`,
    ],
  ],
  traffic: [
    ["time", "Time", (r) => date(r.timestamp)],
    ["method", "Method", (r) => `<span class="method">${esc(r.method)}</span>`],
    [
      "endpoint",
      "Endpoint",
      (r) =>
        `<span class="path">${esc(r.path)}</span><small>${esc(r.endpoint)}</small>`,
    ],
    ["status", "HTTP", (r) => r.statusCode],
    ["outcome", "Evaluation", (r) => badge(r.evaluation_status)],
    [
      "",
      "Signals",
      (r) =>
        `${r.prediction?.is_anomaly ? badge("finding") : badge(r.evaluation_status === "pending" ? "pending" : "no flags")}<small>${esc(r.prediction?.reasons?.join("; ") || "No detector flags")}</small>`,
    ],
    [
      "score",
      "Behavior score",
      (r) =>
        r.prediction?.behavioral_score == null
          ? "—"
          : Number(r.prediction.behavioral_score).toFixed(3),
    ],
    ["", "Context", originLabel],
  ],
};
function renderShell() {
  const view = state.view;
  document
    .querySelectorAll("#nav a")
    .forEach((el) =>
      el.classList.toggle(
        "active",
        el.dataset.view === (view === "requests" ? "scans" : view),
      ),
    );
  $("#page-title").textContent = names[view];
  $("#page-eyebrow").textContent =
    view === "requests" ? "SCAN INVESTIGATION" : "API INVESTIGATION";
  const descriptions = {
    overview:
      "A scoped summary of your inventory, scans, and observed traffic.",
    endpoints:
      "Choose an operation to inspect its checks, findings, and traffic.",
    scans:
      "Each scan keeps its own target, configuration, and request history.",
    requests:
      "Every check and baseline control, including responses that produced no finding.",
    findings: "Filter by scan and endpoint. Open a row to follow the evidence.",
    traffic:
      "Passive gateway observations. These are separate from active scanner requests.",
    health:
      "Measured service state. Investigation filters do not change system health.",
  };
  $("#page-description").textContent = descriptions[view];
  for (const section of ["overview", "health", "explorer"])
    $("#" + section).hidden =
      section !==
      (view === "overview"
        ? "overview"
        : view === "health"
          ? "health"
          : "explorer");
  $("#scan-summary").hidden = view !== "requests";
  $("#density").hidden = view === "overview" || view === "health";
  $("#workspace-api").value = state.api;
  ensureTarget();
  const [title, version] = state.api ? JSON.parse(state.api) : [];
  $("#breadcrumb").innerHTML =
    `<span>${esc(title ? `${title} · ${version}` : "All APIs")}</span><span>/</span><span>${esc(state.target || "All targets")}</span>${state.scanId ? `<span>/</span><button data-action="scan" data-id="${esc(state.scanId)}">Scan ${esc(state.scanId.slice(0, 8))}</button>` : ""}${state.operationKey ? `<span>/</span><span>${esc(operationParts(state.operationKey).slice(2).join(" "))}</span>` : ""}`;
}
function ensureTarget() {
  const values = [...new Set([...targets, state.target].filter(Boolean))];
  $("#workspace-target").innerHTML =
    '<option value="">All targets</option>' +
    values.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join("") +
    '<option value="__unknown">Target not recorded (traffic)</option>';
  $("#workspace-target").value = state.target;
}
function renderFilters() {
  const list = filters[currentResource()] || [];
  $("#search").value = state.q || "";
  $("#page-size").value = state.limit;
  $("#filter-controls").innerHTML = list
    .map(([key, label, values]) => {
      if (values === "date")
        return `<label>${label}<input data-filter="${key}" type="datetime-local" value="${esc(state[key] ? localInput(state[key]) : "")}"></label>`;
      if (values === "text")
        return `<label>${label}<input data-filter="${key}" value="${esc(state[key] || "")}" placeholder="/users/42"></label>`;
      const options = typeof values === "function" ? values() : values;
      let content = options
        .map(
          (o) =>
            `<option value="${esc(o.value)}"${state[key] === o.value ? " selected" : ""}>${esc(o.label)}</option>`,
        )
        .join("");
      if (state[key] && !options.some((o) => o.value === state[key]))
        content += `<option selected value="${esc(state[key])}">${esc(key === "operationKey" ? operationParts(state[key]).slice(2).join(" ") : state[key])}</option>`;
      return `<label>${label}<select data-filter="${key}"><option value="">All</option>${content}</select></label>`;
    })
    .join("");
  const keys = ["q", ...list.map((f) => f[0])];
  $("#filter-chips").innerHTML = keys
    .filter((k) => state[k])
    .map(
      (k) =>
        `<span class="chip">${esc(k)}: ${esc(k === "operationKey" ? operationParts(state[k]).slice(2).join(" ") : state[k])}<button data-clear="${k}" aria-label="Remove ${esc(k)} filter">×</button></span>`,
    )
    .join("");
}
function localInput(raw) {
  const d = new Date(raw);
  return new Date(d - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
function renderTable() {
  const resource = currentResource(),
    defs = columns[resource] || [];
  $("#results-table thead").innerHTML =
    "<tr>" +
    defs
      .map(
        ([key, label]) =>
          `<th${key && state.sort === key ? ` aria-sort="${state.direction === "asc" ? "ascending" : "descending"}"` : ""}>${key ? `<button data-sort="${key}" aria-label="Sort by ${esc(label)}">${label} ${state.sort === key ? (state.direction === "asc" ? "↑" : "↓") : "↕"}</button>` : label}</th>`,
      )
      .join("") +
    "</tr>";
  $("#results-table tbody").innerHTML = page.items
    .map(
      (r, i) =>
        `<tr tabindex="0" data-row="${i}" aria-label="Open ${esc(r.method ? r.method + " " + r.path : r.id)}"${detail?.id === r.id ? ' class="selected"' : ""}>${defs.map(([, , render]) => `<td>${render(r)}</td>`).join("")}</tr>`,
    )
    .join("");
  $("#result-count").textContent =
    `${page.total.toLocaleString()} matching ${resource}${state.snapshot ? " · stable snapshot" : ""}`;
  $("#page-info").textContent = page.total
    ? `${state.offset + 1}–${Math.min(state.offset + state.limit, page.total)} of ${page.total.toLocaleString()}`
    : "0 results";
  $("#previous").disabled = state.offset === 0;
  $("#next").disabled = state.offset + state.limit >= page.total;
  $("#table-message").hidden = page.items.length > 0;
  if (!page.items.length) {
    let message =
      "No matching results. Try clearing a filter or choosing another scan.";
    if (resource === "requests" && activeScan && !activeScan.traceVersion)
      message =
        "Individual request history was not recorded for this older scan. Its findings remain available.";
    else if (resource === "requests" && activeScan?.status === "running")
      message =
        "The scan is preparing its request plan. Progress will appear here.";
    else if (resource === "traffic" && state.target)
      message =
        "No traffic matches this target. Older traffic with no recorded target is kept separate.";
    $("#table-message").textContent = message;
  }
  $("#export-csv").disabled = false;
  $("#export-json").disabled = false;
}
async function load() {
  const serial = ++requestSerial;
  renderShell();
  $("#new-results").hidden = true;
  if (state.view === "overview") {
    await loadOverview();
    return;
  }
  if (state.view === "health") {
    renderHealth();
    return;
  }
  renderFilters();
  $("#result-count").textContent = "Loading matching results…";
  try {
    if (state.view === "requests" && state.scanId) {
      activeScan = await api("/api/scans/" + encodeURIComponent(state.scanId));
      renderScanSummary();
    } else {
      activeScan = null;
      $("#scan-summary").hidden = true;
    }
    const resource = currentResource();
    const data = await api("/api/explorer/" + resource + "?" + query());
    if (serial !== requestSerial) return;
    page = data;
    if (data.snapshot && !state.snapshot) {
      state.snapshot = data.snapshot;
      writeState();
    }
    renderTable();
  } catch (error) {
    if (serial !== requestSerial) return;
    $("#results-table tbody").innerHTML = "";
    $("#table-message").hidden = false;
    $("#table-message").textContent = error.message;
    $("#result-count").textContent = "Results unavailable";
  }
}
function renderScanSummary() {
  if (!activeScan) return;
  const s = activeScan,
    planned = s.plannedChecks || 0,
    done = s.completedChecks || 0;
  $("#scan-summary").hidden = false;
  $("#scan-summary").innerHTML =
    `<div class="scan-summary"><div><h3>Scan ${esc(s.id.slice(0, 8))} ${badge(s.status)}</h3><code>${esc(s.target)}</code><small> · ${esc(s.specTitle)} ${esc(s.specVersion)}</small><p class="muted">${esc(s.error || s.phase || "Finished")}</p>${s.status === "running" ? `<div class="progress-track"><span style="width:${planned ? Math.min(100, (done / planned) * 100) : 0}%"></span></div>` : ""}${!s.traceVersion ? '<p class="muted">Legacy scan: request traces were not recorded.</p>' : ""}</div><div class="scan-stats"><span><strong>${s.probesSent || 0}</strong>Total requests</span><span><strong>${s.baselineRequests || 0}</strong><button data-action="controls">View baseline controls</button></span><span><strong>${done}/${planned}</strong>Checks completed</span><span><strong>${s.findingsCount || 0}</strong>Findings</span></div><button data-action="scan-findings" data-id="${esc(s.id)}">View findings</button>${s.status === "running" ? `<button data-action="cancel" data-id="${esc(s.id)}">Cancel scan</button>` : ""}</div>`;
}
async function loadOverview() {
  try {
    const p = new URLSearchParams(scope());
    const [summary, recent, findings] = await Promise.all([
      api("/api/overview?" + p),
      api(
        "/api/explorer/scans?" + new URLSearchParams({ ...scope(), limit: 5 }),
      ),
      api(
        "/api/explorer/findings?" +
          new URLSearchParams({ ...scope(), limit: 5 }),
      ),
    ]);
    $("#overview").innerHTML = `<div class="metrics">${[
      [
        "Documented operations",
        summary.operations,
        "From the selected API inventory",
      ],
      ["Scans", summary.scans, "Within the selected scope"],
      ["Findings", summary.findings, "Across matching scans"],
      [
        "Traffic observations",
        summary.traffic,
        "Recorded for the selected scope",
      ],
    ]
      .map(
        ([label, value, note]) =>
          `<article class="metric"><span>${label}</span><strong>${Number(value).toLocaleString()}</strong><small>${note}</small></article>`,
      )
      .join(
        "",
      )}</div><div class="overview-grid"><article class="panel"><div class="panel-head"><h2>Recent scans</h2><button data-action="navigate" data-view="scans">All scans →</button></div>${recent.items.map((s) => `<div class="list-row"><button data-action="scan" data-id="${esc(s.id)}">${esc(s.target)}<small>${esc(s.specTitle)} · ${date(s.startedAt)} · ${s.probesSent} requests</small></button>${badge(s.status)}</div>`).join("") || '<p class="muted">No scans in this scope. Start with Preview requests.</p>'}</article><article class="panel"><div class="panel-head"><h2>Findings to investigate</h2><button data-action="navigate" data-view="findings">All findings →</button></div>${findings.items.map((f) => `<div class="list-row"><button data-action="finding" data-id="${esc(f.id)}">${endpoint(f.method, f.path)}<small>${esc(f.title)} · scan ${esc(f.scanId.slice(0, 8))}</small></button>${badge(f.severity)}</div>`).join("") || '<p class="muted">No findings recorded in this scope.</p>'}</article></div>`;
  } catch (e) {
    $("#overview").innerHTML =
      `<div class="error-message">${esc(e.message)}</div>`;
  }
}
function renderHealth() {
  if (!health) {
    $("#health").innerHTML =
      '<p class="muted">Service health is unavailable.</p>';
    return;
  }
  $("#health").innerHTML = `<div class="health-grid">${[
    [
      "Memgraph",
      health.memgraph ? "Connected" : "Unavailable",
      "Scoped specification inventory",
    ],
    [
      "SQLite",
      health.storage ? "Healthy" : "Unavailable",
      "Persistent traffic, traces, and findings",
    ],
    [
      "Detector",
      health.detector.status,
      health.detector.active_model_id
        ? `Model ${health.detector.active_model_id.slice(0, 8)}`
        : "Inventory rules only",
    ],
    [
      "Kafka",
      "Not directly measured",
      "Use persisted traffic and consumer logs to inspect ingestion.",
    ],
    [
      "Predictions",
      "Per-event evaluation",
      "Normal endpoint verdicts are never cached.",
    ],
  ]
    .map(
      ([name, status, note]) =>
        `<article class="panel"><h3>${name}</h3>${badge(status)}<p>${esc(note)}</p></article>`,
    )
    .join("")}</div>`;
}
async function updateOptions() {
  try {
    specs = await api("/api/specs");
    const options =
      '<option value="">All APIs</option>' +
      specs
        .map(
          (s) =>
            `<option value="${esc(JSON.stringify([s.title, s.version]))}">${esc(s.title)} · ${esc(s.version)}</option>`,
        )
        .join("");
    $("#workspace-api").innerHTML = options;
    $("#scan-api").innerHTML = options.replace(
      '<option value="">All APIs</option>',
      '<option value="">Select an API</option>',
    );
    const scans = await api("/api/explorer/scans?limit=500");
    targets = [
      ...new Set(
        [
          ...specs.map((s) => s.target),
          ...scans.items.map((s) => s.target),
        ].filter(Boolean),
      ),
    ];
    targets.scanOptions = scans.items.map((s) =>
      option(s.id, `${s.id.slice(0, 8)} · ${s.target}`),
    );
    await updateOperations();
    renderShell();
  } catch (e) {
    notify(e.message);
  }
}
async function updateOperations() {
  try {
    const data = await api(
      "/api/explorer/endpoints?" +
        new URLSearchParams({ ...scope(), limit: 500 }),
    );
    operations = data.items;
    return operations;
  } catch {
    return [];
  }
}
function detailTabs(tabs) {
  $("#detail-tabs").innerHTML = tabs
    .map(
      ([id, label]) =>
        `<button role="tab" aria-selected="${detailTab === id}" class="${detailTab === id ? "active" : ""}" data-tab="${id}">${label}</button>`,
    )
    .join("");
}
function section(title, body) {
  return `<section class="evidence-section"><h3>${title}</h3>${body}</section>`;
}
function values(pairs) {
  return (
    '<dl class="key-values">' +
    pairs
      .map(([key, value]) => `<dt>${esc(key)}</dt><dd>${value ?? "—"}</dd>`)
      .join("") +
    "</dl>"
  );
}
function bodyPreview(text, truncated) {
  return `<pre class="evidence-body">${esc(text || "(empty body)")}</pre>${truncated ? "<small>Preview is truncated. It is not the full response.</small>" : ""}`;
}
function rawEvidence(data) {
  return `<div class="copy-row"><button data-copy="json">Copy sanitized JSON</button></div><pre class="raw-json">${esc(JSON.stringify(data, null, 2))}</pre>`;
}
async function openDetail(type, row) {
  returnFocus = document.activeElement;
  detail = { type, id: row.id || row.request_id, row };
  detailTab = "summary";
  $("#detail").hidden = false;
  $("#detail-backdrop").hidden = false;
  $("#detail").focus();
  $("#detail-body").innerHTML = '<p class="muted">Loading evidence…</p>';
  try {
    if (type === "request")
      detail.row = await api("/api/requests/" + encodeURIComponent(detail.id));
    if (type === "finding")
      detail.row = await api("/api/findings/" + encodeURIComponent(detail.id));
    if (type === "traffic")
      detail.row = await api("/api/traffic/" + encodeURIComponent(detail.id));
    await renderDetail();
  } catch (e) {
    $("#detail-body").innerHTML =
      `<p class="error-message">${esc(e.message)}</p>`;
  }
}
function closeDetail() {
  if ($("#detail").hidden) return;
  $("#detail").hidden = true;
  $("#detail-backdrop").hidden = true;
  detail = null;
  if (returnFocus?.isConnected) returnFocus.focus();
}
async function renderDetail() {
  if (!detail) return;
  const { type, row: r } = detail;
  $("#detail-kind").textContent =
    type === "endpoint" ? "OPERATION" : type.toUpperCase() + " EVIDENCE";
  $("#detail-title").textContent = `${r.method || ""} ${r.path || r.id}`;
  detailTabs(
    type === "endpoint"
      ? [
          ["summary", "Summary"],
          ["checks", "Checks"],
          ["findings", "Findings"],
          ["traffic", "Traffic"],
        ]
      : type === "request"
        ? [
            ["summary", "Evidence"],
            ["comparisons", "Comparisons"],
            ["raw", "Raw JSON"],
          ]
        : [
            ["summary", "Evidence"],
            ["raw", "Raw JSON"],
          ],
  );
  if (detailTab === "raw") {
    $("#detail-body").innerHTML = rawEvidence(r);
    return;
  }
  if (type === "endpoint") {
    await renderEndpointDetail(r);
    return;
  }
  if (type === "request" && detailTab === "comparisons") {
    const ids = [...(r.baselineIds || []), r.comparedRequestId].filter(Boolean);
    const comparisons = await Promise.all(
      ids.map((id) => api("/api/requests/" + encodeURIComponent(id))),
    );
    if (!detail || detail.id !== r.id) return;
    $("#detail-body").innerHTML =
      comparisons
        .map((c) =>
          section(
            c.id === r.comparedRequestId
              ? "Authenticated comparison"
              : "Nonexistent-route baseline",
            values([
              ["Request", endpoint(c.method, c.path)],
              ["HTTP", c.statusCode || "—"],
              ["Authentication", esc(c.authContext)],
              ["Result", badge(c.outcome)],
            ]) + bodyPreview(c.responseBody, c.responseTruncated),
          ),
        )
        .join("") ||
      '<p class="muted">No comparison evidence was recorded for this request.</p>';
    return;
  }
  let content = "";
  if (type === "finding") {
    let evidence = {};
    try {
      evidence = JSON.parse(r.evidence);
    } catch {}
    content =
      `<div class="status-reason">${esc(r.title)}<small>${esc(r.description)}</small></div>` +
      values([
        ["API", `${esc(r.specTitle)} · ${esc(r.specVersion)}`],
        [
          "Scan",
          `<button data-action="scan" data-id="${esc(r.scanId)}">${esc(r.scanId.slice(0, 8))} →</button>`,
        ],
        ["Actual URL", `<code>${esc(r.target)}</code>`],
        ["Severity", badge(r.severity)],
        ["Confidence", esc(r.confidence)],
        ["Verification", esc(r.verification)],
        ["Schema", esc(r.schema_result)],
        ["HTTP", r.statusCode],
        ["Check", esc(checks[r.strategy] || r.strategy)],
      ]) +
      section(
        "Response evidence",
        bodyPreview(evidence.bodySnippet || r.evidence, false),
      ) +
      section("Suggested action", `<p>${esc(r.remediation)}</p>`) +
      (r.requestId
        ? `<button data-action="request" data-id="${esc(r.requestId)}">Inspect the originating request →</button>`
        : '<p class="muted">This older finding has no recorded individual request trace.</p>');
  } else {
    const reason =
      type === "request"
        ? r.reason
        : r.prediction?.reasons?.join("; ") || "No detector flags";
    content =
      `<div class="status-reason">${badge(r.outcome || r.evaluation_status)} <p>${esc(reason)}</p><small>${type === "traffic" ? "Passive observation: separate from active scanner probes." : "A check with no finding is not a guarantee that the endpoint is secure."}</small></div>` +
      values([
        ["API", `${esc(r.specTitle)} · ${esc(r.specVersion)}`],
        ["Target", `<code>${esc(r.target || "Target not recorded")}</code>`],
        ["Method / path", endpoint(r.method, r.path)],
        ["Actual URL", `<code>${esc(r.url || r.path)}</code>`],
        ["HTTP", r.statusCode || "—"],
        ["Duration", duration(r.durationMs)],
        ["Authentication", esc(r.authContext || "Not recorded")],
        ["Schema", esc(r.schemaResult || "Not evaluated")],
        [
          "Scan",
          r.scanId
            ? `<button data-action="scan" data-id="${esc(r.scanId)}">${esc(r.scanId.slice(0, 8))} →</button>`
            : "Passive traffic",
        ],
      ]) +
      `<div class="copy-row"><button data-copy="url">Copy URL / path</button><button data-copy="json">Copy sanitized JSON</button></div>` +
      section(
        "Request headers",
        bodyPreview(JSON.stringify(r.requestHeaders || {}, null, 2), false),
      ) +
      section("Request body", bodyPreview(r.requestBody, r.requestTruncated)) +
      section(
        "Response headers",
        bodyPreview(JSON.stringify(r.responseHeaders || {}, null, 2), false),
      ) +
      section(
        "Response body",
        bodyPreview(r.responseBody, r.responseTruncated),
      );
    if (r.findingIds?.length)
      content += section(
        "Linked findings",
        r.findingIds
          .map(
            (id) =>
              `<button data-action="finding" data-id="${esc(id)}">Open finding ${esc(id.slice(0, 8))} →</button>`,
          )
          .join(""),
      );
  }
  $("#detail-body").innerHTML = content;
}
async function renderEndpointDetail(r) {
  if (detailTab === "summary") {
    $("#detail-body").innerHTML =
      values([
        ["API", `${esc(r.specTitle)} · ${esc(r.specVersion)}`],
        ["Operation", endpoint(r.method, r.path)],
        ["Inventory", badge(r.documented ? "documented" : "undocumented")],
        ["Deprecated", r.deprecated ? "Yes" : "No"],
        ["Authentication", esc(r.authentication)],
        ["History", esc(r.scanStatus)],
        ["Recorded checks", r.requests],
        ["Findings", r.findings],
        ["Last observed", date(r.lastObserved)],
      ]) +
      `<div class="copy-row"><button class="primary" data-action="scan-endpoint" data-key="${esc(r.operation_key)}">Scan this operation</button><button data-action="endpoint-checks" data-key="${esc(r.operation_key)}">Open check history</button></div>`;
    return;
  }
  const resource = detailTab === "checks" ? "requests" : detailTab;
  const params = {
    specTitle: r.specTitle,
    specVersion: r.specVersion,
    operationKey: r.operation_key,
    limit: 25,
  };
  if (state.target) params.target = state.target;
  if (state.scanId && resource !== "traffic") params.scanId = state.scanId;
  const data = await api(
    "/api/explorer/" + resource + "?" + new URLSearchParams(params),
  );
  if (!detail || detail.id !== r.id) return;
  $("#detail-body").innerHTML =
    `<p class="muted">${data.total} matching ${resource}</p><div class="copy-row"><button data-action="endpoint-open" data-view="${resource}" data-key="${esc(r.operation_key)}">Open filtered explorer →</button></div>` +
    data.items
      .map(
        (item) =>
          `<div class="list-row"><button data-action="${resource === "requests" ? "request" : resource === "findings" ? "finding" : "traffic"}" data-id="${esc(item.id)}">${endpoint(item.method, item.path)}<small>${esc(item.outcome || item.title || item.evaluation_status)}</small></button>${badge(item.severity || item.outcome || item.evaluation_status)}</div>`,
      )
      .join("");
}
function scanSelection() {
  const value = $("#scan-api").value;
  if (!value) throw Error("Select an API and version");
  const [title, version] = JSON.parse(value);
  const headers = {};
  document.querySelectorAll(".header-row").forEach((row) => {
    const name = row.querySelector("[data-header-name]").value.trim(),
      value = row.querySelector("[data-header-value]").value;
    if (name) headers[name] = value;
  });
  const strategies = [
    ...document.querySelectorAll('input[name="strategy"]:checked'),
  ].map((e) => e.value);
  if (!strategies.length) throw Error("Select at least one check");
  let selectedOperations = [];
  if ($("#scan-scope").value === "selected") {
    const op = operationParts($("#scan-operation").value);
    if (op.length !== 4) throw Error("Select an operation");
    selectedOperations = [{ method: op[2], path: op[3] }];
  }
  return {
    target: $("#scan-target").value.trim(),
    specTitle: title,
    specVersion: version,
    headers,
    strategies,
    workers: Number($("#scan-workers").value),
    rps: Number($("#scan-rps").value),
    maxRequests: Number($("#scan-budget").value),
    dryRun: $("#dry-run").checked,
    allowMutating: $("#allow-mutating").checked,
    selectedOperations,
  };
}
function addHeader(name = "", value = "") {
  const row = document.createElement("div");
  row.className = "header-row";
  row.innerHTML = `<input data-header-name aria-label="Header name" placeholder="Authorization" value="${esc(name)}"><input data-header-value aria-label="Header value" placeholder="Bearer …" type="password" value="${esc(value)}"><button type="button" data-remove-header aria-label="Remove header">×</button>`;
  $("#header-rows").append(row);
}
async function openScan(key = "") {
  closeDetail();
  $("#scan-error").hidden = true;
  $("#preview-panel").hidden = true;
  $("#scan-api").value = key
    ? JSON.stringify(operationParts(key).slice(0, 2))
    : state.api || JSON.stringify([specs[0]?.title, specs[0]?.version]);
  $("#scan-scope").value = key ? "selected" : "all";
  $("#operation-field").hidden = !key;
  await scanOptions(key);
  $("#scan-dialog").showModal();
  $("#scan-api").focus();
}
async function scanOptions(selected = "") {
  const value = $("#scan-api").value;
  if (!value) return;
  const [title, version] = JSON.parse(value);
  const spec = specs.find((s) => s.title === title && s.version === version);
  $("#scan-target").value =
    state.target && state.target !== "__unknown"
      ? state.target
      : spec?.target || "";
  const data = await api(
    "/api/explorer/endpoints?" +
      new URLSearchParams({
        specTitle: title,
        specVersion: version,
        limit: 500,
      }),
  );
  $("#scan-operation").innerHTML = data.items
    .map(
      (o) =>
        `<option value="${esc(o.operation_key)}">${esc(o.method + " " + o.path)}</option>`,
    )
    .join("");
  if (selected) $("#scan-operation").value = selected;
}
async function previewScan() {
  try {
    $("#scan-error").hidden = true;
    $("#preview-scan").disabled = true;
    const result = await api("/api/scans/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(scanSelection()),
    });
    $("#preview-count").textContent =
      `${result.total} planned entries · ${result.items.filter((r) => r.conditional).length} conditional · zero requests sent`;
    $("#preview-table tbody").innerHTML = result.items
      .map(
        (r) =>
          `<tr><td>${esc(r.method)}</td><td><code>${esc(r.url)}</code></td><td>${esc(checks[r.strategy])}</td><td>${r.conditional ? "Conditional" : "Planned"}</td></tr>`,
      )
      .join("");
    $("#preview-panel").hidden = false;
  } catch (e) {
    $("#scan-error").textContent = e.message;
    $("#scan-error").hidden = false;
  } finally {
    $("#preview-scan").disabled = false;
  }
}
async function startScan(event) {
  event.preventDefault();
  try {
    $("#scan-error").hidden = true;
    $("#submit-scan").disabled = true;
    const configuration = scanSelection();
    const result = await api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(configuration),
    });
    $("#scan-dialog").close();
    navigate("requests", {
      api: JSON.stringify([configuration.specTitle, configuration.specVersion]),
      target: configuration.target,
      scanId: result.id,
    });
    notify("Scan accepted. Request history will appear as checks execute.");
    await updateOptions();
  } catch (e) {
    $("#scan-error").textContent = e.message;
    $("#scan-error").hidden = false;
  } finally {
    $("#submit-scan").disabled = false;
  }
}
async function exportResults(format) {
  try {
    if (currentResource() === "endpoints") {
      const items = [];
      let offset = 0;
      while (true) {
        const data = await api(
          "/api/explorer/endpoints?" + query({ limit: 500, offset }),
        );
        items.push(...data.items);
        if (items.length >= data.total) break;
        offset += 500;
      }
      if (format === "json")
        download(
          JSON.stringify(items, null, 2),
          "application/json",
          "sentry-endpoints.json",
        );
      else {
        const keys = [
          "method",
          "path",
          "specTitle",
          "specVersion",
          "documented",
          "deprecated",
          "authentication",
          "requests",
          "findings",
          "scanStatus",
        ];
        const cell = (v) => {
          let text = String(v ?? "");
          if (/^[=+@-]/.test(text)) text = "'" + text;
          return '"' + text.replaceAll('"', '""') + '"';
        };
        download(
          [
            keys.join(","),
            ...items.map((r) => keys.map((k) => cell(r[k])).join(",")),
          ].join("\r\n"),
          "text/csv",
          "sentry-endpoints.csv",
        );
      }
      return;
    }
    const response = await fetch(
      "/api/export/" + currentResource() + "?" + query({ format }),
    );
    if (!response.ok) {
      const error = await response.json();
      throw Error(error.error);
    }
    const blob = await response.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `sentry-${currentResource()}.${format}`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  } catch (e) {
    notify(e.message);
  }
}
function download(text, type, name) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function resetPage() {
  state.offset = 0;
  state.snapshot = 0;
}
function changeFilter(key, value) {
  state[key] = value;
  resetPage();
  writeState();
  load();
}
async function openScanHistory(id) {
  const scan = await api("/api/scans/" + encodeURIComponent(id));
  navigate("requests", {
    api: JSON.stringify([scan.specTitle, scan.specVersion]),
    target: scan.target,
    scanId: id,
  });
}
document.addEventListener("click", async (event) => {
  try {
    const button = event.target.closest("button");
    const row = event.target.closest("[data-row]");
    if (row && !button) {
      const record = page.items[Number(row.dataset.row)];
      if (state.view === "scans") {
        await openScanHistory(record.id);
      } else
        await openDetail(
          state.view === "requests"
            ? "request"
            : state.view === "findings"
              ? "finding"
              : state.view === "traffic"
                ? "traffic"
                : "endpoint",
          record,
        );
      return;
    }
    if (!button) return;
    if (button.dataset.sort) {
      state.direction =
        state.sort === button.dataset.sort && state.direction === "asc"
          ? "desc"
          : "asc";
      state.sort = button.dataset.sort;
      resetPage();
      writeState();
      load();
      return;
    }
    if (button.dataset.clear) {
      changeFilter(button.dataset.clear, "");
      return;
    }
    if (button.dataset.tab) {
      detailTab = button.dataset.tab;
      await renderDetail();
      return;
    }
    if (button.hasAttribute("data-remove-header")) {
      button.closest(".header-row").remove();
      return;
    }
    if (button.dataset.copy) {
      await navigator.clipboard.writeText(
        button.dataset.copy === "json"
          ? JSON.stringify(detail.row, null, 2)
          : detail.row.url || detail.row.path,
      );
      notify("Copied");
      return;
    }
    const action = button.dataset.action;
    if (action === "navigate") navigate(button.dataset.view);
    if (action === "scan") await openScanHistory(button.dataset.id);
    if (action === "finding")
      await openDetail("finding", { id: button.dataset.id });
    if (action === "request")
      await openDetail("request", { id: button.dataset.id });
    if (action === "traffic")
      await openDetail("traffic", { id: button.dataset.id });
    if (action === "scan-endpoint") await openScan(button.dataset.key);
    if (action === "endpoint-checks" || action === "endpoint-open") {
      const parts = operationParts(button.dataset.key);
      navigate(
        action === "endpoint-checks" ? "requests" : button.dataset.view,
        {
          api: JSON.stringify(parts.slice(0, 2)),
          target: state.target,
          operationKey: button.dataset.key,
          scanId: state.scanId,
        },
      );
    }
    if (action === "scan-findings")
      navigate("findings", {
        scanId: button.dataset.id,
        operationKey: state.operationKey,
      });
    if (action === "controls") {
      changeFilter("kind", "baseline");
    }
    if (action === "cancel") {
      await api("/api/scans/" + button.dataset.id, { method: "DELETE" });
      notify("Cancellation requested");
    }
  } catch (e) {
    notify(e.message);
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDetail();
  if (event.key === "Enter" && event.target.matches("[data-row]"))
    event.target.click();
  if (!$("#detail").hidden && event.key === "Tab") {
    const focusable = [
      ...$("#detail").querySelectorAll('button,a,input,select,[tabindex="0"]'),
    ].filter((e) => e.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0],
      last = focusable.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }
});
$("#nav").addEventListener("click", (event) => {
  const link = event.target.closest("[data-view]");
  if (link) {
    event.preventDefault();
    navigate(link.dataset.view);
  }
});
$("#workspace-api").addEventListener("change", async () => {
  state = {
    ...defaults,
    view: state.view === "requests" ? "scans" : state.view,
    api: $("#workspace-api").value,
    target: state.target,
  };
  await updateOperations();
  writeState(true);
  closeDetail();
  load();
});
$("#workspace-target").addEventListener("change", async () => {
  state.target = $("#workspace-target").value;
  state.scanId = "";
  resetPage();
  await updateOperations();
  writeState();
  closeDetail();
  load();
});
$("#filter-controls").addEventListener("change", (event) => {
  const key = event.target.dataset.filter;
  if (key)
    changeFilter(
      key,
      event.target.type === "datetime-local" && event.target.value
        ? new Date(event.target.value).toISOString()
        : event.target.value,
    );
});
$("#search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => changeFilter("q", $("#search").value), 250);
});
$("#clear-filters").addEventListener("click", () => {
  state = {
    ...defaults,
    view: state.view,
    api: state.api,
    target: state.target,
    scanId: state.view === "requests" ? state.scanId : "",
    limit: state.limit,
  };
  writeState();
  load();
});
$("#page-size").addEventListener("change", () => {
  state.limit = Number($("#page-size").value);
  resetPage();
  writeState();
  load();
});
$("#previous").addEventListener("click", () => {
  state.offset = Math.max(0, state.offset - state.limit);
  writeState();
  load();
});
$("#next").addEventListener("click", () => {
  state.offset += state.limit;
  writeState();
  load();
});
for (const id of ["refresh", "load-new"])
  $("#" + id).addEventListener("click", () => {
    resetPage();
    writeState();
    load();
  });
$("#density").addEventListener("click", () => {
  const compact = document.body.classList.toggle("compact");
  $("#density").setAttribute("aria-pressed", compact);
  $("#density").textContent = compact ? "Comfortable rows" : "Compact rows";
  localStorage.setItem("sentry-density", compact ? "compact" : "comfortable");
});
$("#new-scan").addEventListener("click", () => openScan());
$("#close-detail").addEventListener("click", closeDetail);
$("#detail-backdrop").addEventListener("click", closeDetail);
$("#close-scan").addEventListener("click", () => $("#scan-dialog").close());
$("#scan-api").addEventListener("change", () => scanOptions());
$("#scan-scope").addEventListener(
  "change",
  () => ($("#operation-field").hidden = $("#scan-scope").value !== "selected"),
);
let operationTimer;
$("#operation-search").addEventListener("input", () => {
  clearTimeout(operationTimer);
  operationTimer = setTimeout(async () => {
    try {
      const [title, version] = JSON.parse($("#scan-api").value);
      const data = await api(
        "/api/explorer/endpoints?" +
          new URLSearchParams({
            specTitle: title,
            specVersion: version,
            q: $("#operation-search").value,
            limit: 100,
          }),
      );
      $("#scan-operation").innerHTML = data.items
        .map(
          (o) =>
            `<option value="${esc(o.operation_key)}">${esc(o.method + " " + o.path)}</option>`,
        )
        .join("");
    } catch (e) {
      notify(e.message);
    }
  }, 250);
});
$("#add-header").addEventListener("click", () => addHeader());
$("#apply-json").addEventListener("click", () => {
  try {
    const values = JSON.parse($("#headers-json").value || "{}");
    if (
      !values ||
      Array.isArray(values) ||
      typeof values !== "object" ||
      Object.values(values).some((v) => typeof v !== "string")
    )
      throw Error("Use an object with string header values");
    $("#header-rows").innerHTML = "";
    Object.entries(values).forEach(([k, v]) => addHeader(k, v));
    $("#headers-json").value = "";
    notify("Header values applied");
  } catch (e) {
    notify(e.message);
  }
});
$("#preview-scan").addEventListener("click", previewScan);
$("#scan-form").addEventListener("submit", startScan);
$("#export-csv").addEventListener("click", () => exportResults("csv"));
$("#export-json").addEventListener("click", () => exportResults("json"));
window.addEventListener("popstate", () => {
  state = readState();
  closeDetail();
  load();
});
window.addEventListener("hashchange", () => {
  state = readState();
  closeDetail();
  load();
});
async function poll() {
  try {
    health = await api("/api/health");
    $("#connection").textContent =
      health.status === "healthy"
        ? "● Services healthy"
        : "● Services degraded";
    if (state.view === "health") renderHealth();
    if (
      state.view === "requests" &&
      state.scanId &&
      activeScan?.status === "running"
    ) {
      activeScan = await api("/api/scans/" + state.scanId);
      renderScanSummary();
      if (!detail && state.offset === 0) {
        state.snapshot = 0;
        await load();
      }
    } else if (columns[currentResource()]) {
      const data = await api(
        "/api/explorer/" +
          currentResource() +
          "?" +
          query({ limit: 1, snapshot: 0, offset: 0 }),
      );
      if (
        data.total !== page.total ||
        (data.snapshot && data.snapshot !== page.snapshot)
      )
        $("#new-results").hidden = false;
    }
  } catch {
    $("#connection").textContent = "● Backend unavailable";
  }
}
state = readState();
if (localStorage.getItem("sentry-density") === "compact") {
  document.body.classList.add("compact");
  $("#density").setAttribute("aria-pressed", "true");
  $("#density").textContent = "Comfortable rows";
}
addHeader();
await updateOptions();
await load();
await poll();
setInterval(poll, 3000);
