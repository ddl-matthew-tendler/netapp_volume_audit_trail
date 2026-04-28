/**
 * Domino NetApp File Access Audit Viewer — Frontend Logic
 *
 * On page load:
 *   1. Call /api/init — gets SVMs, cluster name, Domino context automatically
 *   2. Populate the SVM dropdown — no user input needed for connection details
 *   3. Set default date range (today and 7 days ago)
 *
 * User only needs to:
 *   1. Pick an SVM from the dropdown
 *   2. Optionally adjust dates
 *   3. Click Run Query
 */

"use strict";

// -----------------------------------------------------------------------
// Base URL for API calls — derived from the current page URL.
// Domino proxies the app at a path like /modelproducts/abc/proxy/8888/
// and the browser's location.href includes that full path.  We use it
// as the base so that fetch("api/init") resolves correctly.
// -----------------------------------------------------------------------
const API_BASE = (() => {
  let base = window.location.href;
  // Ensure it ends with /
  if (!base.endsWith("/")) base += "/";
  return base;
})();

// -----------------------------------------------------------------------
// State
// -----------------------------------------------------------------------
let allEvents      = [];
let filteredEvents = [];
let sortCol        = "timestamp_str";
let sortDir        = "desc";
let currentSvm     = "";
let volumesBySvm   = {};  // populated from /api/init

// -----------------------------------------------------------------------
// DOM refs
// -----------------------------------------------------------------------
const statusPanel   = document.getElementById("status-panel");
const initLoading   = document.getElementById("init-loading");
const initError     = document.getElementById("init-error");
const queryCard     = document.getElementById("query-card");
const queryForm     = document.getElementById("query-form");
const runBtn        = document.getElementById("run-btn");
const clearBtn      = document.getElementById("clear-btn");
const liveBtn       = document.getElementById("live-btn");
const loading       = document.getElementById("loading");
const metaBar       = document.getElementById("meta-bar");
const alertBox      = document.getElementById("alert-box");
const resultsCard   = document.getElementById("results-card");
const tbody         = document.getElementById("events-tbody");
const tableSearch   = document.getElementById("table-search");
const exportCsvBtn  = document.getElementById("export-csv-btn");
const rowCount      = document.getElementById("row-count");
const filterCount   = document.getElementById("filter-count");
const sessionsModal = document.getElementById("sessions-modal");
const sessionsBody  = document.getElementById("sessions-body");
const modalCloseBtn = document.getElementById("modal-close-btn");
const svmSelect     = document.getElementById("svm_name");
const volumeSelect  = document.getElementById("volume");
const toggleFilters = document.getElementById("toggle-filters");
const filterFields  = document.getElementById("filter-fields");

// -----------------------------------------------------------------------
// Initialise on page load — fully automatic
// -----------------------------------------------------------------------
(async function init() {
  // Set default dates
  const today = new Date();
  const week  = new Date();
  week.setDate(today.getDate() - 7);
  document.getElementById("end_date").value   = isoDate(today);
  document.getElementById("start_date").value = isoDate(week);

  function showForm(data) {
    initLoading.style.display = "none";
    setText("ctx-project", data.project_name || "—");
    setText("ctx-user",    data.username     || "—");
    setText("ctx-cluster", data.cluster_name || "—");
    setText("header-user", data.username ? `Logged in as: ${data.username}` : "");
    volumesBySvm = data.volumes || {};
    populateSvms(data.svms || []);
    queryCard.style.display = "block";
  }

  // Abort the fetch if it takes more than 12 seconds
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);

  try {
    const res  = await fetch(API_BASE + "api/init", { signal: controller.signal });
    clearTimeout(timer);
    const data = await res.json();

    renderStatusPanel(data);
    applyDemoIndicators(!!data.demo_mode);
    applyOverrideIndicator(!!data.demo_override);

    if (!res.ok || !data.ok) {
      // ONTAP connection failed — but still show the form if demo mode is active
      if (data.demo_mode) {
        showForm(data);
      } else {
        // Status panel already tells the user everything — just hide the spinner.
        initLoading.style.display = "none";
      }
      return;
    }

    showForm(data);

  } catch (e) {
    clearTimeout(timer);
    const isTimeout = e.name === "AbortError";
    renderStatusPanel({
      ok: false,
      demo_mode: false,
      network_error: true,
      error: isTimeout
        ? "The server did not respond within 12 seconds."
        : `Network error: ${e.message}`,
    });
    initLoading.style.display = "none";
  }
})();

// -----------------------------------------------------------------------
// Status Panel — tells the user, unambiguously, which mode they're in and
// (in demo/error modes) exactly how to connect to a real cluster.
// -----------------------------------------------------------------------

const STATUS_DETAILS_KEY = "netapp_audit_status_details_open";

function statusDetailsOpen() {
  // Default: open on first load (so first-time users see the instructions),
  // then respect the user's choice via localStorage on subsequent loads.
  const v = localStorage.getItem(STATUS_DETAILS_KEY);
  return v === null ? true : v === "1";
}
function setStatusDetailsOpen(open) {
  localStorage.setItem(STATUS_DETAILS_KEY, open ? "1" : "0");
}

function renderStatusPanel(data) {
  const env = data.env_status || {};
  const mode = data.network_error
    ? "network"
    : (data.demo_mode ? "demo"
       : (data.ok ? "live" : "error"));

  const open = statusDetailsOpen();

  const heading = {
    demo:    "Sample Data",
    live:    "Live Mode — Connected to ONTAP",
    error:   "Live Mode Configured, but ONTAP Connection Failed",
    network: "Cannot Reach the App Backend",
  }[mode];

  const summary = {
    demo: data.demo_forced
      ? "ONTAP_DEMO_MODE is enabled. Showing illustrative data."
      : "No ONTAP credentials detected. Showing illustrative data.",
    live: `All data below comes from the live cluster ${data.cluster_name || ""}${data.ontap_version ? ` (ONTAP ${data.ontap_version})` : ""}.`,
    error: data.error || "The app found credentials, but the cluster rejected them or was unreachable.",
    network: data.error || "The app backend did not respond.",
  }[mode];

  statusPanel.className = `status-panel status-panel--${mode}`;
  statusPanel.innerHTML = `
    <div class="status-panel__bar">
      <span class="status-panel__badge">${
        mode === "demo"  ? "SAMPLE" :
        mode === "live"  ? "LIVE" :
        mode === "error" ? "ERROR" : "OFFLINE"
      }</span>
      <div class="status-panel__text">
        <div class="status-panel__heading">${esc(heading)}</div>
        <div class="status-panel__summary">${esc(summary)}</div>
      </div>
      <button type="button" class="status-panel__toggle" id="status-toggle"
              aria-expanded="${open}">
        ${open ? "Hide details ▾" : "Show details ▸"}
      </button>
    </div>
    <div class="status-panel__details" id="status-details"
         style="display:${open ? "block" : "none"}">
      ${renderStatusDetails(mode, data, env)}
    </div>
  `;

  document.getElementById("status-toggle").addEventListener("click", () => {
    const box = document.getElementById("status-details");
    const btn = document.getElementById("status-toggle");
    const isOpen = box.style.display === "block";
    box.style.display  = isOpen ? "none" : "block";
    btn.textContent    = isOpen ? "Show details ▸" : "Hide details ▾";
    btn.setAttribute("aria-expanded", String(!isOpen));
    setStatusDetailsOpen(!isOpen);
  });

  // Wire up the "Reload to recheck" button (present in demo/error/network modes)
  const reloadBtn = document.getElementById("status-reload-btn");
  if (reloadBtn) reloadBtn.addEventListener("click", () => location.reload());
}

function renderStatusDetails(mode, data, env) {
  const envRows = renderEnvChecklist(env);

  if (mode === "live") {
    return `
      <div class="status-section">
        <h4 class="status-section__title">Connection verified</h4>
        <ul class="status-verified">
          <li><strong>Cluster:</strong> ${esc(data.cluster_name || "—")}</li>
          <li><strong>ONTAP version:</strong> ${esc(data.ontap_version || "unknown")}</li>
          <li><strong>Storage VMs discovered:</strong> ${(data.svms || []).length}</li>
          <li><strong>Protocols supported:</strong> SMB/CIFS and NFS</li>
          <li><strong>Credentials detected from environment:</strong></li>
        </ul>
        ${envRows}
      </div>
      <div class="status-section status-section--muted">
        <h4 class="status-section__title">Want to use sample data instead?</h4>
        <p>Set <code>ONTAP_DEMO_MODE=true</code> as a project environment variable in Domino, then stop and restart this app from the Apps tab.</p>
      </div>
    `;
  }

  if (mode === "network") {
    return `
      <div class="status-section">
        <p>The page loaded, but <code>/api/init</code> did not respond. This usually means the Flask process crashed on startup or is still booting.</p>
        <h4 class="status-section__title">What to try</h4>
        <ol class="status-steps">
          <li>Wait 10–15 seconds for the app to finish starting, then reload.</li>
          <li>Go to <strong>Apps</strong> in the project nav and check the app's status and logs.</li>
          <li>If the app is stopped or crashed, click <strong>Republish</strong>.</li>
        </ol>
      </div>
      <div class="status-section">
        <button type="button" class="btn btn-secondary btn-sm" id="status-reload-btn">Reload page</button>
      </div>
    `;
  }

  // demo or error — both show env checklist + Domino setup instructions + restart note

  const errorSpecific = mode === "error" ? `
    <div class="status-section status-section--error">
      <h4 class="status-section__title">Error from ONTAP</h4>
      <pre class="status-error-detail">${esc(data.error || "Unknown error")}</pre>
      <p class="status-hint">The app detected credentials but could not use them. Common causes: wrong password, wrong cluster IP/hostname, TLS cert failure (try <code>ONTAP_VERIFY_SSL=false</code>), or the account lacks audit read permission.</p>
    </div>
  ` : "";

  return `
    ${errorSpecific}

    <div class="status-section">
      <h4 class="status-section__title">What the app currently sees in its environment</h4>
      ${envRows}
      <p class="status-hint">Values are read once when the app container starts. Changing them in Domino's UI does <strong>not</strong> affect a running app until you restart it (see below).</p>
    </div>

    <div class="status-section">
      <h4 class="status-section__title">How to connect to a real NetApp cluster (FSxN or on-prem)</h4>
      <p style="font-size:13px;margin-bottom:12px;">Follow these steps exactly — no terminal needed. Everything is done through the Domino web UI.</p>

      <ol class="status-steps">
        <li>
          <strong>Step 1 — Store the password as a User Environment Variable</strong> (private, Vault-backed).<br>
          <ol style="margin-top:6px;padding-left:20px;">
            <li>Click your <strong>avatar</strong> (top-right corner of Domino).</li>
            <li>Click <strong>Account Settings</strong>.</li>
            <li>In the left sidebar, click <strong>User Environment Variables</strong>.</li>
            <li>Click <strong>+ Add Variable</strong>.</li>
            <li>Name: <code>ONTAP_PASSWORD</code></li>
            <li>Value: <em>paste your SVM admin password here</em></li>
            <li>Click <strong>Save</strong>.</li>
          </ol>
          <p class="status-hint" style="margin-top:6px;">User Environment Variables are encrypted and never visible to other users or in logs. This is the most secure way to store the password.</p>
        </li>

        <li>
          <strong>Step 2 — Store the cluster IP and username at the Project level.</strong><br>
          <ol style="margin-top:6px;padding-left:20px;">
            <li>Navigate to your project: <strong>netapp_volume_audit_trail</strong>.</li>
            <li>Click <strong>Settings</strong> in the left sidebar.</li>
            <li>Scroll down to the <strong>Environment Variables</strong> section.</li>
            <li>Click <strong>+ Add Variable</strong> and add each of these:</li>
          </ol>
          <table style="margin:10px 0;font-size:13px;border-collapse:collapse;width:100%;">
            <thead>
              <tr style="background:#f0f4fa;border-bottom:2px solid #d8dde6;">
                <th style="padding:8px 12px;text-align:left;font-weight:700;">Variable Name</th>
                <th style="padding:8px 12px;text-align:left;font-weight:700;">Value</th>
                <th style="padding:8px 12px;text-align:left;font-weight:700;">Notes</th>
              </tr>
            </thead>
            <tbody>
              <tr style="border-bottom:1px solid #e8ecf0;">
                <td style="padding:8px 12px;"><code>ONTAP_CLUSTER_IP</code></td>
                <td style="padding:8px 12px;"><code>10.0.35.160</code></td>
                <td style="padding:8px 12px;font-size:12px;color:#6b7d8f;">Management LIF of your FSxN SVM</td>
              </tr>
              <tr style="border-bottom:1px solid #e8ecf0;">
                <td style="padding:8px 12px;"><code>ONTAP_USERNAME</code></td>
                <td style="padding:8px 12px;"><code>vsadmin</code></td>
                <td style="padding:8px 12px;font-size:12px;color:#6b7d8f;">SVM admin user — use the primary SVM admin credentials, <strong>not</strong> the filesystem admin</td>
              </tr>
              <tr style="border-bottom:1px solid #e8ecf0;">
                <td style="padding:8px 12px;"><code>ONTAP_VERIFY_SSL</code></td>
                <td style="padding:8px 12px;"><code>false</code></td>
                <td style="padding:8px 12px;font-size:12px;color:#6b7d8f;">Optional — set to <code>true</code> only if using a trusted TLS cert</td>
              </tr>
            </tbody>
          </table>
          <p class="status-hint">For the <strong>life-sciences-demo</strong> environment, the FSxN filesystem is <code>fs-031fcf7d53ab65bb8</code> in <code>us-west-2</code>, SVM name is <code>demo-ls102402-svm</code>, and the management LIF is <code>10.0.35.160</code>.</p>
        </li>

        <li>
          <strong>Step 3 — Restart this app so it picks up the new variables.</strong><br>
          <ol style="margin-top:6px;padding-left:20px;">
            <li>Go to the project's left sidebar and click <strong>App</strong> (or <strong>Publish</strong> depending on your Domino version).</li>
            <li>Click <strong>Stop</strong> on the running app.</li>
            <li>Once stopped, click <strong>Publish</strong> (or <strong>Start</strong>) to restart it.</li>
            <li>Wait for the app to finish starting (usually 30–60 seconds).</li>
            <li>Reload this page in your browser.</li>
          </ol>
          <p class="status-hint">Simply reloading this page without restarting the app will <strong>not</strong> pick up new environment variables. The app reads them once at startup.</p>
        </li>

        <li>
          <strong>Step 4 — Verify the connection.</strong><br>
          After the restart, this panel should flip to <span style="color:#18a058;font-weight:700;">green "LIVE"</span> mode.
          If it stays on demo or shows an error, check:
          <ul style="margin-top:4px;padding-left:20px;">
            <li>Is the password correct? (Re-enter it in Account Settings if unsure)</li>
            <li>Is the cluster IP reachable from Domino's network? (<code>10.0.35.160</code>)</li>
            <li>Does the account have permission to read audit data?</li>
          </ul>
        </li>
      </ol>
    </div>

    <div class="status-section">
      <h4 class="status-section__title">FSxN-specific: Ensure auditing is enabled</h4>
      <p style="font-size:13px;">For this app to show real file access events, <strong>auditing must be enabled</strong> on the SVM. If you see a "no audit log files" message after connecting, ask your NetApp / AWS administrator to enable it:</p>
      <pre class="status-error-detail" style="background:#0f2035;color:#a8d0f0;">
# Connect to the FSxN CLI (via SSH or AWS CloudShell):
ssh fsxadmin@10.0.35.160

# Create the audit configuration (one-time setup):
vserver audit create -vserver demo-ls102402-svm \\
  -destination /vol/audit_log \\
  -format evtx \\
  -rotate-size 100MB

# Enable auditing:
vserver audit enable -vserver demo-ls102402-svm

# Verify:
vserver audit show -vserver demo-ls102402-svm</pre>
      <p class="status-hint">The destination volume (<code>/vol/audit_log</code>) must exist on the SVM. NFS file access events are captured automatically once auditing is enabled — no CIFS/SMB server is required.</p>
    </div>

    <div class="status-section status-section--muted">
      <h4 class="status-section__title">Already set the variables and restarted?</h4>
      <p>Click below to re-check. If this panel still shows an error after a restart, at least one variable is still missing or incorrect — the checklist above will show which one.</p>
      <button type="button" class="btn btn-secondary btn-sm" id="status-reload-btn">Reload and re-check</button>
    </div>
  `;
}

function renderEnvChecklist(env) {
  const rows = [
    ["ONTAP_CLUSTER_IP", "Cluster IP or hostname",        true],
    ["ONTAP_USERNAME",   "ONTAP read-only user",          true],
    ["ONTAP_PASSWORD",   "Password (masked for display)", true],
    ["ONTAP_VERIFY_SSL", "Verify TLS cert (optional)",    false],
    ["ONTAP_DEMO_MODE",  "Force demo mode (optional)",    false],
  ];
  return `<ul class="env-checklist">${rows.map(([key, label, required]) => {
    const entry    = env[key] || {};
    const present  = !!entry.configured;
    const value    = entry.value;
    const iconCls  = present ? "ok" : (required ? "missing" : "off");
    const icon     = present ? "✓" : (required ? "✗" : "—");
    const valueStr = value != null
      ? ` <code class="env-checklist__value">${esc(String(value))}</code>`
      : (required ? ` <span class="env-checklist__missing">not set</span>` : "");
    return `
      <li class="env-checklist__row env-checklist__row--${iconCls}">
        <span class="env-checklist__icon">${icon}</span>
        <code class="env-checklist__key">${esc(key)}</code>
        <span class="env-checklist__label">${esc(label)}${required ? "" : " <em>(optional)</em>"}</span>
        ${valueStr}
      </li>`;
  }).join("")}</ul>`;
}

// -----------------------------------------------------------------------
// Demo indicators — persistent cues so users never forget they're
// looking at synthetic data while scrolling results.
// -----------------------------------------------------------------------
function applyDemoIndicators(isDemo) {
  document.body.classList.toggle("is-demo-mode", isDemo);
}

function applyOverrideIndicator(isOverride) {
  let el = document.getElementById("demo-override-hint");
  if (isOverride) {
    if (!el) {
      el = document.createElement("div");
      el.id = "demo-override-hint";
      el.style.cssText = "position:fixed;bottom:4px;right:8px;font-size:10px;color:#999;opacity:0.5;z-index:1;pointer-events:none;";
      el.textContent = "sample data active";
      document.body.appendChild(el);
    }
  } else if (el) {
    el.remove();
  }
}

// -----------------------------------------------------------------------
// Populate SVM dropdown
// -----------------------------------------------------------------------
function populateSvms(svms) {
  svmSelect.innerHTML = "";

  if (!svms.length) {
    svmSelect.innerHTML = '<option value="">No data SVMs found</option>';
    return;
  }

  const placeholder = document.createElement("option");
  placeholder.value       = "";
  placeholder.textContent = `Select a storage virtual machine (${svms.length} available)`;
  svmSelect.appendChild(placeholder);

  // "All SVMs" option
  const allOpt = document.createElement("option");
  allOpt.value       = "__all__";
  allOpt.textContent = `All SVMs (${svms.length})`;
  svmSelect.appendChild(allOpt);

  svms.forEach(name => {
    const opt = document.createElement("option");
    opt.value       = name;
    opt.textContent = name;
    svmSelect.appendChild(opt);
  });

  // When SVM changes, update volume dropdown and run preflight
  svmSelect.addEventListener("change", () => {
    populateVolumes(svmSelect.value);
    runPreflight(svmSelect.value);
  });
}

function populateVolumes(svmName) {
  volumeSelect.innerHTML = '<option value="">All volumes</option>';

  let vols = [];
  if (svmName === "__all__") {
    // Combine all volumes from all SVMs
    const seen = new Set();
    Object.values(volumesBySvm).forEach(arr =>
      arr.forEach(v => { if (!seen.has(v)) { seen.add(v); vols.push(v); } }));
    vols.sort();
  } else if (svmName && volumesBySvm[svmName]) {
    vols = [...volumesBySvm[svmName]].sort();
  }

  vols.forEach(name => {
    const opt = document.createElement("option");
    opt.value       = name;
    opt.textContent = name;
    volumeSelect.appendChild(opt);
  });
}

// -----------------------------------------------------------------------
// Preflight checks — validates ONTAP readiness per SVM
// -----------------------------------------------------------------------
const preflightSection = document.getElementById("preflight-section");
const preflightBody    = document.getElementById("preflight-body");
const preflightChecks  = document.getElementById("preflight-checks");
const preflightSummary = document.getElementById("preflight-summary");
const togglePreflight  = document.getElementById("toggle-preflight");

togglePreflight.addEventListener("click", () => {
  const open = preflightBody.style.display === "block";
  preflightBody.style.display = open ? "none" : "block";
  togglePreflight.innerHTML   = open
    ? "&#9656; Prerequisites Check"
    : "&#9662; Prerequisites Check";
});

async function runPreflight(svmName) {
  if (!svmName) {
    preflightSection.style.display = "none";
    return;
  }

  preflightSection.style.display = "block";
  preflightSummary.textContent   = "Checking…";
  preflightSummary.className     = "preflight-summary";

  try {
    const res  = await post("/api/preflight", { svm_name: svmName });
    const data = await res.json();
    renderPreflight(data.checks || []);
  } catch (err) {
    preflightSummary.textContent = "Check failed";
    preflightSummary.className   = "preflight-summary has-errors";
    preflightChecks.innerHTML    = `<div class="preflight-item status-error">
      <span class="preflight-icon">&#10060;</span>
      <div class="preflight-content">
        <div class="preflight-label">Could not run checks</div>
        <div class="preflight-detail">${esc(err.message)}</div>
      </div>
    </div>`;
  }
}

function renderPreflight(checks) {
  if (!checks.length) {
    preflightSection.style.display = "none";
    return;
  }

  const icons = { pass: "&#10003;", warn: "&#9888;", fail: "&#10007;", error: "&#10007;", info: "&#8505;" };
  const fails  = checks.filter(c => c.status === "fail" || c.status === "error").length;
  const warns  = checks.filter(c => c.status === "warn").length;
  const passes = checks.filter(c => c.status === "pass").length;
  const infos  = checks.filter(c => c.status === "info").length;

  if (fails > 0) {
    preflightSummary.textContent = `${fails} issue(s) need attention`;
    preflightSummary.className   = "preflight-summary has-errors";
    // Auto-expand if there are failures
    preflightBody.style.display  = "block";
    togglePreflight.innerHTML    = "&#9662; Prerequisites Check";
  } else if (warns > 0) {
    preflightSummary.textContent = `All passed, ${warns} warning(s)`;
    preflightSummary.className   = "preflight-summary has-issues";
  } else {
    preflightSummary.textContent = `All ${passes} check(s) passed` + (infos > 0 ? `, ${infos} info` : "");
    preflightSummary.className   = "preflight-summary all-pass";
  }

  preflightChecks.innerHTML = checks.map(c => `
    <div class="preflight-item status-${c.status}">
      <span class="preflight-icon">${icons[c.status] || "?"}</span>
      <div class="preflight-content">
        <div class="preflight-label">${esc(c.label)}</div>
        <div class="preflight-detail">${esc(c.detail)}</div>
      </div>
    </div>
  `).join("");
}

// -----------------------------------------------------------------------
// Toggle optional path filter
// -----------------------------------------------------------------------
toggleFilters.addEventListener("click", () => {
  const open = filterFields.style.display === "block";
  filterFields.style.display = open ? "none" : "block";
  toggleFilters.innerHTML    = open
    ? "&#9656; Filters"
    : "&#9662; Filters";
});

// -----------------------------------------------------------------------
// Main query — user just picks SVM + dates
// -----------------------------------------------------------------------
queryForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  hideAlert();
  clearResults();
  setLoading(true);
  runBtn.disabled = true;

  currentSvm = svmSelect.value;

  // Collect checked event types
  const checkedTypes = [...document.querySelectorAll('input[name="event_type"]:checked')]
    .map(cb => cb.value);
  const allTypes = document.querySelectorAll('input[name="event_type"]').length;

  const payload = {
    svm_name:      currentSvm,
    start_date:    document.getElementById("start_date").value,
    end_date:      document.getElementById("end_date").value,
    path_prefix:   document.getElementById("path_prefix")?.value.trim() || "",
    username:      document.getElementById("username_filter")?.value.trim() || "",
    result_filter: document.getElementById("result_filter")?.value || "all",
    volume:        document.getElementById("volume")?.value || "",
    // Only send event_types if user unchecked something (otherwise send empty = all)
    event_types:   checkedTypes.length < allTypes ? checkedTypes : [],
  };

  try {
    const res  = await post("/api/query", payload);
    const data = await res.json();

    if (!res.ok || data.error) {
      showAlert("error", data.error || "An unknown error occurred.");
      return;
    }

    allEvents = data.events || [];
    renderMetaBar(data.meta, data.warning);
    renderTable(allEvents);

    if (data.warning)     showAlert("info", data.warning);
    if (data.parse_errors?.length) {
      showAlert("info",
        `Completed with ${data.parse_errors.length} file parse error(s). ` +
        `First: ${data.parse_errors[0]}`);
    }

    if (allEvents.length) {
      resultsCard.style.display = "block";
      clearBtn.style.display    = "inline-flex";
      resultsCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }

  } catch (err) {
    showAlert("error", `Request failed: ${err.message}`);
  } finally {
    setLoading(false);
    runBtn.disabled = false;
  }
});

// -----------------------------------------------------------------------
// Clear
// -----------------------------------------------------------------------
clearBtn.addEventListener("click", () => {
  clearResults();
  hideAlert();
  metaBar.style.display     = "none";
  clearBtn.style.display    = "none";
});

function clearResults() {
  allEvents = filteredEvents = [];
  tbody.innerHTML           = "";
  resultsCard.style.display = "none";
  rowCount.textContent      = "";
  filterCount.textContent   = "";
  tableSearch.value         = "";
}

// -----------------------------------------------------------------------
// Live sessions modal — SVM auto-selected from dropdown
// -----------------------------------------------------------------------
liveBtn.addEventListener("click", async () => {
  const svm = svmSelect.value;
  if (!svm) {
    showAlert("error", "Select an SVM first.");
    return;
  }
  sessionsModal.style.display = "flex";
  sessionsBody.innerHTML      = "<p>Loading live sessions…</p>";

  try {
    const res  = await post("/api/live_sessions", { svm_name: svm });
    const data = await res.json();

    if (data.error) {
      sessionsBody.innerHTML = `<div class="alert alert-error">${esc(data.error)}</div>`;
      return;
    }

    const sessions = data.sessions || [];
    const note = data.note || "";

    if (!sessions.length) {
      sessionsBody.innerHTML =
        `<p>No active sessions found for <strong>${esc(svm)}</strong>.</p>` +
        (note ? `<p style="font-size:12px;color:#6b7d8f;margin-top:8px;">${esc(note)}</p>` : "");
      return;
    }

    sessionsBody.innerHTML = `
      <p class="sessions-meta">${sessions.length} active session(s) — live snapshot</p>
      ${note ? `<p style="font-size:12px;color:#6b7d8f;margin-bottom:12px;">${esc(note)}</p>` : ""}
      <div class="table-scroll">
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <thead style="background:#f8f9fb;">
          <tr>
            <th style="${thS()}">User</th>
            <th style="${thS()}">Client IP</th>
            <th style="${thS()}">SVM</th>
            <th style="${thS()}">Protocol</th>
            <th style="${thS()}">Duration</th>
            <th style="${thS()}">Open Files</th>
          </tr>
        </thead>
        <tbody>
          ${sessions.map(s => `
            <tr>
              <td style="${tdS()}"><strong>${esc(s.user || "—")}</strong></td>
              <td style="${tdS()};font-family:monospace">${esc(s.client_ip || "—")}</td>
              <td style="${tdS()}">${esc(s.svm?.name || "—")}</td>
              <td style="${tdS()}">${protocolBadge(s.protocol || "SMB")}</td>
              <td style="${tdS()}">${esc(s.connected_duration || "—")}</td>
              <td style="${tdS()}">${s.open_files ?? "—"}</td>
            </tr>`).join("")}
        </tbody>
      </table>
      </div>`;
  } catch (err) {
    sessionsBody.innerHTML =
      `<div class="alert alert-error">Request failed: ${esc(err.message)}</div>`;
  }
});

modalCloseBtn.addEventListener("click", () => sessionsModal.style.display = "none");
sessionsModal.addEventListener("click", e => {
  if (e.target === sessionsModal) sessionsModal.style.display = "none";
});

// -----------------------------------------------------------------------
// Table rendering
// -----------------------------------------------------------------------
function renderTable(events) {
  filteredEvents = applyFilter(events, tableSearch.value);
  const sorted   = applySort(filteredEvents, sortCol, sortDir);
  tbody.innerHTML = sorted.map(rowHtml).join("");
  updateCounts(events.length, filteredEvents.length);
}

function rowHtml(ev) {
  return `<tr>
    <td style="white-space:nowrap">${esc(ev.timestamp_str)}</td>
    <td>${esc(ev.svm_name || "—")}</td>
    <td>${protocolBadge(ev.protocol || "SMB")}</td>
    <td>${eventBadge(ev.event_type)}</td>
    <td><strong>${esc(ev.user)}</strong></td>
    <td>${esc(ev.domain)}</td>
    <td class="col-ip">${esc(ev.client_ip)}</td>
    <td class="col-path" title="${esc(ev.object_path)}">${esc(truncate(ev.object_path, 60))}</td>
    <td>${esc(ev.share_name)}</td>
    <td>${esc(ev.access_operations)}</td>
    <td>${resultBadge(ev.result)}</td>
  </tr>`;
}

function protocolBadge(proto) {
  const cls = proto === "NFS" ? "badge-nfs" : "badge-smb";
  return `<span class="badge ${cls}">${esc(proto)}</span>`;
}

function eventBadge(type) {
  const cls = {
    "Object Accessed":      "badge-info",
    "Handle Requested":     "badge-info",
    "Object Deleted":       "badge-danger",
    "Permissions Changed":  "badge-warn",
    "Share Accessed":       "badge-info",
    "Share Access Checked": "badge-info",
  }[type] || "badge-info";
  return `<span class="badge ${cls}">${esc(type)}</span>`;
}

function resultBadge(result) {
  return result === "Success"
    ? `<span class="badge badge-success">Success</span>`
    : `<span class="badge badge-danger">${esc(result)}</span>`;
}

// -----------------------------------------------------------------------
// Client-side filter
// -----------------------------------------------------------------------
tableSearch.addEventListener("input", () => renderTable(allEvents));

function applyFilter(events, q) {
  q = (q || "").toLowerCase().trim();
  if (!q) return events;
  const cols = ["timestamp_str", "svm_name", "protocol", "event_type", "user", "domain",
                "client_ip", "object_path", "share_name", "access_operations", "result"];
  return events.filter(ev => cols.some(c => (ev[c] || "").toLowerCase().includes(q)));
}

// -----------------------------------------------------------------------
// Sort
// -----------------------------------------------------------------------
document.querySelectorAll("th.sortable").forEach(th => {
  th.addEventListener("click", () => {
    const col = th.dataset.col;
    sortDir = (sortCol === col && sortDir === "asc") ? "desc" : "asc";
    sortCol = col;
    document.querySelectorAll("th").forEach(h =>
      h.classList.remove("sorted-asc", "sorted-desc"));
    th.classList.add(sortDir === "asc" ? "sorted-asc" : "sorted-desc");
    renderTable(allEvents);
  });
});

function applySort(events, col, dir) {
  return [...events].sort((a, b) => {
    const av = String(a[col] ?? ""), bv = String(b[col] ?? "");
    return dir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
  });
}

// -----------------------------------------------------------------------
// CSV Export
// -----------------------------------------------------------------------
exportCsvBtn.addEventListener("click", () => {
  if (!filteredEvents.length) return;
  const cols = ["timestamp_str", "svm_name", "protocol", "event_type", "user", "domain",
                "client_ip", "object_path", "share_name", "access_operations", "result"];
  const csv  = [cols.join(","),
    ...filteredEvents.map(ev =>
      cols.map(c => `"${String(ev[c] ?? "").replace(/"/g, '""')}"`).join(","))
  ].join("\n");
  const a    = Object.assign(document.createElement("a"), {
    href:     URL.createObjectURL(new Blob([csv], { type: "text/csv" })),
    download: `file_access_audit_${currentSvm}_${isoDate(new Date())}.csv`,
  });
  a.click();
});

// -----------------------------------------------------------------------
// Meta bar
// -----------------------------------------------------------------------
function renderMetaBar(meta) {
  if (!meta) return;
  metaBar.style.display = "flex";
  metaBar.innerHTML = `
    ${metaItem("Project",       meta.project_name)}
    ${metaItem("Queried by",    meta.queried_by)}
    ${metaItem("SVM",           meta.svm_name)}
    ${metaItem("Date range",    `${meta.query_start} → ${meta.query_end}`)}
    ${metaItem("Protocols",     meta.protocol_filter || "SMB/CIFS and NFS")}
    ${metaItem("Files checked", meta.files_checked)}
    <div class="meta-item">
      <span class="meta-label">Events found</span>
      <span class="meta-count">${meta.events_found}</span>
    </div>
    ${metaItem("Generated",     meta.generated_at)}
    ${meta.files_skipped_due_to_cap > 0
      ? `<div class="meta-item" style="color:#d4850a;">
           <span class="meta-label">Files skipped (cap reached)</span>
           <span class="meta-value">${meta.files_skipped_due_to_cap}</span>
         </div>` : ""}
  `;
}

function metaItem(label, value) {
  return `<div class="meta-item">
    <span class="meta-label">${label}</span>
    <span class="meta-value">${esc(String(value ?? "—"))}</span>
  </div>`;
}

// -----------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------
function showAlert(type, msg) {
  alertBox.style.display = "block";
  alertBox.className     = `alert alert-${type}`;
  alertBox.textContent   = msg;
}
function hideAlert()      { alertBox.style.display = "none"; }
function setLoading(on)   { loading.style.display  = on ? "flex" : "none"; }
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function updateCounts(total, visible) {
  rowCount.textContent    = `${total} event${total !== 1 ? "s" : ""} returned`;
  filterCount.textContent = visible !== total ? `(${visible} shown after filter)` : "";
}
function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function truncate(s, n) { return s?.length > n ? "…" + s.slice(-(n - 1)) : (s || "—"); }
function isoDate(d)      { return d.toISOString().split("T")[0]; }
async function post(url, body) {
  // Build absolute URL using API_BASE (derived from page location)
  // so requests always route through the Domino reverse proxy.
  const fullUrl = API_BASE + url.replace(/^\//, "");
  return fetch(fullUrl, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
}
function thS() { return "padding:8px 12px;text-align:left;font-size:11px;font-weight:700;color:#6b7d8f;text-transform:uppercase;border-bottom:2px solid #d8dde6;"; }
function tdS() { return "padding:8px 12px;border-bottom:1px solid #f0f2f5;"; }

// -----------------------------------------------------------------------
// Hidden demo override — triple-click the header logo to toggle
// -----------------------------------------------------------------------
(() => {
  const logo = document.querySelector(".brand-logo");
  if (!logo) return;
  let clicks = 0, timer = null;
  logo.style.cursor = "default";
  logo.addEventListener("click", () => {
    clicks++;
    clearTimeout(timer);
    if (clicks >= 3) {
      clicks = 0;
      post("/api/demo-toggle", {}).then(r => r.json()).then(() => {
        location.reload();
      });
    } else {
      timer = setTimeout(() => { clicks = 0; }, 600);
    }
  });
})();
