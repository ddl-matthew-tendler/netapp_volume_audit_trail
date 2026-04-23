/**
 * Domino NetApp SMB Audit Viewer — Frontend Logic
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

  function showInitError(msg) {
    initLoading.style.display = "none";
    initError.style.display   = "block";
    initError.innerHTML       = msg;
  }

  // Abort the fetch if it takes more than 12 seconds
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);

  try {
    const res  = await fetch(API_BASE + "api/init", { signal: controller.signal });
    clearTimeout(timer);
    const data = await res.json();

    if (!res.ok || !data.ok) {
      // ONTAP connection failed — but still show the form if demo mode is active
      if (data.demo_mode) {
        showForm(data);
      } else {
        showInitError(`
          <strong>Could not connect to ONTAP.</strong> ${esc(data.error || "Unknown error")}
          <br><br>
          Ask your administrator to verify <code>ONTAP_CLUSTER_IP</code>,
          <code>ONTAP_USERNAME</code>, and <code>ONTAP_PASSWORD</code> are set correctly
          on this app, then republish it.`);
      }
      return;
    }

    showForm(data);

  } catch (e) {
    clearTimeout(timer);
    const isTimeout = e.name === "AbortError";
    showInitError(`
      <strong>${isTimeout ? "Request timed out" : "Network error"} — could not reach the app backend.</strong>
      ${isTimeout ? "The server did not respond within 12 seconds." : `Details: ${esc(e.message)}`}
      <br><br>
      Try <a href="javascript:location.reload()">reloading the page</a>.
      If this keeps happening, ask your administrator to check that the app is running.`);
  }
})();

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

  // When SVM changes, update volume dropdown
  svmSelect.addEventListener("change", () => populateVolumes(svmSelect.value));
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
    if (!sessions.length) {
      sessionsBody.innerHTML =
        `<p>No active SMB sessions found for <strong>${esc(svm)}</strong>.</p>`;
      return;
    }

    sessionsBody.innerHTML = `
      <p class="sessions-meta">${sessions.length} active session(s) — live snapshot</p>
      <div class="table-scroll">
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <thead style="background:#f8f9fb;">
          <tr>
            <th style="${thS()}">User</th>
            <th style="${thS()}">Client IP</th>
            <th style="${thS()}">SVM</th>
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
  const cols = ["timestamp_str", "svm_name", "event_type", "user", "domain",
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
  const cols = ["timestamp_str", "svm_name", "event_type", "user", "domain",
                "client_ip", "object_path", "share_name", "access_operations", "result"];
  const csv  = [cols.join(","),
    ...filteredEvents.map(ev =>
      cols.map(c => `"${String(ev[c] ?? "").replace(/"/g, '""')}"`).join(","))
  ].join("\n");
  const a    = Object.assign(document.createElement("a"), {
    href:     URL.createObjectURL(new Blob([csv], { type: "text/csv" })),
    download: `smb_audit_${currentSvm}_${isoDate(new Date())}.csv`,
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
