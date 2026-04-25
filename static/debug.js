/**
 * Debug Console — NetApp File Access Audit Viewer
 *
 * Captures and displays:
 *   - Every fetch/XHR call: exact resolved URL, method, status, latency, response preview
 *   - JavaScript errors (window.onerror)
 *   - Unhandled promise rejections
 *   - Console.error / console.warn output
 *   - Environment snapshot (page URL, base path, user agent, demo mode)
 *
 * Toggle: Ctrl+` (backtick)  or click the "▶ Debug" floating button.
 *
 * IMPORTANT: This script is loaded AFTER app.js so it wraps fetch after
 * app.js has already set up its logic — but the fetch interceptor catches
 * all subsequent calls made by app.js at runtime.
 */

(function () {
  "use strict";

  // ── DOM refs ─────────────────────────────────────────────────────────
  const fab     = document.getElementById("debug-fab");
  const panel   = document.getElementById("debug-console");
  const body    = document.getElementById("debug-body");
  const badge   = document.getElementById("debug-badge");
  const envEl   = document.getElementById("debug-env");
  const btnCopy = document.getElementById("debug-copy");
  const btnClear= document.getElementById("debug-clear");
  const btnClose= document.getElementById("debug-close");

  // ── State ─────────────────────────────────────────────────────────────
  let logs      = [];   // { level, time, message, detail }
  let errorCount= 0;
  let open      = false;

  // ── Toggle panel ──────────────────────────────────────────────────────
  function togglePanel() {
    open = !open;
    panel.style.display = open ? "flex" : "none";
    fab.style.display   = open ? "none" : "flex";
    if (open) renderEnv();
  }

  fab.addEventListener("click", togglePanel);
  btnClose.addEventListener("click", togglePanel);
  document.addEventListener("keydown", e => {
    if (e.ctrlKey && e.key === "`") { e.preventDefault(); togglePanel(); }
  });

  // ── Clear ──────────────────────────────────────────────────────────────
  btnClear.addEventListener("click", () => {
    logs = [];
    errorCount = 0;
    body.innerHTML = "";
    updateBadge();
  });

  // ── Copy ──────────────────────────────────────────────────────────────
  btnCopy.addEventListener("click", () => {
    const text = logs.map(l =>
      `[${l.time}] [${l.level.toUpperCase()}] ${l.message}` +
      (l.detail ? `\n    ${l.detail}` : "")
    ).join("\n");
    navigator.clipboard.writeText(text).then(() => {
      btnCopy.textContent = "Copied!";
      setTimeout(() => btnCopy.textContent = "Copy", 1500);
    });
  });

  // ── Environment snapshot ───────────────────────────────────────────────
  function renderEnv() {
    const loc = window.location;
    const items = [
      ["Page URL",    loc.href],
      ["Origin",      loc.origin],
      ["Path",        loc.pathname],
      ["Base href",   document.baseURI],
      ["Demo mode",   (document.body.innerHTML.includes("Demo Mode") ? "YES ⚠" : "no")],
      ["User agent",  navigator.userAgent.substring(0, 80) + "…"],
      ["Time (local)",new Date().toLocaleString()],
    ];
    envEl.innerHTML = items.map(([k, v]) =>
      `<span class="dbg-env-item"><span class="dbg-env-key">${k}:</span> ${escHtml(v)}</span>`
    ).join("");
  }

  // ── Log entry ─────────────────────────────────────────────────────────
  function log(level, message, detail = "") {
    const now  = new Date();
    const time = now.toTimeString().slice(0, 8) + "." +
                 String(now.getMilliseconds()).padStart(3, "0");
    const entry = { level, time, message, detail };
    logs.push(entry);
    appendRow(entry);
    updateBadge();
    if (level === "error") {
      errorCount++;
      // Auto-open on first error so the user sees it
      if (!open) togglePanel();
    }
  }

  function appendRow({ level, time, message, detail }) {
    const row = document.createElement("div");
    row.className = `dbg-row dbg-${level}`;
    row.innerHTML =
      `<span class="dbg-time">${time}</span>` +
      `<span class="dbg-level">${level.toUpperCase()}</span>` +
      `<span class="dbg-msg">${escHtml(message)}</span>` +
      (detail ? `<pre class="dbg-detail">${escHtml(detail)}</pre>` : "");
    body.appendChild(row);
    body.scrollTop = body.scrollHeight;
  }

  function updateBadge() {
    badge.textContent = logs.length;
    badge.style.background = errorCount > 0 ? "#c0392b" : "#1a6dc8";
  }

  // ── Intercept fetch ───────────────────────────────────────────────────
  // Wrap window.fetch so every call (including from app.js) is logged
  // with the fully resolved URL, method, status, and latency.
  const _origFetch = window.fetch;
  window.fetch = function (input, init = {}) {
    const method  = (init.method || "GET").toUpperCase();
    const rawUrl  = typeof input === "string" ? input : input.url;

    // Resolve the URL exactly as the browser will — this is the key diagnostic
    // for Domino proxy path issues.
    let resolvedUrl;
    try { resolvedUrl = new URL(rawUrl, window.location.href).href; }
    catch { resolvedUrl = rawUrl; }

    const t0 = performance.now();
    log("info", `→ ${method} ${rawUrl}`,
        `Resolved: ${resolvedUrl}\nBase: ${window.location.href}`);

    return _origFetch.call(this, input, init).then(async res => {
      const ms      = Math.round(performance.now() - t0);
      const level   = res.ok ? "success" : "error";
      let preview   = "";
      try {
        // Clone so the real consumer can still read the body
        const clone = res.clone();
        const text  = await clone.text();
        preview     = text.length > 400 ? text.slice(0, 400) + "…" : text;
      } catch { preview = "(could not read body)"; }

      log(level,
        `← ${res.status} ${res.statusText}  ${method} ${rawUrl}  [${ms}ms]`,
        `URL: ${resolvedUrl}\n\nResponse preview:\n${preview}`
      );
      return res;

    }).catch(err => {
      const ms = Math.round(performance.now() - t0);
      log("error",
        `✗ FAILED ${method} ${rawUrl} [${ms}ms] — ${err.name}: ${err.message}`,
        `Resolved URL: ${resolvedUrl}\n\nThis usually means:\n` +
        `  • Network error or CORS block\n` +
        `  • Domino proxy path mismatch (leading "/" in URL)\n` +
        `  • AbortError = request timed out\n\n` +
        `Stack: ${err.stack || "(none)"}`
      );
      throw err;
    });
  };

  // ── Intercept console.error / console.warn ────────────────────────────
  const _origError = console.error.bind(console);
  const _origWarn  = console.warn.bind(console);

  console.error = function (...args) {
    log("error", args.map(String).join(" "));
    _origError(...args);
  };
  console.warn = function (...args) {
    log("warn", args.map(String).join(" "));
    _origWarn(...args);
  };

  // ── Global JS errors ──────────────────────────────────────────────────
  window.addEventListener("error", e => {
    log("error",
      `JS ERROR: ${e.message}`,
      `File: ${e.filename}  Line: ${e.lineno}:${e.colno}\nStack: ${e.error?.stack || "(none)"}`
    );
  });

  window.addEventListener("unhandledrejection", e => {
    log("error",
      `UNHANDLED PROMISE REJECTION: ${e.reason?.message || e.reason}`,
      `Stack: ${e.reason?.stack || "(none)"}`
    );
  });

  // ── Startup log ───────────────────────────────────────────────────────
  log("info", "Debug console initialised",
    `Page: ${window.location.href}\n` +
    `Path: ${window.location.pathname}\n` +
    `fetch interceptor: active\n` +
    `Tip: API calls should use relative URLs (no leading /) so they\n` +
    `     resolve through the Domino proxy correctly.`
  );

  // ── Helpers ───────────────────────────────────────────────────────────
  function escHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

})();
