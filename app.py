"""
Domino NetApp File Access Audit Viewer
=======================================
A Domino App for administrators to query NetApp ONTAP audit logs for
file-access events over both SMB/CIFS and NFS protocols.  No data is
stored in Domino — results are pulled from ONTAP on demand and displayed
in the browser only.

Required environment variables (set once by IT admin when publishing the app):
  ONTAP_CLUSTER_IP   Cluster management IP or hostname  e.g. "10.0.35.160"
  ONTAP_USERNAME     ONTAP account with audit read access e.g. "vsadmin"
  ONTAP_PASSWORD     Password for the above account

Optional environment variables:
  ONTAP_VERIFY_SSL   "true" to enable TLS cert verification (default: "false")
  ONTAP_MAX_FILES    Max EVTX files fetched per query (default: 10, max: 50)

Domino automatically injects at runtime (no config needed):
  DOMINO_PROJECT_NAME       Name of the current Domino project
  DOMINO_STARTING_USERNAME  Username of whoever launched the app
"""

import os
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template, request

from ontap_client import OntapClient, OntapError
from evtx_parser import parse_smb_events, EVTX_AVAILABLE
from demo_data import generate_demo_events, DEMO_SVM_LIST, DEMO_CLUSTER_NAME, DEMO_VOLUMES

# Demo mode activates automatically when ONTAP credentials are not configured,
# so the app is always usable out of the box.
_ONTAP_CONFIGURED = bool(
    os.environ.get("ONTAP_CLUSTER_IP") and
    os.environ.get("ONTAP_USERNAME") and
    os.environ.get("ONTAP_PASSWORD")
)
_DEMO_FORCED = os.environ.get("ONTAP_DEMO_MODE", "false").lower() == "true"
DEMO_MODE = _DEMO_FORCED or not _ONTAP_CONFIGURED
_DEMO_OVERRIDE = False  # Runtime toggle — set via hidden UI switch


def _is_demo() -> bool:
    """Check if demo mode is active (static config OR runtime override)."""
    return DEMO_MODE or _DEMO_OVERRIDE


def _env_status() -> dict:
    """Report which ONTAP env vars the app actually sees at runtime.

    Values are never returned — only presence. The password row is always
    masked so viewers of the UI can't read it.
    """
    cluster = os.environ.get("ONTAP_CLUSTER_IP", "").strip()
    user    = os.environ.get("ONTAP_USERNAME", "").strip()
    pwd     = os.environ.get("ONTAP_PASSWORD", "").strip()
    verify  = os.environ.get("ONTAP_VERIFY_SSL", "false").strip().lower()
    return {
        "ONTAP_CLUSTER_IP": {"configured": bool(cluster), "value": cluster or None},
        "ONTAP_USERNAME":   {"configured": bool(user),    "value": user or None},
        "ONTAP_PASSWORD":   {"configured": bool(pwd),     "value": "••••••••" if pwd else None},
        "ONTAP_VERIFY_SSL": {"configured": True,          "value": verify or "false"},
        "ONTAP_DEMO_MODE":  {"configured": _DEMO_FORCED,  "value": "true" if _DEMO_FORCED else "false"},
    }


def _demo_reason() -> str:
    """Explain — in one short sentence — why the app is in demo mode."""
    if _DEMO_FORCED:
        return "ONTAP_DEMO_MODE is set to 'true', which forces demo mode even if credentials are configured."
    missing = [k for k in ("ONTAP_CLUSTER_IP", "ONTAP_USERNAME", "ONTAP_PASSWORD")
               if not os.environ.get(k, "").strip()]
    if missing:
        return f"Missing environment variable(s): {', '.join(missing)}."
    return ""

app = Flask(__name__)


def _get_client() -> OntapClient:
    """Build an OntapClient from environment variables only — no user input needed."""
    cluster_ip = os.environ.get("ONTAP_CLUSTER_IP", "").strip()
    username   = os.environ.get("ONTAP_USERNAME", "").strip()
    password   = os.environ.get("ONTAP_PASSWORD", "").strip()
    verify_ssl = os.environ.get("ONTAP_VERIFY_SSL", "false").lower() == "true"

    if not cluster_ip or not username or not password:
        raise OntapError(
            "ONTAP connection is not configured.  Ask your administrator to set "
            "ONTAP_CLUSTER_IP, ONTAP_USERNAME, and ONTAP_PASSWORD as environment variables "
            "on this app."
        )
    return OntapClient(cluster_ip, username, password, verify_ssl=verify_ssl)


def _domino_context() -> dict:
    """Return Domino runtime context that is auto-injected by the platform."""
    return {
        "project_name": os.environ.get("DOMINO_PROJECT_NAME", ""),
        "username":     os.environ.get("DOMINO_STARTING_USERNAME",
                        os.environ.get("DOMINO_USER_NAME", "")),
    }


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    ctx = _domino_context()
    # Read CSS and JS files to inline them into the HTML.
    # This eliminates all external resource loads, which is the only
    # reliable way to serve a Domino App behind Domino's reverse proxy
    # (Flask has no knowledge of the proxy prefix, so external <link>
    # and <script src> paths can never resolve correctly).
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    inline = {}
    for name in ("styles.css", "app.js", "debug.js"):
        path = os.path.join(static_dir, name)
        with open(path, "r") as f:
            inline[name] = f.read()
    return render_template(
        "index.html",
        project_name=ctx["project_name"],
        username=ctx["username"],
        demo_mode=_is_demo(),
        ontap_configured=_ONTAP_CONFIGURED,
        evtx_available=(EVTX_AVAILABLE or _is_demo()),
        inline_css=inline["styles.css"],
        inline_app_js=inline["app.js"],
        inline_debug_js=inline["debug.js"],
    )


# ---------------------------------------------------------------------------
# Initialisation endpoint — called once on page load
# ---------------------------------------------------------------------------

@app.route("/api/init", methods=["GET"])
def init():
    """
    Called automatically when the page loads.
    Returns SVMs, cluster name, and Domino context.
    In DEMO_MODE, returns synthetic data with no ONTAP connection needed.
    """
    ctx = _domino_context()
    env_status = _env_status()

    if _is_demo():
        return jsonify({
            "ok": True,
            "cluster_name": DEMO_CLUSTER_NAME,
            "svms": DEMO_SVM_LIST,
            "volumes": DEMO_VOLUMES,
            "project_name": ctx["project_name"] or "Demo Project",
            "username": ctx["username"] or "demo-admin",
            "evtx_available": True,
            "demo_mode": True,
            "demo_reason": _demo_reason(),
            "demo_forced": _DEMO_FORCED,
            "demo_override": _DEMO_OVERRIDE,
            "env_status": env_status,
        })

    try:
        client       = _get_client()
        cluster_info = client.ping()
        svms         = client.list_svms()
        svm_names    = [s["name"] for s in svms]

        # Fetch ONTAP version for the status panel
        try:
            version_info = client.get_ontap_version()
            ontap_version = version_info.get("full", "unknown")
        except OntapError:
            ontap_version = "unknown"

        # Fetch volumes grouped by SVM
        all_volumes  = client.list_volumes()
        volumes_by_svm = {}
        for v in all_volumes:
            svm = v.get("svm", {}).get("name", "")
            if svm:
                volumes_by_svm.setdefault(svm, []).append(v["name"])

        return jsonify({
            "ok":             True,
            "cluster_name":   cluster_info.get("name", "Unknown"),
            "ontap_version":  ontap_version,
            "svms":           svm_names,
            "volumes":        volumes_by_svm,
            "project_name":   ctx["project_name"],
            "username":       ctx["username"],
            "evtx_available": EVTX_AVAILABLE,
            "demo_mode":      False,
            "env_status":     env_status,
        })
    except OntapError as exc:
        return jsonify({
            "ok": False,
            "error": str(exc),
            "env_status": env_status,
            "demo_mode": False,
        }), 400


# ---------------------------------------------------------------------------
# Preflight checks — validates ONTAP readiness per SVM
# ---------------------------------------------------------------------------

@app.route("/api/preflight", methods=["POST"])
def preflight():
    """
    Run prerequisite checks for a specific SVM (or all SVMs).
    Returns a checklist of pass/fail items so the admin can see what
    needs to be configured before querying.

    In DEMO_MODE, returns an all-pass checklist.
    """
    body = request.get_json(force=True)
    svm_name = body.get("svm_name", "")

    if _is_demo():
        return jsonify({"checks": _demo_preflight_checks(svm_name)})

    checks = []

    # 1. ONTAP version >= 9.11.1
    try:
        client = _get_client()
        ver = client.get_ontap_version()
        ver_str = ver["full"]
        gen, maj, minor = ver["generation"], ver["major"], ver["minor"]
        meets_version = (gen > 9) or (gen == 9 and maj > 11) or (gen == 9 and maj == 11 and minor >= 1)
        checks.append({
            "id": "ontap_version",
            "label": "ONTAP version >= 9.11.1",
            "status": "pass" if meets_version else "fail",
            "detail": f"Running ONTAP {ver_str}" if meets_version
                      else f"Running ONTAP {ver_str}. The audit log file REST API requires 9.11.1 or later.",
        })
    except OntapError as exc:
        checks.append({
            "id": "ontap_version",
            "label": "ONTAP version >= 9.11.1",
            "status": "error",
            "detail": f"Could not retrieve version: {exc}",
        })
        # Can't continue without a connection
        return jsonify({"checks": checks})

    # If checking a specific SVM, run SVM-level checks
    svms_to_check = []
    if svm_name and svm_name != "__all__":
        svms_to_check = [svm_name]
    elif svm_name == "__all__":
        try:
            svms_to_check = [s["name"] for s in client.list_svms()]
        except OntapError:
            svms_to_check = []

    for svm in svms_to_check:
        # 2. CIFS/SMB server — informational, not a hard requirement for NFS
        try:
            cifs = client.check_cifs_server(svm)
            if cifs:
                enabled = cifs.get("enabled", True)
                checks.append({
                    "id": f"cifs_server_{svm}",
                    "label": f"CIFS/SMB server on {svm}",
                    "status": "pass" if enabled else "warn",
                    "detail": f"CIFS server '{cifs.get('name', '?')}' configured"
                              + ("" if enabled else " but disabled"),
                })
            else:
                checks.append({
                    "id": f"cifs_server_{svm}",
                    "label": f"CIFS/SMB server on {svm}",
                    "status": "info",
                    "detail": "No CIFS server found — this SVM may be NFS-only. "
                              "NFS file access auditing still works without a CIFS server.",
                })
        except OntapError as exc:
            checks.append({
                "id": f"cifs_server_{svm}",
                "label": f"CIFS/SMB server on {svm}",
                "status": "info",
                "detail": f"Could not check CIFS status: {exc}. "
                          "This is normal for NFS-only SVMs.",
            })

        # 3. Auditing enabled + EVTX format
        try:
            svm_uuid = client.get_svm_uuid(svm)
            audit_cfg = client.get_audit_config(svm_uuid)
            audit_enabled = audit_cfg.get("enabled", False)
            log_format = audit_cfg.get("log", {}).get("format", audit_cfg.get("format", "evtx"))

            if not audit_enabled:
                checks.append({
                    "id": f"audit_enabled_{svm}",
                    "label": f"Auditing enabled on {svm}",
                    "status": "fail",
                    "detail": "Auditing is not enabled. Run: vserver audit enable "
                              f"-vserver {svm}",
                })
            elif log_format.lower() != "evtx":
                checks.append({
                    "id": f"audit_enabled_{svm}",
                    "label": f"Auditing enabled on {svm}",
                    "status": "warn",
                    "detail": f"Auditing is enabled but log format is '{log_format}', not 'evtx'. "
                              "This app requires EVTX format. Reconfigure with: "
                              f"vserver audit modify -vserver {svm} -format evtx",
                })
            else:
                dest = audit_cfg.get("log_path", audit_cfg.get("log", {}).get("path", ""))
                checks.append({
                    "id": f"audit_enabled_{svm}",
                    "label": f"Auditing enabled on {svm}",
                    "status": "pass",
                    "detail": f"Auditing enabled, EVTX format"
                              + (f", destination: {dest}" if dest else ""),
                })

            # 4. Audit log files exist
            if audit_enabled:
                try:
                    files = client.list_audit_log_files(svm_uuid)
                    if files:
                        checks.append({
                            "id": f"audit_files_{svm}",
                            "label": f"Audit log files on {svm}",
                            "status": "pass",
                            "detail": f"{len(files)} log file(s) available",
                        })
                    else:
                        checks.append({
                            "id": f"audit_files_{svm}",
                            "label": f"Audit log files on {svm}",
                            "status": "warn",
                            "detail": "No audit log files found yet. Files are created "
                                      "after the first audited file access event occurs.",
                        })
                except OntapError as exc:
                    error_str = str(exc)
                    if "404" in error_str:
                        checks.append({
                            "id": f"audit_files_{svm}",
                            "label": f"Audit log files on {svm}",
                            "status": "fail",
                            "detail": "The audit log files endpoint returned 404. "
                                      "This endpoint requires ONTAP 9.11.1 or later.",
                        })
                    else:
                        checks.append({
                            "id": f"audit_files_{svm}",
                            "label": f"Audit log files on {svm}",
                            "status": "error",
                            "detail": str(exc),
                        })
        except OntapError as exc:
            checks.append({
                "id": f"audit_enabled_{svm}",
                "label": f"Auditing enabled on {svm}",
                "status": "error",
                "detail": f"Could not read audit config: {exc}. "
                          "Auditing may not be configured on this SVM. Run: "
                          f"vserver audit create -vserver {svm} -destination <path> -format evtx",
            })

    return jsonify({"checks": checks})


def _demo_preflight_checks(svm_name: str) -> list[dict]:
    """Return an all-pass preflight checklist for demo mode."""
    checks = [{
        "id": "ontap_version",
        "label": "ONTAP version >= 9.11.1",
        "status": "pass",
        "detail": "Running ONTAP 9.14.1 (demo)",
    }]
    svms = [svm_name] if svm_name and svm_name != "__all__" else DEMO_SVM_LIST
    for svm in svms:
        checks.extend([
            {
                "id": f"cifs_server_{svm}",
                "label": f"CIFS/SMB server on {svm}",
                "status": "pass",
                "detail": f"CIFS server 'CORP-NAS' configured",
            },
            {
                "id": f"nfs_server_{svm}",
                "label": f"NFS on {svm}",
                "status": "pass",
                "detail": "NFS enabled — NFS file access events will be captured",
            },
            {
                "id": f"audit_enabled_{svm}",
                "label": f"Auditing enabled on {svm}",
                "status": "pass",
                "detail": "Auditing enabled, EVTX format, destination: /audit_log",
            },
            {
                "id": f"audit_files_{svm}",
                "label": f"Audit log files on {svm}",
                "status": "pass",
                "detail": "3 log file(s) available",
            },
        ])
    return checks


# ---------------------------------------------------------------------------
# Main query
# ---------------------------------------------------------------------------

@app.route("/api/query", methods=["POST"])
def query_events():
    """
    Query ONTAP audit logs for file access events (SMB and NFS).

    Accepts (from the simplified form — no credentials needed from user):
      svm_name          SVM to query (selected from dropdown)
      start_date        YYYY-MM-DD  (UTC)
      end_date          YYYY-MM-DD  (UTC)
      path_prefix       Optional path filter  e.g. /vol/finance/
    """
    body = request.get_json(force=True)

    missing = [f for f in ("svm_name", "start_date", "end_date") if not body.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    # Parse and validate dates first (applies to both demo and real mode)
    try:
        start_dt = datetime.fromisoformat(body["start_date"]).replace(tzinfo=timezone.utc)
        end_dt   = datetime.fromisoformat(body["end_date"]).replace(
                       hour=23, minute=59, second=59, tzinfo=timezone.utc)
    except ValueError as exc:
        return jsonify({"error": f"Invalid date: {exc}"}), 400

    if start_dt > end_dt:
        return jsonify({"error": "start_date must be before end_date"}), 400

    path_prefix   = body.get("path_prefix", "").strip()
    username_filt = body.get("username", "").strip()
    event_types   = body.get("event_types") or []  # list of event type strings
    result_filter = body.get("result_filter", "all").strip().lower()
    volume_filt   = body.get("volume", "").strip()
    max_files     = min(int(os.environ.get("ONTAP_MAX_FILES", 10)), 50)
    ctx           = _domino_context()

    # --- Demo mode: return synthetic events, no ONTAP or python-evtx needed ---
    if _is_demo():
        events = generate_demo_events(
            body["svm_name"], body["start_date"], body["end_date"],
            path_prefix, username_filt, event_types or None,
            result_filter, volume_filt,
        )
        svm_label = "All SVMs" if body["svm_name"] == "__all__" else body["svm_name"]
        return jsonify({
            "meta": _build_meta(
                ctx, svm_label, start_dt, end_dt,
                files_checked=3 if body["svm_name"] != "__all__" else 9,
                events_found=len(events), files_skipped=0,
            ),
            "events": events,
            "demo_mode": True,
        })

    # EVTX parsing is only needed for real ONTAP queries
    if not EVTX_AVAILABLE:
        return jsonify({
            "error": "python-evtx is not installed in this environment. "
                     "Add it to requirements.txt and redeploy."
        }), 500

    try:
        client = _get_client()
    except OntapError as exc:
        return jsonify({"error": str(exc)}), 500

    # Resolve which SVMs to query
    svm_name = body["svm_name"]
    if svm_name == "__all__":
        try:
            svms_to_query = [(s["name"], s["uuid"]) for s in client.list_svms()]
        except OntapError as exc:
            return jsonify({"error": f"Could not list SVMs: {exc}"}), 400
        svm_label = "All SVMs"
    else:
        try:
            svm_uuid = client.get_svm_uuid(svm_name)
            svms_to_query = [(svm_name, svm_uuid)]
        except OntapError as exc:
            return jsonify({"error": str(exc)}), 400
        svm_label = svm_name

    # EVTX parsing is only needed for real ONTAP queries
    if not EVTX_AVAILABLE:
        return jsonify({
            "error": "python-evtx is not installed in this environment. "
                     "Add it to requirements.txt and redeploy."
        }), 500

    all_events, parse_errors = [], []
    total_files_checked = 0
    total_files_skipped = 0

    for query_svm_name, query_svm_uuid in svms_to_query:
        # Confirm auditing is enabled and using EVTX format
        try:
            audit_cfg = client.get_audit_config(query_svm_uuid)
            if not audit_cfg.get("enabled", False):
                if len(svms_to_query) == 1:
                    return jsonify({
                        "error": f"Auditing is not enabled on SVM '{query_svm_name}'. "
                                 "Ask your administrator to enable it: "
                                 f"vserver audit enable -vserver {query_svm_name}"
                    }), 400
                continue  # skip this SVM in multi-SVM mode
            log_format = audit_cfg.get("log", {}).get("format", audit_cfg.get("format", "evtx"))
            if log_format.lower() != "evtx":
                if len(svms_to_query) == 1:
                    return jsonify({
                        "error": f"Audit log format on SVM '{query_svm_name}' is '{log_format}', "
                                 "but this app requires EVTX format. Ask your administrator to "
                                 f"reconfigure: vserver audit modify -vserver {query_svm_name} -format evtx"
                    }), 400
                continue
        except OntapError as exc:
            if len(svms_to_query) == 1:
                return jsonify({"error": f"Could not read audit config: {exc}"}), 400
            continue  # skip this SVM in multi-SVM mode

        # List EVTX log files
        try:
            log_files = client.list_audit_log_files(query_svm_uuid)
        except OntapError as exc:
            if len(svms_to_query) == 1:
                return jsonify({"error": f"Failed to list audit log files: {exc}"}), 400
            continue

        if not log_files:
            continue

        relevant = _filter_files_by_time(log_files, start_dt, end_dt)
        to_fetch = relevant[:max_files]
        total_files_skipped += len(relevant) - len(to_fetch)
        total_files_checked += len(to_fetch)

        # Download and parse
        for f in to_fetch:
            try:
                raw  = client.download_audit_log_file(query_svm_uuid, f["name"])
                evts = parse_smb_events(raw, path_prefix, start_dt, end_dt)
                for ev in evts:
                    ev["svm_name"] = query_svm_name
                all_events.extend(evts)
            except Exception as exc:
                parse_errors.append(f"{f['name']}: {exc}")

    if not total_files_checked and not all_events:
        return jsonify({
            "meta": _build_meta(ctx, svm_label, start_dt, end_dt, 0, 0),
            "events": [],
            "warning": "No audit log files found. Auditing may not be configured on the selected SVM(s).",
        })

    all_events.sort(key=lambda e: e["timestamp"], reverse=True)
    serialized = [_serialize(e) for e in all_events]

    response = {
        "meta": _build_meta(
            ctx, svm_label, start_dt, end_dt,
            files_checked=total_files_checked,
            events_found=len(serialized),
            files_skipped=total_files_skipped,
        ),
        "events": serialized,
    }
    if parse_errors:
        response["parse_errors"] = parse_errors
    return jsonify(response)


# ---------------------------------------------------------------------------
# Live sessions
# ---------------------------------------------------------------------------

@app.route("/api/live_sessions", methods=["POST"])
def live_sessions():
    body = request.get_json(force=True)
    if not body.get("svm_name"):
        return jsonify({"error": "svm_name is required"}), 400

    if _is_demo():
        return jsonify({"sessions": [
            {"user": "j.smith",    "client_ip": "10.0.1.45",  "svm": {"name": body["svm_name"]}, "connected_duration": "PT2H14M", "open_files": 3, "protocol": "SMB"},
            {"user": "m.johnson",  "client_ip": "10.0.1.112", "svm": {"name": body["svm_name"]}, "connected_duration": "PT47M",   "open_files": 1, "protocol": "SMB"},
            {"user": "domino-svc", "client_ip": "10.0.2.50",  "svm": {"name": body["svm_name"]}, "connected_duration": "P1DT3H",  "open_files": 2, "protocol": "NFS"},
            {"user": "svc-domino", "client_ip": "10.0.2.10",  "svm": {"name": body["svm_name"]}, "connected_duration": "P1DT3H",  "open_files": 0, "protocol": "SMB"},
        ], "demo_mode": True})

    try:
        client   = _get_client()
        sessions = client.list_cifs_sessions(body["svm_name"])
        # Tag sessions as SMB since they come from the CIFS sessions endpoint
        for s in sessions:
            s["protocol"] = "SMB"
        return jsonify({"sessions": sessions, "note": "Only SMB/CIFS sessions are shown. NFS does not have a comparable live sessions API."})
    except OntapError as exc:
        # This is expected for NFS-only SVMs — return gracefully
        error_str = str(exc)
        if "404" in error_str or "not found" in error_str.lower() or "not supported" in error_str.lower():
            return jsonify({
                "sessions": [],
                "note": "No CIFS/SMB server configured on this SVM. "
                        "Live sessions are only available for SMB connections. "
                        "NFS-mounted volumes do not expose a live sessions API."
            })
        return jsonify({"error": str(exc)}), 400


# ---------------------------------------------------------------------------
# Hidden demo override toggle — failsafe for customer demos
# ---------------------------------------------------------------------------

@app.route("/api/demo-toggle", methods=["POST"])
def demo_toggle():
    """Toggle the runtime demo override. Not linked in the UI — activated
    by triple-clicking the header logo."""
    global _DEMO_OVERRIDE
    _DEMO_OVERRIDE = not _DEMO_OVERRIDE
    return jsonify({"demo_override": _DEMO_OVERRIDE})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _filter_files_by_time(log_files, start_dt, end_dt):
    result = []
    for f in log_files:
        mod_str = f.get("modified_time", "")
        try:
            mod_dt = datetime.fromisoformat(mod_str.replace("Z", "+00:00"))
            if mod_dt >= start_dt:
                result.append(f)
        except (ValueError, AttributeError):
            result.append(f)  # include if unparseable to be safe
    return result


def _serialize(event: dict) -> dict:
    out = {k: v for k, v in event.items() if k != "raw_data"}
    if isinstance(out.get("timestamp"), datetime):
        out["timestamp"] = out["timestamp"].isoformat()
    return out


def _build_meta(ctx, svm_name, start_dt, end_dt, files_checked,
                events_found, files_skipped=0) -> dict:
    return {
        "project_name":             ctx.get("project_name", ""),
        "queried_by":               ctx.get("username", ""),
        "svm_name":                 svm_name,
        "query_start":              start_dt.strftime("%Y-%m-%d"),
        "query_end":                end_dt.strftime("%Y-%m-%d"),
        "files_checked":            files_checked,
        "files_skipped_due_to_cap": files_skipped,
        "events_found":             events_found,
        "generated_at":             datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "protocol_filter":          "SMB/CIFS and NFS",
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8888))
    app.run(host="0.0.0.0", port=port, debug=False)
