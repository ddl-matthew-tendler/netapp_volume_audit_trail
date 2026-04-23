"""
Domino NetApp SMB Audit Viewer
==============================
A Domino App for administrators to query NetApp ONTAP audit logs for SMB/CIFS
file-access events.  No data is stored in Domino — results are pulled from
ONTAP on demand and displayed in the browser only.

Required environment variables (set once by IT admin when publishing the app):
  ONTAP_CLUSTER_IP   Cluster management IP or hostname  e.g. "192.168.1.10"
  ONTAP_USERNAME     ONTAP account with audit read access e.g. "domino-readonly"
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
DEMO_MODE = (
    os.environ.get("ONTAP_DEMO_MODE", "false").lower() == "true"
    or not _ONTAP_CONFIGURED
)

app = Flask(__name__)


def _get_client() -> OntapClient:
    """Build an OntapClient from environment variables only — no user input needed."""
    cluster_ip = os.environ.get("ONTAP_CLUSTER_IP", "").strip()
    username   = os.environ.get("ONTAP_USERNAME", "").strip()
    password   = os.environ.get("ONTAP_PASSWORD", "").strip()
    verify_ssl = os.environ.get("ONTAP_VERIFY_SSL", "false").lower() == "true"

    if not cluster_ip or not username or not password:
        raise OntapError(
            "ONTAP connection is not configured.  Ask your Domino administrator to set "
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
        demo_mode=DEMO_MODE,
        ontap_configured=_ONTAP_CONFIGURED,
        evtx_available=(EVTX_AVAILABLE or DEMO_MODE),
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

    if DEMO_MODE:
        return jsonify({
            "ok": True,
            "cluster_name": DEMO_CLUSTER_NAME,
            "svms": DEMO_SVM_LIST,
            "volumes": DEMO_VOLUMES,
            "project_name": ctx["project_name"] or "Demo Project",
            "username": ctx["username"] or "demo-admin",
            "evtx_available": True,
            "demo_mode": True,
        })

    try:
        client       = _get_client()
        cluster_info = client.ping()
        svms         = client.list_svms()
        svm_names    = [s["name"] for s in svms]

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
            "svms":           svm_names,
            "volumes":        volumes_by_svm,
            "project_name":   ctx["project_name"],
            "username":       ctx["username"],
            "evtx_available": EVTX_AVAILABLE,
            "demo_mode":      False,
        })
    except OntapError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


# ---------------------------------------------------------------------------
# Main query
# ---------------------------------------------------------------------------

@app.route("/api/query", methods=["POST"])
def query_events():
    """
    Query ONTAP audit logs for SMB events.

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
    if DEMO_MODE:
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

    # Resolve SVM UUID
    try:
        svm_uuid = client.get_svm_uuid(body["svm_name"])
    except OntapError as exc:
        return jsonify({"error": str(exc)}), 400

    # Confirm auditing is enabled
    try:
        audit_cfg = client.get_audit_config(svm_uuid)
        if not audit_cfg.get("enabled", False):
            return jsonify({
                "error": f"Auditing is not enabled on SVM '{body['svm_name']}'. "
                         "Ask your NetApp administrator to enable it: "
                         "vserver audit enable -vserver <svm>"
            }), 400
    except OntapError as exc:
        return jsonify({"error": f"Could not read audit config: {exc}"}), 400

    # List EVTX log files
    try:
        log_files = client.list_audit_log_files(svm_uuid)
    except OntapError as exc:
        return jsonify({"error": f"Failed to list audit log files: {exc}"}), 400

    if not log_files:
        return jsonify({
            "meta": _build_meta(ctx, body["svm_name"], start_dt, end_dt, 0, 0),
            "events": [],
            "warning": "No audit log files found for this SVM.",
        })

    relevant   = _filter_files_by_time(log_files, start_dt, end_dt)
    to_fetch   = relevant[:max_files]
    skipped    = len(relevant) - len(to_fetch)

    if not to_fetch:
        return jsonify({
            "meta": _build_meta(ctx, body["svm_name"], start_dt, end_dt, 0, 0),
            "events": [],
            "warning": "No audit log files found within the requested time window.",
        })

    # Download and parse
    all_events, parse_errors = [], []
    for f in to_fetch:
        try:
            raw   = client.download_audit_log_file(svm_uuid, f["name"])
            evts  = parse_smb_events(raw, path_prefix, start_dt, end_dt)
            all_events.extend(evts)
        except Exception as exc:
            parse_errors.append(f"{f['name']}: {exc}")

    all_events.sort(key=lambda e: e["timestamp"], reverse=True)
    serialized = [_serialize(e) for e in all_events]

    response = {
        "meta": _build_meta(
            ctx, body["svm_name"], start_dt, end_dt,
            files_checked=len(to_fetch),
            events_found=len(serialized),
            files_skipped=skipped,
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

    if DEMO_MODE:
        return jsonify({"sessions": [
            {"user": "j.smith",    "client_ip": "10.0.1.45",  "svm": {"name": body["svm_name"]}, "connected_duration": "PT2H14M", "open_files": 3},
            {"user": "m.johnson",  "client_ip": "10.0.1.112", "svm": {"name": body["svm_name"]}, "connected_duration": "PT47M",   "open_files": 1},
            {"user": "svc-domino", "client_ip": "10.0.2.10",  "svm": {"name": body["svm_name"]}, "connected_duration": "P1DT3H",  "open_files": 0},
        ], "demo_mode": True})

    try:
        client   = _get_client()
        sessions = client.list_cifs_sessions(body["svm_name"])
        return jsonify({"sessions": sessions})
    except OntapError as exc:
        return jsonify({"error": str(exc)}), 400


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
        "protocol_filter":          "SMB/CIFS only",
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8888))
    app.run(host="0.0.0.0", port=port, debug=False)
