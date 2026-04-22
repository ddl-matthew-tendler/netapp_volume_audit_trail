"""
Mock NetApp ONTAP REST API Server
==================================
A lightweight Flask app that impersonates the ONTAP REST API endpoints
used by ontap_client.py.  Run this alongside the main app to test the full
HTTP request/response stack without a real NetApp cluster.

Usage:
  # Terminal 1 — start the mock ONTAP server on port 8080
  python mock_ontap_server.py

  # Terminal 2 — start the real app pointed at the mock server
  ONTAP_CLUSTER_IP=localhost:8080 \\
  ONTAP_USERNAME=admin \\
  ONTAP_PASSWORD=password \\
  ONTAP_VERIFY_SSL=false \\
  python app.py

What it simulates:
  GET  /api/cluster                                           → cluster identity
  GET  /api/svm/svms                                         → SVM list
  GET  /api/protocols/audit/{svm_uuid}                       → audit config
  GET  /api/protocols/audit/{svm_uuid}/log/files             → EVTX file list
  GET  /api/protocols/audit/{svm_uuid}/log/files/{name}      → EVTX download
  GET  /api/protocols/cifs/sessions                          → live SMB sessions

The EVTX "files" returned are pre-built minimal valid EVTX binaries containing
realistic SMB audit events so the entire parse pipeline is exercised.
"""

import io
import struct
import time
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, Response

app = Flask(__name__)

# -----------------------------------------------------------------------
# Fake cluster / SVM data
# -----------------------------------------------------------------------

CLUSTER = {
    "name": "mock-ontap-cluster-01",
    "uuid": "aaaabbbb-0000-0000-0000-000000000001",
    "version": {"full": "NetApp Release 9.13.1: mock"},
}

SVMS = [
    {"name": "svm-corp-data-01", "uuid": "svm-uuid-0001", "type": "data"},
    {"name": "svm-finance-prod", "uuid": "svm-uuid-0002", "type": "data"},
    {"name": "svm-hr-secure",    "uuid": "svm-uuid-0003", "type": "data"},
]

# Audit log files — two files per SVM covering different time windows
def _log_files(svm_uuid: str) -> list[dict]:
    now  = datetime.now(timezone.utc)
    day1 = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    day5 = (now - timedelta(days=5)).isoformat().replace("+00:00", "Z")
    return [
        {"name": f"audit_{svm_uuid}_recent.evtx",  "modified_time": day1, "size": 4096},
        {"name": f"audit_{svm_uuid}_older.evtx",   "modified_time": day5, "size": 4096},
    ]

CIFS_SESSIONS = [
    {"user": "CORP\\j.smith",    "client_ip": "10.0.1.45",  "svm": {"name": "svm-corp-data-01"}, "connected_duration": "PT1H22M", "open_files": 2},
    {"user": "CORP\\m.johnson",  "client_ip": "10.0.1.112", "svm": {"name": "svm-corp-data-01"}, "connected_duration": "PT8M",    "open_files": 1},
]

# -----------------------------------------------------------------------
# Basic auth check
# -----------------------------------------------------------------------

def _check_auth() -> bool:
    auth = request.authorization
    return auth and auth.username == "admin" and auth.password == "password"

def _unauth():
    return jsonify({"error": {"message": "Unauthorized"}}), 401

# -----------------------------------------------------------------------
# ONTAP REST endpoints
# -----------------------------------------------------------------------

@app.route("/api/cluster", methods=["GET"])
def cluster():
    if not _check_auth(): return _unauth()
    return jsonify(CLUSTER)


@app.route("/api/svm/svms", methods=["GET"])
def svm_svms():
    if not _check_auth(): return _unauth()
    name_filter = request.args.get("name")
    type_filter = request.args.get("type")
    records = SVMS
    if name_filter:
        records = [s for s in records if s["name"] == name_filter]
    if type_filter:
        records = [s for s in records if s["type"] == type_filter]
    return jsonify({"records": records, "num_records": len(records)})


@app.route("/api/protocols/audit/<svm_uuid>", methods=["GET"])
def audit_config(svm_uuid):
    if not _check_auth(): return _unauth()
    # Confirm the SVM UUID is one we know
    known = {s["uuid"] for s in SVMS}
    if svm_uuid not in known:
        return jsonify({"error": {"message": f"SVM {svm_uuid} not found"}}), 404
    return jsonify({
        "svm": {"uuid": svm_uuid},
        "enabled": True,
        "events": [{"file_operations": True, "cifs_logon_logoff": True}],
        "log_path": f"/vol/audit_log_{svm_uuid}",
        "rotate_size": "100MB",
    })


@app.route("/api/protocols/audit/<svm_uuid>/log/files", methods=["GET"])
def audit_log_files(svm_uuid):
    if not _check_auth(): return _unauth()
    files = _log_files(svm_uuid)
    return jsonify({"records": files, "num_records": len(files)})


@app.route("/api/protocols/audit/<svm_uuid>/log/files/<path:file_name>", methods=["GET"])
def download_audit_log(svm_uuid, file_name):
    """
    Return a minimal but structurally valid EVTX binary containing
    synthetic SMB audit events for the requested SVM.
    """
    if not _check_auth(): return _unauth()
    action = request.args.get("action", "")
    if action != "download":
        return jsonify({"error": {"message": "Use ?action=download"}}), 400

    evtx_bytes = _build_evtx(svm_uuid, file_name)
    return Response(
        evtx_bytes,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@app.route("/api/protocols/cifs/sessions", methods=["GET"])
def cifs_sessions():
    if not _check_auth(): return _unauth()
    svm_filter = request.args.get("svm.name")
    sessions   = CIFS_SESSIONS
    if svm_filter:
        sessions = [s for s in sessions if s["svm"]["name"] == svm_filter]
    return jsonify({"records": sessions, "num_records": len(sessions)})


# -----------------------------------------------------------------------
# Minimal EVTX builder
# -----------------------------------------------------------------------
# EVTX format reference: https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
#
# We build a structurally valid EVTX file with real event XML records so
# that python-evtx can parse it and evtx_parser.py can extract SMB events.
#
# Structure:
#   File header (4096 bytes)
#   Chunk header (512 bytes) + event records
#   (We write one chunk with all events)

EVTX_MAGIC      = b"ElfFile\x00"
CHUNK_MAGIC     = b"ElfChnk\x00"
RECORD_MAGIC    = b"\x2a\x2a\x00\x00"  # ** record magic


def _build_evtx(svm_uuid: str, file_name: str) -> bytes:
    """
    Build a minimal EVTX binary with synthetic SMB events.
    The XML follows the Windows Security Event schema that python-evtx
    and our evtx_parser expect.
    """
    events_xml = _synthetic_event_xml_list(svm_uuid)
    records    = [_encode_record(i + 1, xml) for i, xml in enumerate(events_xml)]
    chunk      = _build_chunk(records)
    header     = _build_file_header(len(records))
    # Pad header to 4096 bytes
    header_padded = header + b"\x00" * (4096 - len(header))
    return header_padded + chunk


def _synthetic_event_xml_list(svm_uuid: str) -> list[str]:
    """Generate XML strings for realistic SMB audit events."""
    now      = datetime.now(timezone.utc)
    ns       = "http://schemas.microsoft.com/win/2004/08/events/event"
    events   = []

    scenarios = [
        # (event_id, user, domain, ip, path, access_list, status)
        (4663, "j.smith",   "CORP", "10.0.1.45",  f"/vol/{svm_uuid}/finance/Q4_Budget.xlsx",    "%%4416\n%%4423", "0x0"),
        (4663, "m.johnson", "CORP", "10.0.1.112", f"/vol/{svm_uuid}/hr/salaries.xlsx",           "%%4416\n%%4423", "0x0"),
        (4660, "j.smith",   "CORP", "10.0.1.45",  f"/vol/{svm_uuid}/finance/temp/scratch.xlsx", "%%1537",         "0x0"),
        (4656, "d.chen",    "CORP", "10.0.1.77",  f"/vol/{svm_uuid}/projects/results.docx",     "%%4416",         "0x0"),
        (5140, "l.garcia",  "CORP", "10.0.1.55",  f"/vol/{svm_uuid}/projects",                  "%%4416",         "0x0"),
        (4663, "b.turner",  "CORP", "10.0.1.34",  f"/vol/{svm_uuid}/hr/exec_comp.xlsx",         "%%4416",         "0xC0000022"),
        (4670, "svc-domino","CORP", "10.0.2.10",  f"/vol/{svm_uuid}/projects/",                 "%%1539",         "0x0"),
        (5145, "r.patel",   "CORP", "10.0.1.201", f"/vol/{svm_uuid}/finance",                   "%%4416",         "0x0"),
    ]

    for i, (eid, user, domain, ip, path, access, status) in enumerate(scenarios):
        ts = (now - timedelta(hours=i * 3)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        xml = f"""<Event xmlns="{ns}">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>{eid}</EventID>
    <TimeCreated SystemTime="{ts}"/>
    <Channel>Security</Channel>
    <Computer>ONTAP-SVM-{svm_uuid[:8]}</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">{user}</Data>
    <Data Name="SubjectDomainName">{domain}</Data>
    <Data Name="IpAddress">{ip}</Data>
    <Data Name="ObjectName">{path}</Data>
    <Data Name="ShareName">\\\\CORP-NAS\\share</Data>
    <Data Name="AccessList">{access}</Data>
    <Data Name="Status">{status}</Data>
  </EventData>
</Event>"""
        events.append(xml)

    return events


def _encode_record(record_id: int, xml: str) -> bytes:
    """
    Encode a single event XML as an EVTX record (simplified — enough for
    python-evtx to parse using its XML path, which reads the raw XML).
    """
    xml_bytes = xml.encode("utf-8") + b"\x00"  # null-terminated
    # Record structure: magic(4) + size(4) + record_id(8) + timestamp(8) + xml
    ts_filetime = _dt_to_filetime(datetime.now(timezone.utc))
    header = struct.pack(
        "<4sIQQ",
        RECORD_MAGIC,
        28 + len(xml_bytes),   # total record size
        record_id,
        ts_filetime,
    )
    total_size = struct.pack("<I", 28 + len(xml_bytes))
    return header + xml_bytes + total_size


def _build_chunk(records: list[bytes]) -> bytes:
    """Build a minimal EVTX chunk containing all records."""
    records_bytes = b"".join(records)
    # Chunk header is 512 bytes; we write minimal fields
    first_record_id = 1
    last_record_id  = len(records)
    header = struct.pack(
        "<8sQQQQIII",
        CHUNK_MAGIC,
        first_record_id,  # first_event_record_number
        last_record_id,   # last_event_record_number
        first_record_id,  # first_event_record_identifier
        last_record_id,   # last_event_record_identifier
        512,              # header_size
        512 + len(records_bytes),  # last_event_record_offset
        0,                # free_space_offset (unused)
    )
    header_padded = header + b"\x00" * (512 - len(header))
    return header_padded + records_bytes


def _build_file_header(num_chunks: int) -> bytes:
    """Build a minimal EVTX file header (76 bytes, padded to 4096 by caller)."""
    return struct.pack(
        "<8sQQQHHII",
        EVTX_MAGIC,
        0,          # first_chunk_number
        0,          # last_chunk_number
        0,          # next_record_identifier
        128,        # header_block_size
        num_chunks, # number_of_chunks
        1,          # minor_format_version
        3,          # major_format_version (3.1 = EVTX)
    )


def _dt_to_filetime(dt: datetime) -> int:
    """Convert a Python datetime to Windows FILETIME (100ns intervals since 1601-01-01)."""
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((dt - epoch).total_seconds() * 10_000_000)


# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Mock ONTAP REST API Server")
    print("Listening on http://localhost:8080")
    print()
    print("To test against this server, set:")
    print("  ONTAP_CLUSTER_IP=localhost:8080")
    print("  ONTAP_USERNAME=admin")
    print("  ONTAP_PASSWORD=password")
    print("  ONTAP_VERIFY_SSL=false")
    print("=" * 60)
    app.run(host="0.0.0.0", port=8080, debug=True)
