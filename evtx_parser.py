"""
EVTX audit log parser for NetApp ONTAP SMB/CIFS file access events.

ONTAP writes Windows-format EVTX files for file auditing.  This module
parses those files and returns only events that represent SMB/CIFS file
access, filtering by event ID and (optionally) by path prefix.

Relevant Windows Security event IDs produced by ONTAP:
  4656 – A handle to an object was requested           (file open attempt)
  4663 – An attempt was made to access an object       (actual read/write/delete)
  4660 – An object was deleted
  4670 – Permissions on an object were changed
  5140 – A network share object was accessed           (share-level)
  5145 – A network share object was checked            (share access check)

ONTAP does NOT set ProcessName the way Windows does; instead it records the
SMB client's IP address and the user's domain account.  We surface those fields
and map the AccessMask to human-readable operation types.
"""

import io
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


# Event IDs we care about for SMB file-level activity
SMB_EVENT_IDS = {4656, 4660, 4663, 4670, 5140, 5145}

# Human-readable labels for common ONTAP SMB access masks / access list values
ACCESS_MAP = {
    "%%4416": "ReadData",
    "%%4417": "WriteData",
    "%%4418": "AppendData",
    "%%4419": "ReadEA",
    "%%4420": "WriteEA",
    "%%4421": "Execute",
    "%%4423": "ReadAttributes",
    "%%4424": "WriteAttributes",
    "%%1537": "Delete",
    "%%1538": "ReadControl",
    "%%1539": "WriteDACL",
    "%%1540": "WriteOwner",
    "%%1541": "Synchronize",
    "%%1542": "AccessSysSec",
}

EVENT_ID_LABELS = {
    4656: "Handle Requested",
    4660: "Object Deleted",
    4663: "Object Accessed",
    4670: "Permissions Changed",
    5140: "Share Accessed",
    5145: "Share Access Checked",
}


def parse_smb_events(
    evtx_bytes: bytes,
    path_prefix: str = "",
    start_dt: datetime | None = None,
    end_dt: datetime | None = None,
) -> list[dict]:
    """
    Parse raw EVTX bytes and return a list of SMB event dicts.

    Each dict contains:
        event_id, event_type, timestamp, user, domain, client_ip,
        object_path, access_operations, result, raw_xml (truncated)

    Args:
        evtx_bytes:   Raw bytes of the .evtx file downloaded from ONTAP.
        path_prefix:  Optional file path prefix to filter on (e.g. /vol/data/).
        start_dt:     Inclusive lower bound for event timestamp (UTC).
        end_dt:       Inclusive upper bound for event timestamp (UTC).
    """
    if not EVTX_AVAILABLE:
        raise RuntimeError(
            "python-evtx is not installed. Run: pip install python-evtx"
        )

    events = []
    fh = io.BytesIO(evtx_bytes)

    with evtx.Evtx(fh) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                event = _parse_record_xml(xml_str)
            except Exception:
                continue

            if event is None:
                continue

            # --- Filter: only SMB-relevant event IDs ---
            if event["event_id"] not in SMB_EVENT_IDS:
                continue

            # --- Filter: time range ---
            ts = event["timestamp"]
            if start_dt and ts < start_dt:
                continue
            if end_dt and ts > end_dt:
                continue

            # --- Filter: optional path prefix ---
            if path_prefix:
                obj_path = event.get("object_path", "")
                if not obj_path.lower().startswith(path_prefix.lower()):
                    continue

            events.append(event)

    # Sort newest-first
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events


def _parse_record_xml(xml_str: str) -> dict | None:
    """Parse a single EVTX record XML string into a structured dict."""
    ns = {
        "evt": "http://schemas.microsoft.com/win/2004/08/events/event",
        "": "http://schemas.microsoft.com/win/2004/08/events/event",
    }

    root = ET.fromstring(xml_str)

    # System section
    sys_el = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}System")
    if sys_el is None:
        return None

    event_id_el = sys_el.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
    time_el = sys_el.find("{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")

    if event_id_el is None or time_el is None:
        return None

    try:
        event_id = int(event_id_el.text)
    except (TypeError, ValueError):
        return None

    # Parse timestamp — ONTAP stores UTC in SystemTime attribute
    system_time = time_el.get("SystemTime", "")
    try:
        ts = datetime.fromisoformat(system_time.replace("Z", "+00:00"))
    except ValueError:
        ts = datetime.now(timezone.utc)

    # EventData section — ONTAP populates this as a flat list of Named Data elements
    event_data_el = root.find(
        ".//{http://schemas.microsoft.com/win/2004/08/events/event}EventData"
    )

    data = {}
    if event_data_el is not None:
        for item in event_data_el:
            name = item.get("Name", "")
            value = (item.text or "").strip()
            if name:
                data[name] = value

    # Map ONTAP EVTX fields to our schema
    user = data.get("SubjectUserName", data.get("SubjectUser", "-"))
    domain = data.get("SubjectDomainName", data.get("SubjectDomain", "-"))
    client_ip = data.get("IpAddress", data.get("ClientIpAddress", "-"))
    object_path = data.get("ObjectName", data.get("HandleId", "-"))
    access_list_raw = data.get("AccessList", data.get("AccessMask", ""))
    result_code = data.get("Status", data.get("SubStatus", "0x0"))

    # Decode access operations
    access_ops = _decode_access_list(access_list_raw)

    # Determine result
    result = "Success" if result_code in ("0x0", "0", "", "-", "%%1793") else f"Failure ({result_code})"

    return {
        "event_id": event_id,
        "event_type": EVENT_ID_LABELS.get(event_id, f"Event {event_id}"),
        "timestamp": ts,
        "timestamp_str": ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "user": user,
        "domain": domain,
        "client_ip": client_ip,
        "object_path": object_path,
        "access_operations": access_ops,
        "result": result,
        "share_name": data.get("ShareName", data.get("ShareLocalPath", "-")),
        "raw_data": data,  # keep full dict for advanced debug view
    }


def _decode_access_list(raw: str) -> str:
    """
    Convert ONTAP access list tokens (e.g. '%%4416\n\t\t\t\t%%4417') to
    readable operation labels (e.g. 'ReadData, WriteData').
    """
    if not raw:
        return "-"
    tokens = [t.strip() for t in raw.replace("\t", " ").split() if t.strip()]
    labels = [ACCESS_MAP.get(t, t) for t in tokens]
    return ", ".join(labels) if labels else raw
