"""
Synthetic file access audit events for Demo Mode and testing.

Includes both SMB/CIFS and NFS scenarios:
  - Finance users opening Excel files via SMB mapped drive
  - NFS clients accessing data science volumes
  - Deletion and permission change events
  - Failed access attempts on both protocols

Activated by setting ONTAP_DEMO_MODE=true in the app environment.
"""

from datetime import datetime, timedelta, timezone


def generate_demo_events(svm_name: str, start_date: str, end_date: str,
                          path_prefix: str = "", username: str = "",
                          event_types: list[str] | None = None,
                          result_filter: str = "all",
                          volume: str = "") -> list[dict]:
    """
    Return a list of realistic-looking file access audit events.
    Timestamps are spread across the requested date range.
    """
    # If "All SVMs" selected, generate events for each SVM and combine
    if svm_name == "__all__":
        combined = []
        for svm in DEMO_SVM_LIST:
            combined.extend(generate_demo_events(
                svm, start_date, end_date, path_prefix,
                username, event_types, result_filter, volume,
            ))
        combined.sort(key=lambda e: e["timestamp"], reverse=True)
        return combined

    try:
        start = datetime.fromisoformat(start_date).replace(tzinfo=timezone.utc)
        end   = datetime.fromisoformat(end_date).replace(
                    hour=23, minute=59, second=59, tzinfo=timezone.utc)
    except ValueError:
        start = datetime.now(timezone.utc) - timedelta(days=7)
        end   = datetime.now(timezone.utc)

    span_seconds = max(int((end - start).total_seconds()), 1)

    # Seed events — realistic SMB/CIFS and NFS scenarios
    raw_events = [
        # --- SMB events ---
        {
            "offset_pct": 0.95,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "j.smith", "domain": "CORP",
            "client_ip": "10.0.1.45", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/finance/reports/Q4_2025_Budget.xlsx",
            "share_name": "\\\\CORP-NAS\\Finance",
            "access_operations": "ReadData, ReadAttributes",
            "result": "Success",
        },
        {
            "offset_pct": 0.91,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "j.smith", "domain": "CORP",
            "client_ip": "10.0.1.45", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/finance/reports/Q4_2025_Budget.xlsx",
            "share_name": "\\\\CORP-NAS\\Finance",
            "access_operations": "WriteData, WriteAttributes",
            "result": "Success",
        },
        {
            "offset_pct": 0.88,
            "event_id": 5140, "event_type": "Share Accessed",
            "user": "m.johnson", "domain": "CORP",
            "client_ip": "10.0.1.112", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/hr",
            "share_name": "\\\\CORP-NAS\\HR",
            "access_operations": "ReadData",
            "result": "Success",
        },
        {
            "offset_pct": 0.85,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "m.johnson", "domain": "CORP",
            "client_ip": "10.0.1.112", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/hr/compensation/salary_bands_2026.xlsx",
            "share_name": "\\\\CORP-NAS\\HR",
            "access_operations": "ReadData, ReadAttributes",
            "result": "Success",
        },
        # --- NFS events ---
        {
            "offset_pct": 0.83,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "domino-svc", "domain": "-",
            "client_ip": "10.0.2.50", "protocol": "NFS",
            "object_path": f"/vol/{svm_name}/projects/ml_training/dataset_v3.parquet",
            "share_name": "-",
            "access_operations": "ReadData",
            "result": "Success",
        },
        {
            "offset_pct": 0.80,
            "event_id": 4656, "event_type": "Handle Requested",
            "user": "d.chen", "domain": "CORP",
            "client_ip": "10.0.1.77", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/projects/domino_ml/model_results.docx",
            "share_name": "\\\\CORP-NAS\\Projects",
            "access_operations": "ReadData",
            "result": "Success",
        },
        {
            "offset_pct": 0.78,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "ubuntu", "domain": "-",
            "client_ip": "10.0.2.51", "protocol": "NFS",
            "object_path": f"/vol/{svm_name}/projects/ml_training/checkpoints/epoch_50.pt",
            "share_name": "-",
            "access_operations": "WriteData, WriteAttributes",
            "result": "Success",
        },
        {
            "offset_pct": 0.75,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "d.chen", "domain": "CORP",
            "client_ip": "10.0.1.77", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/projects/domino_ml/model_results.docx",
            "share_name": "\\\\CORP-NAS\\Projects",
            "access_operations": "ReadData, ReadAttributes",
            "result": "Success",
        },
        {
            "offset_pct": 0.72,
            "event_id": 4656, "event_type": "Handle Requested",
            "user": "domino-svc", "domain": "-",
            "client_ip": "10.0.2.50", "protocol": "NFS",
            "object_path": f"/vol/{svm_name}/projects/experiment_logs/run_2025-12-01.json",
            "share_name": "-",
            "access_operations": "ReadData, WriteData",
            "result": "Success",
        },
        {
            "offset_pct": 0.70,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "r.patel", "domain": "CORP",
            "client_ip": "10.0.1.201", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/finance/raw_data/transactions_nov.csv",
            "share_name": "\\\\CORP-NAS\\Finance",
            "access_operations": "ReadData",
            "result": "Success",
        },
        {
            "offset_pct": 0.65,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "a.nguyen", "domain": "CORP",
            "client_ip": "10.0.1.88", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/finance/reports/Q3_2025_Budget.xlsx",
            "share_name": "\\\\CORP-NAS\\Finance",
            "access_operations": "ReadData, ReadAttributes",
            "result": "Success",
        },
        {
            # Failed access — permission denied (SMB)
            "offset_pct": 0.60,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "b.turner", "domain": "CORP",
            "client_ip": "10.0.1.34", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/hr/compensation/salary_bands_2026.xlsx",
            "share_name": "\\\\CORP-NAS\\HR",
            "access_operations": "ReadData",
            "result": "Failure (0xC0000022)",  # STATUS_ACCESS_DENIED
        },
        {
            # Failed access — permission denied (NFS)
            "offset_pct": 0.58,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "nobody", "domain": "-",
            "client_ip": "10.0.3.99", "protocol": "NFS",
            "object_path": f"/vol/{svm_name}/projects/ml_training/private/credentials.yaml",
            "share_name": "-",
            "access_operations": "ReadData",
            "result": "Failure (0xC0000022)",
        },
        {
            "offset_pct": 0.55,
            "event_id": 4670, "event_type": "Permissions Changed",
            "user": "svc-domino", "domain": "CORP",
            "client_ip": "10.0.2.10", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/projects/domino_ml/",
            "share_name": "\\\\CORP-NAS\\Projects",
            "access_operations": "WriteDACL",
            "result": "Success",
        },
        {
            "offset_pct": 0.52,
            "event_id": 4670, "event_type": "Permissions Changed",
            "user": "root", "domain": "-",
            "client_ip": "10.0.2.50", "protocol": "NFS",
            "object_path": f"/vol/{svm_name}/projects/ml_training/",
            "share_name": "-",
            "access_operations": "WriteAttributes",
            "result": "Success",
        },
        {
            "offset_pct": 0.50,
            "event_id": 4660, "event_type": "Object Deleted",
            "user": "j.smith", "domain": "CORP",
            "client_ip": "10.0.1.45", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/finance/temp/scratch_calc.xlsx",
            "share_name": "\\\\CORP-NAS\\Finance",
            "access_operations": "Delete",
            "result": "Success",
        },
        {
            "offset_pct": 0.48,
            "event_id": 4660, "event_type": "Object Deleted",
            "user": "domino-svc", "domain": "-",
            "client_ip": "10.0.2.51", "protocol": "NFS",
            "object_path": f"/vol/{svm_name}/projects/ml_training/tmp/scratch_tensor.npy",
            "share_name": "-",
            "access_operations": "Delete",
            "result": "Success",
        },
        {
            "offset_pct": 0.45,
            "event_id": 5145, "event_type": "Share Access Checked",
            "user": "l.garcia", "domain": "CORP",
            "client_ip": "10.0.1.55", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/projects",
            "share_name": "\\\\CORP-NAS\\Projects",
            "access_operations": "ReadData",
            "result": "Success",
        },
        {
            "offset_pct": 0.40,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "l.garcia", "domain": "CORP",
            "client_ip": "10.0.1.55", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/projects/domino_ml/feature_engineering.ipynb",
            "share_name": "\\\\CORP-NAS\\Projects",
            "access_operations": "ReadData, WriteData",
            "result": "Success",
        },
        {
            "offset_pct": 0.38,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "ubuntu", "domain": "-",
            "client_ip": "10.0.2.52", "protocol": "NFS",
            "object_path": f"/vol/{svm_name}/projects/experiment_logs/metrics.csv",
            "share_name": "-",
            "access_operations": "ReadData, AppendData",
            "result": "Success",
        },
        {
            "offset_pct": 0.35,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "m.johnson", "domain": "CORP",
            "client_ip": "10.0.1.112", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/hr/org_chart_2026.pptx",
            "share_name": "\\\\CORP-NAS\\HR",
            "access_operations": "ReadData",
            "result": "Success",
        },
        {
            "offset_pct": 0.28,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "r.patel", "domain": "CORP",
            "client_ip": "10.0.1.201", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/finance/models/revenue_forecast.xlsx",
            "share_name": "\\\\CORP-NAS\\Finance",
            "access_operations": "ReadData, WriteData, WriteAttributes",
            "result": "Success",
        },
        {
            "offset_pct": 0.20,
            "event_id": 5140, "event_type": "Share Accessed",
            "user": "svc-domino", "domain": "CORP",
            "client_ip": "10.0.2.10", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/projects",
            "share_name": "\\\\CORP-NAS\\Projects",
            "access_operations": "ReadData",
            "result": "Success",
        },
        {
            "offset_pct": 0.15,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "domino-svc", "domain": "-",
            "client_ip": "10.0.2.50", "protocol": "NFS",
            "object_path": f"/vol/{svm_name}/projects/ml_training/config/hyperparams.yaml",
            "share_name": "-",
            "access_operations": "ReadData",
            "result": "Success",
        },
        {
            "offset_pct": 0.12,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "a.nguyen", "domain": "CORP",
            "client_ip": "10.0.1.88", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/finance/raw_data/transactions_dec.csv",
            "share_name": "\\\\CORP-NAS\\Finance",
            "access_operations": "ReadData",
            "result": "Success",
        },
        {
            # Another failed access (SMB)
            "offset_pct": 0.06,
            "event_id": 4656, "event_type": "Handle Requested",
            "user": "b.turner", "domain": "CORP",
            "client_ip": "10.0.1.34", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/hr/compensation/executive_comp.xlsx",
            "share_name": "\\\\CORP-NAS\\HR",
            "access_operations": "ReadData",
            "result": "Failure (0xC0000022)",
        },
        {
            "offset_pct": 0.02,
            "event_id": 4663, "event_type": "Object Accessed",
            "user": "d.chen", "domain": "CORP",
            "client_ip": "10.0.1.77", "protocol": "SMB",
            "object_path": f"/vol/{svm_name}/projects/domino_ml/README.md",
            "share_name": "\\\\CORP-NAS\\Projects",
            "access_operations": "ReadData",
            "result": "Success",
        },
    ]

    events = []
    for raw in raw_events:
        offset  = int(span_seconds * raw["offset_pct"])
        ts      = start + timedelta(seconds=offset)
        ts_str  = ts.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Apply path prefix filter if requested
        if path_prefix and not raw["object_path"].lower().startswith(path_prefix.lower()):
            continue

        # Apply username filter
        if username and username.lower() not in raw["user"].lower():
            continue

        # Apply event type filter
        if event_types and raw["event_type"] not in event_types:
            continue

        # Apply result filter
        if result_filter == "success" and raw["result"] != "Success":
            continue
        if result_filter == "failure" and raw["result"] == "Success":
            continue

        # Apply volume filter — volume is the 3rd path segment: /vol/{svm}/{volume}/...
        if volume:
            parts = raw["object_path"].split("/")
            event_volume = parts[3] if len(parts) > 3 else ""
            if event_volume.lower() != volume.lower():
                continue

        events.append({
            "event_id":          raw["event_id"],
            "event_type":        raw["event_type"],
            "timestamp":         ts.isoformat(),
            "timestamp_str":     ts_str,
            "user":              raw["user"],
            "domain":            raw["domain"],
            "client_ip":         raw["client_ip"],
            "object_path":       raw["object_path"],
            "share_name":        raw["share_name"],
            "access_operations": raw["access_operations"],
            "result":            raw["result"],
            "protocol":          raw["protocol"],
            "svm_name":          svm_name,
        })

    # Sort newest-first
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events


DEMO_SVM_LIST = ["svm-corp-data-01", "svm-finance-prod", "svm-hr-secure"]
DEMO_CLUSTER_NAME = "CORP-ONTAP-CLUSTER-01 (Demo)"

DEMO_VOLUMES = {
    "svm-corp-data-01": ["finance", "hr", "projects", "legal", "marketing", "shared_data", "archive_2024", "compliance"],
    "svm-finance-prod": ["gl_data", "accounts_payable", "accounts_receivable", "treasury", "tax_filings", "audit_workpapers"],
    "svm-hr-secure": ["compensation", "recruiting", "benefits", "personnel_records", "training"],
}
