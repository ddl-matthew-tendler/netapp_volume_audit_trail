# NetApp SMB Audit Viewer — Phased Approach, Acceptance Criteria & Assumptions

## Problem Statement

Domino's native audit trail captures file access events that occur through
Domino's own UI/API layer.  However, when a user mounts a Domino-managed
NetApp ONTAP volume over SMB (e.g., mapping a network drive and opening a
file with MS Excel or MS Word from their desktop), Domino has no visibility
into that access.  This app bridges that gap by querying ONTAP's native
audit logs and surfacing SMB file-access events in a Domino admin interface.

---

## Architecture (No Domino Storage)

```
Admin Browser
     │  HTTP form submit + table render
     ▼
Flask App (Domino App, port 8888)
     │  POST /api/query  → on-demand, no caching
     ▼
ontap_client.py  ──►  GET /api/protocols/audit/{svm_uuid}
                  ──►  GET /api/protocols/audit/{svm_uuid}/log/files
                  ──►  GET /api/protocols/audit/{svm_uuid}/log/files/{name}?action=download
                       (EVTX binary)
     │
     ▼
evtx_parser.py   ──►  Filter SMB event IDs (4656,4660,4663,4670,5140,5145)
                  ──►  Filter by time range + optional path prefix
     │
     ▼
JSON response → Frontend table (sort, filter, CSV export)
```

No data is written to Domino storage.  All results are fetched from ONTAP
and held in the browser session only.

---

## Phased Approach

### Phase 1 — Foundation & ONTAP Connectivity  (Weeks 1–2)

**Goal:** Prove the ONTAP REST API connection works and returns audit data.

Tasks:
- [ ] Stand up Flask app skeleton in Domino (domino.yaml, requirements.txt)
- [ ] Implement `OntapClient` with auth, SVM listing, and ping endpoint
- [ ] Verify `/api/protocols/audit` is reachable and returns SVM audit config
- [ ] Verify `/api/protocols/audit/{svm_uuid}/log/files` lists EVTX files
- [ ] Verify file download via `?action=download` returns valid EVTX bytes
- [ ] Enable ONTAP native auditing on a test SVM (CIFS file-op events)
- [ ] Write unit tests for `OntapClient` using mocked HTTP responses

Acceptance Criteria — Phase 1:
- App deploys successfully on Domino and the `/api/ping` endpoint returns
  the cluster name when given valid credentials
- `/api/svms` returns the list of data SVMs for the cluster
- At least one EVTX log file can be downloaded from ONTAP via the app

---

### Phase 2 — EVTX Parsing & SMB Event Extraction  (Weeks 3–4)

**Goal:** Correctly parse ONTAP EVTX files and extract only SMB-relevant events.

Tasks:
- [ ] Integrate `python-evtx` and implement `evtx_parser.parse_smb_events()`
- [ ] Map ONTAP EVTX fields to the canonical event schema
  (timestamp, user, domain, client_ip, object_path, access_operations, result)
- [ ] Filter to SMB/CIFS event IDs: 4656, 4660, 4663, 4670, 5140, 5145
- [ ] Decode ONTAP access mask tokens (%%4416 → ReadData, etc.)
- [ ] Apply time-range filtering precisely at the event level
- [ ] Apply optional path-prefix filtering
- [ ] Write parser unit tests with real EVTX sample files from a test ONTAP
- [ ] Validate that Excel/Word open events appear as event ID 4663 with
  ReadData access and the correct client IP

Acceptance Criteria — Phase 2:
- Parser correctly identifies and returns only SMB events from an EVTX file
  that contains a mix of event types
- A test scenario where an admin opens a .xlsx file from a mapped drive
  produces a row in the results showing the user, client IP, file path,
  "ReadData" operation, and "Success" result
- Events outside the requested date range are excluded
- Events matching the path prefix filter are included; others are excluded

---

### Phase 3 — Admin UI & Query Form  (Weeks 5–6)

**Goal:** Deliver the full admin-facing query interface.

Tasks:
- [ ] Build the query form with all parameters (cluster IP, credentials,
  SVM, date range, path prefix, project name, max files cap)
- [ ] Implement "Test Connection" (ping) and "Load SVMs" helper buttons
- [ ] Wire `/api/query` end-to-end: form → backend → ONTAP → parse → table
- [ ] Render results table with sort, client-side text filter, row counts
- [ ] Implement CSV export of filtered results
- [ ] Add "Live SMB Sessions" modal via `/api/live_sessions`
- [ ] Show meta bar (project name, SVM, date range, event count, generated at)
- [ ] Gate access: confirm the Domino App is set to Admin-only visibility
- [ ] Basic error handling: audit not configured, no files found, parse errors

Acceptance Criteria — Phase 3:
- An admin can complete the full query flow end-to-end in under 2 minutes
  for a 7-day date range with ≤ 10 EVTX files
- Results table is sortable by Timestamp, Event Type, User, Client IP, Result
- Client-side filter narrows rows without a page reload
- CSV export produces a valid file containing all currently visible rows
- The app displays a meaningful error if auditing is not enabled on the SVM
- The app is not accessible to non-admin Domino users
  (enforced via Domino App visibility settings)

---

### Phase 4 — Hardening, Performance & Documentation  (Weeks 7–8)

**Goal:** Make the app production-ready.

Tasks:
- [ ] Add SSL verification toggle (ONTAP_VERIFY_SSL env var)
- [ ] Implement streaming download for large EVTX files to avoid timeouts
- [ ] Add progress indicator if multiple large files need to be fetched
- [ ] Cap number of files per query (configurable, default 10, max 50)
  with a warning when the cap is hit
- [ ] Validate that Gunicorn worker timeout (180 s) is sufficient; tune if needed
- [ ] Add structured logging for each query attempt (no PII in logs)
- [ ] Write runbook: how to enable ONTAP auditing for an SVM (CIFS file-op)
- [ ] Write admin user guide
- [ ] Smoke-test on ONTAP 9.11, 9.12, 9.13 (minimum version: 9.11.1 for
  the log/files REST endpoint)

Acceptance Criteria — Phase 4:
- App handles a date range producing 30 EVTX files gracefully (cap + warning)
- Gunicorn does not time out for a single 50 MB EVTX file download + parse
- No ONTAP credentials are logged at any level
- Runbook successfully guides a NetApp admin to enable CIFS auditing with
  zero prior knowledge of the app

---

## Assumptions

| # | Assumption | Risk if Wrong |
|---|---|---|
| 1 | ONTAP version is ≥ 9.11.1 — required for `/api/protocols/audit/{svm_uuid}/log/files` REST endpoint | Earlier ONTAP versions require SSH/CLI passthrough or ZAPI; significant rework |
| 2 | CIFS/SMB auditing is (or can be) enabled on the target SVM by the NetApp admin | Without auditing enabled, no EVTX files are generated; app has no data to display |
| 3 | The ONTAP cluster management IP is reachable from the Domino compute environment (network path exists) | If firewalled, VPC peering or a proxy would be needed |
| 4 | ONTAP credentials provided in the form have read-only access to the `protocols/audit` and `storage/volumes` API endpoints | If over-permissioned, a dedicated read-only ONTAP REST role should be created |
| 5 | The EVTX file download endpoint (`?action=download`) is enabled and not restricted by ONTAP RBAC | May require specific ONTAP REST role permissions |
| 6 | SMB client process name (Word, Excel) is NOT directly available in ONTAP EVTX | ONTAP records the user, client IP, file path, and access mask — not the desktop application name. The client IP + user identity is the primary correlation point |
| 7 | Domino compute environment allows outbound HTTPS (port 443) to the ONTAP cluster | If egress is locked, a network policy change is needed |
| 8 | The Domino App is deployed with Admin-only visibility (set in Domino App settings) | Without this, any Domino user could query ONTAP credentials stored in the form |
| 9 | EVTX files are ≤ ~100 MB each (typical ONTAP default rotation size) | Very large files may cause memory pressure; streaming download mitigates this |
| 10 | One query covers at most 1 SVM at a time | Cross-SVM queries would require iterating SVMs; can be added in Phase 4 |

---

## Key ONTAP REST API Endpoints Used

| Endpoint | Purpose |
|---|---|
| `GET /api/cluster` | Validate credentials, get cluster name |
| `GET /api/svm/svms?type=data` | List data SVMs |
| `GET /api/svm/svms?name={svm}` | Resolve SVM name → UUID |
| `GET /api/protocols/audit/{svm_uuid}` | Get audit config, confirm enabled |
| `GET /api/protocols/audit/{svm_uuid}/log/files` | List EVTX audit log files |
| `GET /api/protocols/audit/{svm_uuid}/log/files/{name}?action=download` | Download EVTX file |
| `GET /api/protocols/cifs/sessions?svm.name={svm}` | Live active SMB sessions |

---

## SMB Event Reference

| Event ID | Event Name | Triggered By |
|---|---|---|
| 4656 | Handle to object requested | App (Word/Excel) requests file handle over SMB |
| 4663 | Object access attempt | Actual read/write of file content |
| 4660 | Object deleted | File deleted via SMB |
| 4670 | Object permissions changed | ACL modification via SMB |
| 5140 | Network share object accessed | SMB share mount / UNC path access |
| 5145 | Share access check | Share-level permission evaluation |

> **Note on Process Name:** ONTAP EVTX does not record the Windows desktop
> application (Word, Excel) that opened the file. What it does record is the
> **client IP address** and **user account** (domain\user).  Correlation to
> a specific application (e.g., WINWORD.EXE) requires either Windows Security
> Event Log collection from the client endpoint, or an FPolicy integration
> that receives real-time notifications from ONTAP and can correlate with
> EDR/endpoint data.  This is a Phase 4+ enhancement option.

---

## Out of Scope (Current Version)

- Real-time push notifications (FPolicy external engine) — polling via the
  admin UI is the current model
- Cross-SVM aggregated views
- Storage of events in Domino datasets or databases
- Correlation with Windows Security Event Logs for process-level attribution
- Alerting or email notifications on specific events
- Role-based filtering within the app (all admins see all events for the SVM)
