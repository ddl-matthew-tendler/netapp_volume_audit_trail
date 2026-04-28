"""
NetApp ONTAP REST API client.

Handles authentication, SVM discovery, audit configuration lookup,
and EVTX audit log file retrieval.  All calls are on-demand (no caching).

On FSxN, the dedicated audit log files REST API is not available, and EVTX
files have NTFS ACLs that make them invisible to the REST file browser.
The client falls back to reading EVTX files via SMB using smbprotocol.
"""

import io
import requests
import urllib3

try:
    import smbclient as _smbclient
    _SMB_AVAILABLE = True
except ImportError:
    _SMB_AVAILABLE = False

# ONTAP uses self-signed certs in most on-prem deployments.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OntapError(Exception):
    """Raised when the ONTAP REST API returns an error."""
    pass


class OntapClient:
    """Thin wrapper around the ONTAP REST API."""

    def __init__(self, cluster_ip: str, username: str, password: str, verify_ssl: bool = False):
        self.cluster_ip = cluster_ip
        self.password = password
        self.base_url = f"https://{cluster_ip}/api"
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self._smb_registered = False

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def ping(self) -> dict:
        """Return cluster identity — used to validate credentials."""
        return self._get("/cluster")

    # ------------------------------------------------------------------
    # Cluster info
    # ------------------------------------------------------------------

    def get_ontap_version(self) -> dict:
        """Return ONTAP version info: {full, generation, major, minor}."""
        data = self._get("/cluster", params={"fields": "version"})
        ver = data.get("version", {})
        return {
            "full": ver.get("full", "unknown"),
            "generation": ver.get("generation", 0),
            "major": ver.get("major", 0),
            "minor": ver.get("minor", 0),
        }

    # ------------------------------------------------------------------
    # SVMs
    # ------------------------------------------------------------------

    def list_svms(self) -> list[dict]:
        """Return list of {name, uuid} for all data SVMs."""
        try:
            data = self._get("/svm/svms", params={"type": "data", "fields": "name,uuid"})
        except OntapError as exc:
            # FSxN doesn't support the "type" filter — fall back without it
            if "Unexpected argument" in str(exc):
                data = self._get("/svm/svms", params={"fields": "name,uuid"})
            else:
                raise
        return data.get("records", [])

    def get_svm_uuid(self, svm_name: str) -> str:
        """Resolve an SVM name to its UUID."""
        data = self._get("/svm/svms", params={"name": svm_name, "fields": "uuid"})
        records = data.get("records", [])
        if not records:
            raise OntapError(f"SVM '{svm_name}' not found.")
        return records[0]["uuid"]

    # ------------------------------------------------------------------
    # Volumes
    # ------------------------------------------------------------------

    def list_volumes(self, svm_name: str = "") -> list[dict]:
        """Return list of volumes, optionally filtered by SVM name."""
        params = {"fields": "name,svm.name,size,style", "max_records": 1000}
        if svm_name:
            params["svm.name"] = svm_name
        data = self._get("/storage/volumes", params=params)
        return data.get("records", [])

    # ------------------------------------------------------------------
    # Audit configuration
    # ------------------------------------------------------------------

    def get_audit_config(self, svm_uuid: str) -> dict:
        """
        Return the audit configuration for the given SVM.
        Raises OntapError if auditing is not configured for this SVM.
        """
        data = self._get(f"/protocols/audit/{svm_uuid}")
        return data

    def list_audit_log_files(self, svm_uuid: str, audit_log_path: str = "/") -> list[dict]:
        """
        Return a list of audit log file descriptors for the SVM.
        Each record contains at minimum: name, modified_time, size.

        Tries the dedicated audit log files API first (ONTAP 9.11.1+).
        Falls back to browsing the audit destination volume for .evtx files
        (necessary on FSxN where the audit log files API is not available).
        """
        try:
            data = self._get(
                f"/protocols/audit/{svm_uuid}/log/files",
                params={"fields": "name,modified_time,size", "max_records": 500},
            )
            return data.get("records", [])
        except OntapError as exc:
            if "API not found" not in str(exc) and "404" not in str(exc):
                raise
            # Fallback: read EVTX files via SMB (necessary on FSxN)
            return self._list_evtx_via_smb(audit_log_path)

    def _ensure_smb_session(self):
        """Register an SMB session to the cluster for EVTX file access."""
        if self._smb_registered or not _SMB_AVAILABLE:
            return
        # Discover the CIFS server name for the correct username format
        try:
            cifs_data = self._get("/protocols/cifs/services",
                                  params={"fields": "name", "max_records": 1})
            records = cifs_data.get("records", [])
            cifs_name = records[0].get("name", "") if records else ""
        except OntapError:
            cifs_name = ""

        # Try local CIFS user first, then fall back to plain credentials
        usernames = []
        if cifs_name:
            usernames.append(f"{cifs_name}\\auditreader")
        usernames.append("auditreader")

        for uname in usernames:
            try:
                _smbclient.register_session(
                    self.cluster_ip, username=uname, password=self.password)
                self._smb_registered = True
                return
            except Exception:
                continue

    def _list_evtx_via_smb(self, audit_log_path: str) -> list[dict]:
        """List .evtx files by reading the audit share via SMB."""
        if not _SMB_AVAILABLE:
            return []
        self._ensure_smb_session()
        if not self._smb_registered:
            return []

        # Derive share name from audit_log_path (e.g. /audit_logs -> audit_logs)
        share = audit_log_path.strip("/").split("/")[0] if audit_log_path.strip("/") else "c$"
        unc = f"\\\\{self.cluster_ip}\\{share}"

        try:
            entries = _smbclient.listdir(unc)
        except Exception:
            # Fall back to c$ admin share
            if share != "c$":
                unc = f"\\\\{self.cluster_ip}\\c$"
                subdir = audit_log_path.strip("/")
                if subdir:
                    unc += f"\\{subdir}"
                try:
                    entries = _smbclient.listdir(unc)
                except Exception:
                    return []
            else:
                return []

        results = []
        for name in entries:
            if name.lower().endswith(".evtx"):
                try:
                    info = _smbclient.stat(f"{unc}\\{name}")
                    results.append({
                        "name": name,
                        "size": info.st_size,
                        "modified_time": "",
                    })
                except Exception:
                    results.append({"name": name, "size": 0, "modified_time": ""})
        return results

    def download_audit_log_file(self, svm_uuid: str, file_name: str,
                                audit_log_path: str = "/") -> bytes:
        """
        Stream-download a specific EVTX audit log file and return its raw bytes.
        Tries the dedicated audit API first, falls back to volume file read.
        """
        # Try dedicated audit download endpoint first
        url = f"{self.base_url}/protocols/audit/{svm_uuid}/log/files/{requests.utils.quote(file_name, safe='')}"
        resp = self.session.get(url, params={"action": "download"}, stream=True, timeout=120)
        if resp.ok:
            buf = io.BytesIO()
            for chunk in resp.iter_content(chunk_size=65536):
                buf.write(chunk)
            return buf.getvalue()

        # Fallback: download via SMB
        return self._download_evtx_via_smb(file_name, audit_log_path)

    def _download_evtx_via_smb(self, file_name: str, audit_log_path: str) -> bytes:
        """Download an EVTX file via SMB."""
        if not _SMB_AVAILABLE:
            raise OntapError("smbprotocol is not installed — cannot download audit files on FSxN.")
        self._ensure_smb_session()
        if not self._smb_registered:
            raise OntapError("Could not establish SMB session for EVTX download.")

        share = audit_log_path.strip("/").split("/")[0] if audit_log_path.strip("/") else "c$"
        unc = f"\\\\{self.cluster_ip}\\{share}\\{file_name}"

        try:
            with _smbclient.open_file(unc, mode="rb") as f:
                return f.read()
        except Exception:
            # Fall back to c$ admin share
            unc_alt = f"\\\\{self.cluster_ip}\\c$\\{audit_log_path.strip('/')}\\{file_name}"
            try:
                with _smbclient.open_file(unc_alt, mode="rb") as f:
                    return f.read()
            except Exception as exc:
                raise OntapError(f"Failed to download {file_name} via SMB: {exc}")

    # ------------------------------------------------------------------
    # CIFS / SMB server & sessions
    # ------------------------------------------------------------------

    def check_cifs_server(self, svm_name: str) -> dict | None:
        """
        Check if a CIFS server is configured on the SVM.
        Returns the server record dict if found, None otherwise.
        """
        data = self._get(
            "/protocols/cifs/services",
            params={"svm.name": svm_name, "fields": "svm.name,name,enabled"},
        )
        records = data.get("records", [])
        return records[0] if records else None

    def list_cifs_sessions(self, svm_name: str) -> list[dict]:
        """
        Return currently active SMB sessions for a given SVM.
        Useful for showing real-time access alongside historical events.
        """
        data = self._get(
            "/protocols/cifs/sessions",
            params={
                "svm.name": svm_name,
                "fields": "svm.name,user,client_ip,connected_duration,open_files",
            },
        )
        return data.get("records", [])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.get(url, params=params, timeout=30)
        except requests.exceptions.ConnectTimeout:
            raise OntapError(f"Connection to {self.base_url} timed out. "
                             "Check ONTAP_CLUSTER_IP and that the cluster is reachable from Domino.")
        except requests.exceptions.SSLError as exc:
            raise OntapError(f"TLS/SSL error talking to {self.base_url}: {exc}. "
                             "If the cluster uses a self-signed cert, leave ONTAP_VERIFY_SSL unset or set it to 'false'.")
        except requests.exceptions.ConnectionError as exc:
            raise OntapError(f"Could not connect to {self.base_url}: {exc}. "
                             "Check ONTAP_CLUSTER_IP, DNS, and network reachability.")
        except requests.exceptions.RequestException as exc:
            raise OntapError(f"HTTP request to {self.base_url} failed: {exc}")
        self._raise_for_status(resp)
        return resp.json()

    @staticmethod
    def _raise_for_status(resp: requests.Response) -> None:
        if not resp.ok:
            try:
                detail = resp.json().get("error", {}).get("message", resp.text)
            except Exception:
                detail = resp.text
            raise OntapError(f"ONTAP API {resp.status_code}: {detail}")
