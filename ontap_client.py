"""
NetApp ONTAP REST API client.

Handles authentication, SVM discovery, audit configuration lookup,
and EVTX audit log file retrieval.  All calls are on-demand (no caching).
"""

import io
import requests
import urllib3

# ONTAP uses self-signed certs in most on-prem deployments.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OntapError(Exception):
    """Raised when the ONTAP REST API returns an error."""
    pass


class OntapClient:
    """Thin wrapper around the ONTAP REST API."""

    def __init__(self, cluster_ip: str, username: str, password: str, verify_ssl: bool = False):
        self.base_url = f"https://{cluster_ip}/api"
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

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
        data = self._get("/svm/svms", params={"type": "data", "fields": "name,uuid"})
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

    def list_audit_log_files(self, svm_uuid: str) -> list[dict]:
        """
        Return a list of audit log file descriptors for the SVM.
        Each record contains at minimum: name, modified_time, size.

        Requires ONTAP 9.11.1 or later.
        """
        data = self._get(
            f"/protocols/audit/{svm_uuid}/log/files",
            params={"fields": "name,modified_time,size", "max_records": 500},
        )
        return data.get("records", [])

    def download_audit_log_file(self, svm_uuid: str, file_name: str) -> bytes:
        """
        Stream-download a specific EVTX audit log file and return its raw bytes.
        Uses the /protocols/audit/{svm_uuid}/log/files/{name}?action=download endpoint.
        """
        url = f"{self.base_url}/protocols/audit/{svm_uuid}/log/files/{requests.utils.quote(file_name, safe='')}"
        resp = self.session.get(url, params={"action": "download"}, stream=True, timeout=120)
        self._raise_for_status(resp)
        buf = io.BytesIO()
        for chunk in resp.iter_content(chunk_size=65536):
            buf.write(chunk)
        return buf.getvalue()

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
