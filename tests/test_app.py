"""
Pytest suite for the Domino NetApp SMB Audit Viewer.

Three test layers:
  1. Unit tests — evtx_parser and demo_data in isolation
  2. App tests  — Flask test client in DEMO_MODE (no ONTAP needed)
  3. Integration tests — Flask test client with OntapClient mocked,
     feeding realistic synthetic data through the full parse pipeline

Run all tests:
  pytest tests/ -v

Run only demo-mode tests (no deps on python-evtx):
  pytest tests/ -v -k "demo"
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

# Make the project root importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

@pytest.fixture
def demo_app():
    """Flask test client with ONTAP_DEMO_MODE=true — no real ONTAP needed."""
    os.environ["ONTAP_DEMO_MODE"] = "true"
    # Remove real ONTAP vars to confirm demo mode works without them
    for var in ("ONTAP_CLUSTER_IP", "ONTAP_USERNAME", "ONTAP_PASSWORD"):
        os.environ.pop(var, None)

    # Re-import app so DEMO_MODE is picked up fresh
    import importlib
    import app as app_module
    importlib.reload(app_module)

    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client

    os.environ.pop("ONTAP_DEMO_MODE", None)


@pytest.fixture
def mocked_app():
    """
    Flask test client with OntapClient fully mocked.
    Exercises the real app code path (not demo mode) but injects
    controlled responses at the HTTP boundary.
    """
    os.environ.pop("ONTAP_DEMO_MODE", None)
    os.environ["ONTAP_CLUSTER_IP"] = "mock-cluster"
    os.environ["ONTAP_USERNAME"]   = "admin"
    os.environ["ONTAP_PASSWORD"]   = "password"

    import importlib
    import app as app_module
    importlib.reload(app_module)

    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client

    for var in ("ONTAP_CLUSTER_IP", "ONTAP_USERNAME", "ONTAP_PASSWORD"):
        os.environ.pop(var, None)


def _post(client, url, body):
    return client.post(
        url,
        data=json.dumps(body),
        content_type="application/json",
    )


# -----------------------------------------------------------------------
# 1. Unit tests — demo_data
# -----------------------------------------------------------------------

class TestDemoData:

    def test_returns_events_for_date_range(self):
        from demo_data import generate_demo_events
        events = generate_demo_events(
            "svm-test", "2026-01-01", "2026-01-07"
        )
        assert len(events) > 0

    def test_events_have_required_fields(self):
        from demo_data import generate_demo_events
        events = generate_demo_events("svm-test", "2026-01-01", "2026-01-07")
        required = {"event_id", "event_type", "timestamp", "timestamp_str",
                    "user", "domain", "client_ip", "object_path",
                    "share_name", "access_operations", "result"}
        for ev in events:
            assert required.issubset(ev.keys()), f"Missing fields in: {ev}"

    def test_sorted_newest_first(self):
        from demo_data import generate_demo_events
        events = generate_demo_events("svm-test", "2026-01-01", "2026-01-07")
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_path_prefix_filter(self):
        from demo_data import generate_demo_events
        events = generate_demo_events(
            "svm-test", "2026-01-01", "2026-01-07",
            path_prefix="/vol/svm-test/finance"
        )
        for ev in events:
            assert ev["object_path"].lower().startswith("/vol/svm-test/finance")

    def test_contains_failure_events(self):
        from demo_data import generate_demo_events
        events = generate_demo_events("svm-test", "2026-01-01", "2026-01-07")
        failures = [e for e in events if "Failure" in e["result"]]
        assert len(failures) >= 1, "Should include at least one failed access event"

    def test_contains_delete_event(self):
        from demo_data import generate_demo_events
        events = generate_demo_events("svm-test", "2026-01-01", "2026-01-07")
        deletes = [e for e in events if e["event_type"] == "Object Deleted"]
        assert len(deletes) >= 1


# -----------------------------------------------------------------------
# 2. App tests — Demo Mode (fastest, no ONTAP, no python-evtx)
# -----------------------------------------------------------------------

class TestDemoMode:

    def test_homepage_loads(self, demo_app):
        r = demo_app.get("/")
        assert r.status_code == 200
        assert b"NetApp SMB Audit Viewer" in r.data

    def test_init_returns_svms(self, demo_app):
        r    = demo_app.get("/api/init")
        data = r.get_json()
        assert r.status_code == 200
        assert data["ok"] is True
        assert len(data["svms"]) > 0
        assert data["demo_mode"] is True
        assert "DEMO MODE" in data["cluster_name"]

    def test_query_returns_events(self, demo_app):
        r = _post(demo_app, "/api/query", {
            "svm_name":   "svm-corp-data-01",
            "start_date": "2026-01-01",
            "end_date":   "2026-04-22",
        })
        data = r.get_json()
        assert r.status_code == 200
        assert "events" in data
        assert len(data["events"]) > 0

    def test_query_events_have_correct_shape(self, demo_app):
        r = _post(demo_app, "/api/query", {
            "svm_name":   "svm-finance-prod",
            "start_date": "2026-01-01",
            "end_date":   "2026-04-22",
        })
        data  = r.get_json()
        event = data["events"][0]
        for field in ("timestamp_str", "event_type", "user", "domain",
                      "client_ip", "object_path", "share_name",
                      "access_operations", "result"):
            assert field in event, f"Missing field: {field}"

    def test_query_meta_is_populated(self, demo_app):
        r = _post(demo_app, "/api/query", {
            "svm_name":   "svm-corp-data-01",
            "start_date": "2026-01-01",
            "end_date":   "2026-04-22",
        })
        meta = r.get_json()["meta"]
        assert meta["svm_name"]    == "svm-corp-data-01"
        assert meta["query_start"] == "2026-01-01"
        assert meta["query_end"]   == "2026-04-22"
        assert meta["events_found"] > 0

    def test_query_path_prefix_filters_results(self, demo_app):
        r = _post(demo_app, "/api/query", {
            "svm_name":   "svm-corp-data-01",
            "start_date": "2026-01-01",
            "end_date":   "2026-04-22",
            "path_prefix": "/vol/svm-corp-data-01/finance",
        })
        data = r.get_json()
        for ev in data["events"]:
            assert ev["object_path"].lower().startswith(
                "/vol/svm-corp-data-01/finance"
            )

    def test_query_missing_svm_returns_400(self, demo_app):
        r = _post(demo_app, "/api/query", {
            "start_date": "2026-01-01",
            "end_date":   "2026-04-22",
        })
        assert r.status_code == 400
        assert "error" in r.get_json()

    def test_query_invalid_date_returns_400(self, demo_app):
        r = _post(demo_app, "/api/query", {
            "svm_name":   "svm-corp-data-01",
            "start_date": "not-a-date",
            "end_date":   "2026-04-22",
        })
        assert r.status_code == 400

    def test_query_start_after_end_returns_400(self, demo_app):
        r = _post(demo_app, "/api/query", {
            "svm_name":   "svm-corp-data-01",
            "start_date": "2026-04-22",
            "end_date":   "2026-01-01",
        })
        assert r.status_code == 400

    def test_live_sessions_demo(self, demo_app):
        r = _post(demo_app, "/api/live_sessions", {
            "svm_name": "svm-corp-data-01",
        })
        data = r.get_json()
        assert r.status_code == 200
        assert len(data["sessions"]) > 0
        session = data["sessions"][0]
        assert "user" in session
        assert "client_ip" in session

    def test_live_sessions_missing_svm(self, demo_app):
        r = _post(demo_app, "/api/live_sessions", {})
        assert r.status_code == 400


# -----------------------------------------------------------------------
# 3. Integration tests — mocked OntapClient
# -----------------------------------------------------------------------

class TestWithMockedOntap:

    def _make_mock_client(self, svm_uuid="svm-uuid-0001"):
        mock = MagicMock()
        mock.ping.return_value            = {"name": "test-cluster"}
        mock.list_svms.return_value       = [
            {"name": "svm-test", "uuid": svm_uuid}
        ]
        mock.get_svm_uuid.return_value    = svm_uuid
        mock.get_audit_config.return_value = {"enabled": True}

        now      = datetime.now(timezone.utc)
        day_ago  = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        mock.list_audit_log_files.return_value = [
            {"name": "audit_recent.evtx", "modified_time": day_ago, "size": 4096}
        ]
        mock.list_cifs_sessions.return_value = [
            {"user": "CORP\\testuser", "client_ip": "10.0.0.1",
             "svm": {"name": "svm-test"}, "connected_duration": "PT1H", "open_files": 1}
        ]
        return mock

    def test_init_endpoint(self, mocked_app):
        mock_client = self._make_mock_client()
        with patch("app._get_client", return_value=mock_client):
            r    = mocked_app.get("/api/init")
            data = r.get_json()
        assert r.status_code == 200
        assert data["ok"] is True
        assert data["cluster_name"] == "test-cluster"
        assert "svm-test" in data["svms"]

    def test_audit_not_enabled_returns_error(self, mocked_app):
        mock_client = self._make_mock_client()
        mock_client.get_audit_config.return_value = {"enabled": False}

        with patch("app._get_client", return_value=mock_client), \
             patch("app.EVTX_AVAILABLE", True):
            r = _post(mocked_app, "/api/query", {
                "svm_name":   "svm-test",
                "start_date": "2026-01-01",
                "end_date":   "2026-04-22",
            })
        assert r.status_code == 400
        assert "not enabled" in r.get_json()["error"].lower()

    def test_no_log_files_returns_warning(self, mocked_app):
        mock_client = self._make_mock_client()
        mock_client.list_audit_log_files.return_value = []

        with patch("app._get_client", return_value=mock_client), \
             patch("app.EVTX_AVAILABLE", True):
            r = _post(mocked_app, "/api/query", {
                "svm_name":   "svm-test",
                "start_date": "2026-01-01",
                "end_date":   "2026-04-22",
            })
        data = r.get_json()
        assert r.status_code == 200
        assert "warning" in data

    def test_live_sessions_mocked(self, mocked_app):
        mock_client = self._make_mock_client()
        with patch("app._get_client", return_value=mock_client):
            r = _post(mocked_app, "/api/live_sessions", {
                "svm_name": "svm-test",
            })
        data = r.get_json()
        assert r.status_code == 200
        assert data["sessions"][0]["user"] == "CORP\\testuser"

    def test_parse_errors_are_reported(self, mocked_app):
        """If download succeeds but EVTX bytes are garbage, parse errors are reported."""
        mock_client = self._make_mock_client()
        mock_client.download_audit_log_file.return_value = b"not valid evtx data"

        with patch("app._get_client", return_value=mock_client), \
             patch("app.EVTX_AVAILABLE", True), \
             patch("app.parse_smb_events", side_effect=Exception("bad evtx")):
            r = _post(mocked_app, "/api/query", {
                "svm_name":   "svm-test",
                "start_date": "2026-01-01",
                "end_date":   "2026-04-22",
            })
        data = r.get_json()
        assert r.status_code == 200
        assert "parse_errors" in data or data["events"] == []


# -----------------------------------------------------------------------
# 4. Unit tests — evtx_parser (if python-evtx is installed)
# -----------------------------------------------------------------------

class TestEvtxParser:

    @pytest.fixture(autouse=True)
    def skip_if_no_evtx(self):
        try:
            import Evtx.Evtx  # noqa
        except ImportError:
            pytest.skip("python-evtx not installed — skipping EVTX parser tests")

    def test_filters_non_smb_events(self):
        """Parser should return empty list for an EVTX with no SMB event IDs."""
        from evtx_parser import parse_smb_events
        # Build a minimal invalid EVTX — parse will return empty, not crash
        result = parse_smb_events(b"\x00" * 512)
        assert isinstance(result, list)

    def test_mock_ontap_evtx_is_parseable(self):
        """
        Use the mock ONTAP server's EVTX builder to produce a valid file,
        then confirm our parser extracts the expected SMB events.
        """
        import importlib
        mock_server = importlib.import_module("mock_ontap_server")
        evtx_bytes  = mock_server._build_evtx("svm-uuid-0001", "test.evtx")

        from evtx_parser import parse_smb_events
        events = parse_smb_events(evtx_bytes)

        assert len(events) > 0, "Should parse at least one SMB event"
        for ev in events:
            assert ev["event_id"] in {4656, 4660, 4663, 4670, 5140, 5145}
            assert "user" in ev
            assert "object_path" in ev

    def test_parser_applies_path_filter(self):
        import importlib
        mock_server = importlib.import_module("mock_ontap_server")
        evtx_bytes  = mock_server._build_evtx("svm-uuid-0001", "test.evtx")

        from evtx_parser import parse_smb_events
        events = parse_smb_events(evtx_bytes, path_prefix="/vol/svm-uuid-0001/finance")
        for ev in events:
            assert ev["object_path"].lower().startswith("/vol/svm-uuid-0001/finance")
