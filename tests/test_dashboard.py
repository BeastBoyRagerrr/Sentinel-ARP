"""Unit tests for Sentinel-ARP FastAPI dashboard."""

import os
import tempfile
import unittest
from fastapi.testclient import TestClient

from common.db import get_policies, init_db, insert_alert, upsert_device
from m3_dashboard.app import app


class TestDashboard(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_dashboard.db")
        os.environ["SENTINEL_DB"] = self.db_path
        init_db(self.db_path)
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()
        os.environ.pop("SENTINEL_DB", None)

    def test_health_endpoint(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})

    def test_status_has_three_keys(self) -> None:
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("devices", data)
        self.assertIn("alerts", data)
        self.assertIn("policies", data)
        self.assertIsInstance(data["devices"], list)
        self.assertIsInstance(data["alerts"], list)
        self.assertIsInstance(data["policies"], list)

    def test_inserted_alert_appears(self) -> None:
        insert_alert(
            "TEST_ARP_SPOOF",
            "Attacker MAC claiming gateway IP",
            severity="CRITICAL",
            path=self.db_path,
        )
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["alerts"]), 1)
        alert = data["alerts"][0]
        self.assertEqual(alert["type"], "TEST_ARP_SPOOF")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["detail"], "Attacker MAC claiming gateway IP")

    def test_post_policy_works_and_bad_action_returns_400(self) -> None:
        # Valid 'allow'
        res_allow = self.client.post("/policy/192.168.1.10", json={"action": "allow"})
        self.assertEqual(res_allow.status_code, 200)
        self.assertTrue(res_allow.json().get("ok"))
        self.assertEqual(res_allow.json().get("action"), "allow")

        # Verify persisted via get_policies
        policies = get_policies(path=self.db_path)
        self.assertEqual(len(policies), 1)
        self.assertEqual(policies[0]["ip"], "192.168.1.10")
        self.assertEqual(policies[0]["action"], "allow")

        # Valid 'block'
        res_block = self.client.post("/policy/192.168.1.10", json={"action": "block"})
        self.assertEqual(res_block.status_code, 200)
        self.assertTrue(res_block.json().get("ok"))
        self.assertEqual(res_block.json().get("action"), "block")

        policies = get_policies(path=self.db_path)
        self.assertEqual(len(policies), 1)
        self.assertEqual(policies[0]["action"], "block")

        # Invalid action returns 400
        res_invalid = self.client.post("/policy/192.168.1.10", json={"action": "quarantine"})
        self.assertEqual(res_invalid.status_code, 400)

        res_invalid2 = self.client.post("/policy/192.168.1.10", json={"action": "reject"})
        self.assertEqual(res_invalid2.status_code, 400)

    def test_get_root_returns_html(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        content_type = response.headers.get("content-type", "")
        self.assertIn("text/html", content_type)
        html_text = response.text.lower()
        self.assertIn("<!doctype html>", html_text)
        self.assertIn("sentinel-arp", html_text)
        self.assertIn("/status", html_text)


if __name__ == "__main__":
    unittest.main()
