"""Unit tests for the Sentinel database helper module."""

from datetime import datetime
import io
import os
import sqlite3
import sys
import tempfile
import unittest

from common.db import (
    get_alerts,
    get_devices,
    get_policies,
    init_db,
    insert_alert,
    set_policy,
    upsert_device,
)
from common.show import format_table, show_database


class TestSentinelDB(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_sentinel.db")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_init_db_creates_tables_and_sets_wal_mode(self) -> None:
        init_db(self.db_path)

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            # Verify WAL journal mode
            cursor.execute("PRAGMA journal_mode;")
            mode = cursor.fetchone()[0]
            self.assertEqual(mode.lower(), "wal")

            # Verify tables exist
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
            )
            tables = {row[0] for row in cursor.fetchall()}
            self.assertIn("devices", tables)
            self.assertIn("alerts", tables)
            self.assertIn("policies", tables)
        finally:
            conn.close()

    def test_insert_and_get_alerts(self) -> None:
        # Insert alert with default severity
        id1 = insert_alert("ARP_SPOOF", "IP 192.168.1.5 claimed by MAC aa:bb:cc:dd:ee:ff", path=self.db_path)
        self.assertIsInstance(id1, int)

        # Insert alert with custom severity
        id2 = insert_alert(
            "ROGUE_DHCP",
            "Rogue DHCP server detected",
            severity="CRITICAL",
            path=self.db_path,
        )
        self.assertIsInstance(id2, int)

        alerts = get_alerts(limit=50, path=self.db_path)
        self.assertEqual(len(alerts), 2)

        # Verify newest first ordering
        self.assertEqual(alerts[0]["id"], id2)
        self.assertEqual(alerts[0]["type"], "ROGUE_DHCP")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[0]["detail"], "Rogue DHCP server detected")

        self.assertEqual(alerts[1]["id"], id1)
        self.assertEqual(alerts[1]["type"], "ARP_SPOOF")
        self.assertEqual(alerts[1]["severity"], "INFO")

        # Verify timestamps are ISO 8601 strings
        for alert in alerts:
            ts = alert["timestamp"]
            parsed_dt = datetime.fromisoformat(ts)
            self.assertIsNotNone(parsed_dt.tzinfo)

        # Verify limit works
        limited = get_alerts(limit=1, path=self.db_path)
        self.assertEqual(len(limited), 1)
        self.assertEqual(limited[0]["id"], id2)

    def test_upsert_device_insert_and_selective_updates(self) -> None:
        # 1. Initial insert with only ip and mac
        upsert_device("192.168.1.10", "00:11:22:33:44:55", path=self.db_path)
        devices = get_devices(path=self.db_path)
        self.assertEqual(len(devices), 1)
        dev = devices[0]
        self.assertEqual(dev["ip"], "192.168.1.10")
        self.assertEqual(dev["mac"], "00:11:22:33:44:55")
        self.assertIsNone(dev["fingerprint"])
        self.assertEqual(dev["bandwidth_bytes"], 0)
        first_seen = dev["last_seen"]
        self.assertIsNotNone(first_seen)

        # 2. Update with new mac and fingerprint, leaving bandwidth_bytes untouched
        upsert_device(
            "192.168.1.10",
            "00:11:22:33:44:99",
            fingerprint="Linux 5.15",
            path=self.db_path,
        )
        devices = get_devices(path=self.db_path)
        self.assertEqual(len(devices), 1)
        dev = devices[0]
        self.assertEqual(dev["mac"], "00:11:22:33:44:99")
        self.assertEqual(dev["fingerprint"], "Linux 5.15")
        self.assertEqual(dev["bandwidth_bytes"], 0)

        # 3. Update with bandwidth_bytes only, leaving fingerprint untouched
        upsert_device(
            "192.168.1.10",
            "00:11:22:33:44:99",
            bandwidth_bytes=4096,
            path=self.db_path,
        )
        devices = get_devices(path=self.db_path)
        self.assertEqual(len(devices), 1)
        dev = devices[0]
        self.assertEqual(dev["fingerprint"], "Linux 5.15")
        self.assertEqual(dev["bandwidth_bytes"], 4096)

        # 4. Update with neither fingerprint nor bandwidth_bytes: both remain intact
        upsert_device("192.168.1.10", "00:11:22:33:44:99", path=self.db_path)
        devices = get_devices(path=self.db_path)
        self.assertEqual(len(devices), 1)
        dev = devices[0]
        self.assertEqual(dev["fingerprint"], "Linux 5.15")
        self.assertEqual(dev["bandwidth_bytes"], 4096)

        # 5. Insert a second device directly with initial fingerprint and bandwidth_bytes
        upsert_device(
            "192.168.1.20",
            "AA:BB:CC:DD:EE:FF",
            fingerprint="Windows 11",
            bandwidth_bytes=8192,
            path=self.db_path,
        )
        devices = get_devices(path=self.db_path)
        self.assertEqual(len(devices), 2)
        dev_map = {d["ip"]: d for d in devices}
        self.assertEqual(dev_map["192.168.1.20"]["fingerprint"], "Windows 11")
        self.assertEqual(dev_map["192.168.1.20"]["bandwidth_bytes"], 8192)

    def test_set_and_get_policies(self) -> None:
        set_policy("192.168.1.50", "BLOCK", path=self.db_path)
        policies = get_policies(path=self.db_path)
        self.assertEqual(len(policies), 1)
        self.assertEqual(policies[0]["ip"], "192.168.1.50")
        self.assertEqual(policies[0]["action"], "BLOCK")
        self.assertIsNotNone(policies[0]["updated"])
        initial_time = policies[0]["updated"]

        # Update policy for existing IP
        set_policy("192.168.1.50", "ALLOW", path=self.db_path)
        policies = get_policies(path=self.db_path)
        self.assertEqual(len(policies), 1)
        self.assertEqual(policies[0]["action"], "ALLOW")
        self.assertGreaterEqual(policies[0]["updated"], initial_time)

    def test_functions_auto_init_on_fresh_database(self) -> None:
        fresh_db = os.path.join(self.temp_dir.name, "fresh_sentinel.db")
        self.assertFalse(os.path.exists(fresh_db))

        # Querying an uninitialized database should automatically initialize it
        devices = get_devices(path=fresh_db)
        self.assertEqual(devices, [])
        self.assertTrue(os.path.exists(fresh_db))

        alerts = get_alerts(path=fresh_db)
        self.assertEqual(alerts, [])

        policies = get_policies(path=fresh_db)
        self.assertEqual(policies, [])

    def test_show_script_output(self) -> None:
        upsert_device("192.168.1.100", "11:22:33:44:55:66", fingerprint="Printer", bandwidth_bytes=100, path=self.db_path)
        insert_alert("PORT_SCAN", "Rapid syn packets detected", severity="WARN", path=self.db_path)
        set_policy("192.168.1.100", "QUARANTINE", path=self.db_path)

        captured_output = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured_output
            show_database(path=self.db_path)
        finally:
            sys.stdout = old_stdout

        output = captured_output.getvalue()
        self.assertIn("=== Devices ===", output)
        self.assertIn("192.168.1.100", output)
        self.assertIn("11:22:33:44:55:66", output)
        self.assertIn("Printer", output)
        self.assertIn("=== Alerts ===", output)
        self.assertIn("PORT_SCAN", output)
        self.assertIn("WARN", output)
        self.assertIn("=== Policies ===", output)
        self.assertIn("QUARANTINE", output)

    def test_show_cli_invocation(self) -> None:
        import subprocess

        upsert_device("10.0.0.99", "AA:11:22:33:44:55", path=self.db_path)
        result = subprocess.run(
            [sys.executable, "-m", "common.show", "--db", self.db_path],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("=== Devices ===", result.stdout)
        self.assertIn("10.0.0.99", result.stdout)
        self.assertIn("=== Alerts ===", result.stdout)
        self.assertIn("=== Policies ===", result.stdout)


if __name__ == "__main__":
    unittest.main()
