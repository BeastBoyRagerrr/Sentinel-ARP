"""Seed demo data for the Sentinel-ARP dashboard."""

import argparse
import os
import sys

# Ensure project root is in sys.path when running as a script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common.db import init_db, insert_alert, set_policy, upsert_device


def seed_demo_data(db_path: str) -> None:
    """Populate the database with sample devices, alerts, and policies."""
    print(f"Initializing database at: {db_path}")
    init_db(db_path)

    # 1. Seed Sample Devices
    print("Seeding sample devices...")
    devices = [
        ("192.168.1.1", "00:11:22:33:44:01", "Gateway Router", 104857600),
        ("192.168.1.10", "00:11:22:33:44:10", "Linux Workstation (Ubuntu 22.04)", 52428800),
        ("192.168.1.20", "00:11:22:33:44:20", "macOS (Apple Silicon)", 26214400),
        ("192.168.1.30", "00:11:22:33:44:30", "Android 14", 3145728),
        ("192.168.1.99", "AA:BB:CC:DD:EE:99", "Unknown Device (Kali Linux)", 1048576),
    ]

    for ip, mac, fp, bandwidth in devices:
        upsert_device(ip=ip, mac=mac, fingerprint=fp, bandwidth_bytes=bandwidth, path=db_path)
        print(f"  + Device: {ip} ({mac}) - {fp}")

    # 2. Seed Sample Policies
    print("Seeding sample policies...")
    policies = [
        ("192.168.1.10", "allow"),
        ("192.168.1.99", "block"),
    ]
    for ip, action in policies:
        set_policy(ip=ip, action=action, path=db_path)
        print(f"  + Policy: {ip} -> {action.upper()}")

    # 3. Seed One Alert of Each Severity (INFO, WARNING, CRITICAL)
    print("Seeding sample alerts...")
    alerts = [
        ("DEVICE_ONLINE", "New device connected: 192.168.1.30 (Android 14)", "INFO"),
        ("BANDWIDTH_SURGE", "Device 192.168.1.10 exceeded normal traffic baseline", "WARNING"),
        ("ARP_POISONING", "Duplicate ARP reply: 192.168.1.1 claimed by AA:BB:CC:DD:EE:99", "CRITICAL"),
    ]
    for alert_type, detail, severity in alerts:
        aid = insert_alert(alert_type=alert_type, detail=detail, severity=severity, path=db_path)
        print(f"  + Alert #{aid} [{severity}] {alert_type}: {detail}")

    print("\nDemo data seeding complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed demo data for Sentinel-ARP dashboard.")
    parser.add_argument(
        "--db",
        default=os.getenv("SENTINEL_DB", "sentinel.db"),
        help="Path to database file (default: $SENTINEL_DB or sentinel.db)",
    )
    args = parser.parse_args()
    seed_demo_data(args.db)


if __name__ == "__main__":
    main()
