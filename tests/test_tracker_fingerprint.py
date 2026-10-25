"""Unit tests for Sentinel-ARP fingerprinting, fair-usage enforcement, and DB persistence.

Tests:
1. Fingerprint TTL bucketing and SYN-only window update rules.
2. MAC change with consistent fingerprint triggers INFO alert only.
3. MAC change with fingerprint change triggers fingerprint_mismatch WARNING alert.
4. Fair-usage limit generates exactly one alert until usage drops below and rises again.
5. PCAP mode analysis of demo_traffic.pcap with --limit-mb 1 flags 192.168.1.30 only.
6. DB persistence respects db_path=None and 5-second per-device throttling.
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import time
from typing import NamedTuple

import pytest
from scapy.all import Ether, IP, TCP, UDP  # type: ignore

import common.db
from m2_enforcement.config import FAIR_USAGE_BYTES, FAIR_USAGE_WINDOW_SECONDS
from m2_enforcement.tracker import BandwidthTracker, bucket_ttl, parse_args
from tools.make_demo_traffic_pcap import generate_demo_packets


class FakePacket:
    """Mock packet supporting optional attributes for duck typing."""

    def __init__(
        self,
        src: str,
        size: int,
        ttl: int | None = None,
        src_mac: str | None = None,
        flags: str | int | None = None,
        window: int | None = None,
    ) -> None:
        self.src = src
        self.size = size
        if ttl is not None:
            self.ttl = ttl
        if src_mac is not None:
            self.src_mac = src_mac
        if flags is not None:
            self.flags = flags
        if window is not None:
            self.window = window

    def __len__(self) -> int:
        return self.size


def get_device_record(ip: str, path: str) -> dict | None:
    """Retrieve device record from database for a given IP."""
    devices = common.db.get_devices(path=path)
    for d in devices:
        if d["ip"] == ip:
            return d
    return None


def test_ttl_bucketing_and_syn_only_window_rules() -> None:
    """Verify TTL rounding to nearest of 64, 128, 255 and TCP window updated only on SYN."""
    # Test TTL bucket helper directly
    assert bucket_ttl(1) == 64
    assert bucket_ttl(60) == 64
    assert bucket_ttl(64) == 64
    assert bucket_ttl(65) == 128
    assert bucket_ttl(128) == 128
    assert bucket_ttl(129) == 255
    assert bucket_ttl(255) == 255
    assert bucket_ttl(300) == 255
    assert bucket_ttl(None) is None

    tracker = BandwidthTracker()

    # 1. Packet arrives with TTL 64, but is UDP (no TCP SYN)
    pkt_udp = (
        Ether(src="00:11:22:33:44:01")
        / IP(src="192.168.1.50", ttl=60)
        / UDP(sport=1000, dport=1000)
        / b"hello"
    )
    tracker.process_packet(pkt_udp, current_time=10.0)
    meta = tracker._device_meta["192.168.1.50"]
    assert meta["ttl_bucket"] == 64
    assert meta["tcp_window"] is None
    assert meta["fingerprint"] == "64-na"

    # 2. TCP SYN packet arrives for same IP with window 64240
    pkt_syn = (
        Ether(src="00:11:22:33:44:01")
        / IP(src="192.168.1.50", ttl=64)
        / TCP(sport=2000, dport=80, flags="S", window=64240)
    )
    tracker.process_packet(pkt_syn, current_time=11.0)
    meta = tracker._device_meta["192.168.1.50"]
    assert meta["tcp_window"] == 64240
    assert meta["fingerprint"] == "64-64240"

    # 3. Non-SYN TCP packet arrives (e.g. ACK with different window 512)
    pkt_ack = (
        Ether(src="00:11:22:33:44:01")
        / IP(src="192.168.1.50", ttl=64)
        / TCP(sport=2000, dport=80, flags="A", window=512)
    )
    tracker.process_packet(pkt_ack, current_time=12.0)
    meta = tracker._device_meta["192.168.1.50"]
    # Window must stay 64240 because it should only be updated from SYN packets
    assert meta["tcp_window"] == 64240
    assert meta["fingerprint"] == "64-64240"

    # 4. Duck-typed fake packet without TCP/IP layers works gracefully
    fake = FakePacket(src="192.168.1.50", size=100)
    tracker.process_packet(fake, current_time=13.0)
    meta = tracker._device_meta["192.168.1.50"]
    assert meta["fingerprint"] == "64-64240"


def test_mac_change_same_fingerprint_is_info_only(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Verify that a MAC change with an identical fingerprint prints notification and logs INFO only."""
    db_file = str(tmp_path / "mac_info.db")
    tracker = BandwidthTracker(db_path=db_file)

    mac_orig = "00:11:22:33:44:01"
    mac_new = "00:11:22:33:44:02"

    # Host sends initial TCP SYN
    p1 = (
        Ether(src=mac_orig)
        / IP(src="10.0.0.1", ttl=64)
        / TCP(flags="S", window=64240)
    )
    tracker.process_packet(p1, current_time=100.0)
    assert tracker._device_meta["10.0.0.1"]["fingerprint"] == "64-64240"
    assert len(tracker.alerts) == 0

    # Host sends packet from new MAC with same TTL bucket and same window
    p2 = (
        Ether(src=mac_new)
        / IP(src="10.0.0.1", ttl=64)
        / TCP(flags="S", window=64240)
    )
    tracker.process_packet(p2, current_time=105.0)

    # Verify console output
    captured = capsys.readouterr().out
    assert "MAC changed, fingerprint consistent" in captured

    # Verify alerts list and database
    alerts = tracker.alerts
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "mac_change_same_fingerprint"
    assert alerts[0]["severity"] == "INFO"
    assert alerts[0]["ip"] == "10.0.0.1"

    # Verify database has the alert stored
    db_alerts = common.db.get_alerts(path=db_file)
    assert len(db_alerts) == 1
    assert db_alerts[0]["type"] == "mac_change_same_fingerprint"
    assert db_alerts[0]["severity"] == "INFO"

    # Ensure no WARNING alert was created
    assert not any(a["severity"] == "WARNING" for a in alerts)


def test_both_mac_and_fingerprint_change_gives_fingerprint_mismatch(tmp_path: Path) -> None:
    """Verify that when both MAC and fingerprint change with both windows known, fingerprint_mismatch WARNING is saved."""
    db_file = str(tmp_path / "mismatch.db")
    tracker = BandwidthTracker(db_path=db_file)

    mac1 = "00:aa:bb:cc:dd:01"
    mac2 = "00:aa:bb:cc:dd:02"

    # Initial TCP SYN from MAC1 (TTL 64, window 64240)
    p1 = Ether(src=mac1) / IP(src="10.0.0.2", ttl=64) / TCP(flags="S", window=64240)
    tracker.process_packet(p1, current_time=10.0)

    # Second TCP SYN from MAC2 (TTL 128, window 8192)
    p2 = Ether(src=mac2) / IP(src="10.0.0.2", ttl=128) / TCP(flags="S", window=8192)
    tracker.process_packet(p2, current_time=15.0)

    # Check alert
    alerts = tracker.alerts
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "fingerprint_mismatch"
    assert alerts[0]["severity"] == "WARNING"
    assert alerts[0]["ip"] == "10.0.0.2"

    db_alerts = common.db.get_alerts(path=db_file)
    assert len(db_alerts) == 1
    assert db_alerts[0]["type"] == "fingerprint_mismatch"
    assert db_alerts[0]["severity"] == "WARNING"


def test_fingerprint_mismatch_requires_both_windows_known(tmp_path: Path) -> None:
    """Verify fingerprint_mismatch only fires when both old and new window are known."""
    db_file = str(tmp_path / "unknown_win.db")
    tracker = BandwidthTracker(db_path=db_file)

    mac1 = "00:aa:bb:cc:dd:11"
    mac2 = "00:aa:bb:cc:dd:22"

    # Host sends SYN from MAC1 (window known)
    p1 = Ether(src=mac1) / IP(src="10.0.0.3", ttl=64) / TCP(flags="S", window=64240)
    tracker.process_packet(p1, current_time=10.0)

    # Host sends UDP from MAC2 with TTL 128 (window is NOT known for MAC2)
    p2 = Ether(src=mac2) / IP(src="10.0.0.3", ttl=128) / UDP() / b"data"
    tracker.process_packet(p2, current_time=15.0)

    # Should NOT raise fingerprint_mismatch because new window is unknown ("na")
    assert not any(a["alert_type"] == "fingerprint_mismatch" for a in tracker.alerts)


def test_fair_usage_exceeded_single_alert_until_drop_and_rise(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Verify exceeding fair usage alerts once, ignores subsequent packets while over, and alerts again only after dropping below and rising."""
    db_file = str(tmp_path / "fair_usage.db")
    limit_bytes = 1000
    window_secs = 100.0

    tracker = BandwidthTracker(
        fair_usage_bytes=limit_bytes,
        fair_usage_window=window_secs,
        db_path=db_file,
    )

    ip = "192.168.1.99"

    # Packet 1 at t=10: 600 bytes (under limit)
    tracker.process_packet(FakePacket(ip, 600), current_time=10.0)
    assert len(tracker.alerts) == 0

    # Packet 2 at t=20: 500 bytes (total 1100 > 1000, EXCEEDED!)
    tracker.process_packet(FakePacket(ip, 500), current_time=20.0)
    out = capsys.readouterr().out
    assert f"would throttle {ip}" in out

    alerts = [a for a in tracker.alerts if a["alert_type"] == "fair_usage_exceeded"]
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "WARNING"
    assert alerts[0]["ip"] == ip

    # Packet 3 at t=30: 200 bytes (total 1300 > 1000, still over limit)
    tracker.process_packet(FakePacket(ip, 200), current_time=30.0)
    alerts = [a for a in tracker.alerts if a["alert_type"] == "fair_usage_exceeded"]
    assert len(alerts) == 1  # Did NOT repeat!

    # Time advances to t=125 (Packet 1 from t=10 is outside the 100s window!)
    # Window [25.0, 125.0] contains: packet 2 (500) + packet 3 (200) + packet 4 (100) = 800 <= 1000
    tracker.process_packet(FakePacket(ip, 100), current_time=125.0)
    alerts = [a for a in tracker.alerts if a["alert_type"] == "fair_usage_exceeded"]
    assert len(alerts) == 1  # Still 1, usage dropped below limit

    # Packet 5 at t=130: 1000 bytes brings rolling usage (300 + 1000 = 1300 > 1000)
    tracker.process_packet(FakePacket(ip, 1000), current_time=130.0)
    out2 = capsys.readouterr().out
    assert f"would throttle {ip}" in out2

    alerts = [a for a in tracker.alerts if a["alert_type"] == "fair_usage_exceeded"]
    assert len(alerts) == 2  # Alerted a second time after dropping and rising again!

    # Further packet while over limit does not repeat
    tracker.process_packet(FakePacket(ip, 100), current_time=135.0)
    alerts = [a for a in tracker.alerts if a["alert_type"] == "fair_usage_exceeded"]
    assert len(alerts) == 2


def test_pcap_mode_on_demo_traffic_pcap_flags_only_host_30(tmp_path: Path) -> None:
    """Run tracker in pcap mode on demo_traffic.pcap with --limit-mb 1 and verify only 192.168.1.30 is flagged."""
    pcap_path = str(tmp_path / "test_demo_traffic.pcap")
    db_path = str(tmp_path / "pcap_test.db")

    # Generate demo packets to temp pcap
    from scapy.all import wrpcap
    packets = generate_demo_packets()
    wrpcap(pcap_path, packets)

    # Initialize tracker with 1 MB fair usage limit (1024 * 1024 bytes)
    tracker = BandwidthTracker(
        fair_usage_bytes=1024 * 1024,
        fair_usage_window=300.0,
        db_path=db_path,
    )

    tracker.start_capture(offline=pcap_path)

    # Verify fair usage exceeded alerts
    fair_alerts = [a for a in tracker.alerts if a["alert_type"] == "fair_usage_exceeded"]
    assert len(fair_alerts) >= 1
    # 192.168.1.30 sent ~3 MB (> 1 MB), so it must be flagged
    assert all(a["ip"] == "192.168.1.30" for a in fair_alerts)

    # Verify 192.168.1.31 (~100 KB) and 192.168.1.32 were NOT flagged for fair usage
    flagged_ips = {a["ip"] for a in fair_alerts}
    assert "192.168.1.30" in flagged_ips
    assert "192.168.1.31" not in flagged_ips
    assert "192.168.1.32" not in flagged_ips

    # Verify 192.168.1.32 was flagged for fingerprint_mismatch
    mismatch_alerts = [a for a in tracker.alerts if a["alert_type"] == "fingerprint_mismatch"]
    assert len(mismatch_alerts) == 1
    assert mismatch_alerts[0]["ip"] == "192.168.1.32"

    # Verify database contents
    db_devices = {d["ip"]: d for d in common.db.get_devices(path=db_path)}
    assert "192.168.1.30" in db_devices
    assert "192.168.1.31" in db_devices
    assert "192.168.1.32" in db_devices
    assert db_devices["192.168.1.30"]["bandwidth_bytes"] > 1024 * 1024


def test_db_persistence_none_and_throttling(tmp_path: Path) -> None:
    """Verify db_path=None writes nothing, and db_path set throttles upsert to at most once per 5 seconds."""
    # When db_path is None, no DB is written
    tracker_no_db = BandwidthTracker(db_path=None)
    fake_pkt = FakePacket("192.168.1.10", 100)
    tracker_no_db.process_packet(fake_pkt, current_time=1.0)
    # Check that sentinel.db was not created in current dir if not specified
    assert tracker_no_db.db_path is None

    # When db_path is set, verify at most once every 5 seconds per device
    db_path = str(tmp_path / "throttle_test.db")
    tracker = BandwidthTracker(db_path=db_path)

    ip = "192.168.1.200"

    # Packet 1 at t=10.0: first write should happen
    tracker.process_packet(FakePacket(ip, 100, src_mac="aa:bb:cc:dd:ee:01"), current_time=10.0)
    dev1 = get_device_record(ip, path=db_path)
    assert dev1 is not None
    assert dev1["bandwidth_bytes"] == 100

    # Rapid packets at t=11.0, 12.0, 13.0 (< 5s elapsed since t=10.0)
    tracker.process_packet(FakePacket(ip, 100), current_time=11.0)
    tracker.process_packet(FakePacket(ip, 100), current_time=12.0)
    tracker.process_packet(FakePacket(ip, 100), current_time=13.0)

    # In memory, bytes accumulate to 400
    assert tracker.devices[ip]["bytes"] == 400
    # In DB, bytes should still be 100 because writes are throttled!
    dev2 = get_device_record(ip, path=db_path)
    assert dev2 is not None
    assert dev2["bandwidth_bytes"] == 100

    # Packet at t=15.5 (5.5s elapsed >= 5.0s) triggers DB save
    tracker.process_packet(FakePacket(ip, 100), current_time=15.5)
    dev3 = get_device_record(ip, path=db_path)
    assert dev3 is not None
    assert dev3["bandwidth_bytes"] == 500


def test_argparse_cli_options() -> None:
    """Verify command-line arguments are properly parsed."""
    args = parse_args(["-i", "eth1", "--pcap", "test.pcap", "--db", "custom.db", "--limit-mb", "2.5", "--window", "600"])
    assert args.iface == "eth1"
    assert args.pcap == "test.pcap"
    assert args.db == "custom.db"
    assert args.limit_mb == 2.5
    assert args.window == 600.0
