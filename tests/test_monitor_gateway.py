"""Unit tests for ARPMonitor gateway impersonation detection, database logging, and PCAP mode."""

import os
import tempfile
import pytest
from scapy.all import ARP, Ether

from common.db import get_alerts, get_devices
from m1_arp_monitor.monitor import ARPMonitor, isolate_device, main
from tools.make_demo_pcap import make_demo_pcap


def _create_arp_reply(ip: str, mac: str):
    """Helper to construct a mock ARP reply packet."""
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=ip,
        hwsrc=mac,
        pdst="192.168.1.100",
        hwdst="ff:ff:ff:ff:ff:ff",
    )


def test_normal_arp_traffic_raises_nothing():
    """Verify that legitimate ARP replies create no alerts and populate the devices table."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test.db")
        monitor = ARPMonitor(gateway_ip="192.168.1.1", gateway_mac="aa:aa:aa:aa:aa:01", db_path=db_path)

        pkt_gw = _create_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:01")
        pkt_h1 = _create_arp_reply("192.168.1.20", "aa:aa:aa:aa:aa:20")
        pkt_h2 = _create_arp_reply("192.168.1.21", "aa:aa:aa:aa:aa:21")

        assert monitor.process_packet(pkt_gw) is None
        assert monitor.process_packet(pkt_h1) is None
        assert monitor.process_packet(pkt_h2) is None

        # No alerts should be raised
        alerts = get_alerts(path=db_path)
        assert len(alerts) == 0

        # Devices table should contain learned devices
        devices = {d["ip"]: d["mac"] for d in get_devices(path=db_path)}
        assert devices.get("192.168.1.1") == "aa:aa:aa:aa:aa:01"
        assert devices.get("192.168.1.20") == "aa:aa:aa:aa:aa:20"
        assert devices.get("192.168.1.21") == "aa:aa:aa:aa:aa:21"


def test_gateway_mac_change_writes_critical(capsys):
    """Verify that a rogue MAC claiming the gateway IP triggers a CRITICAL alert and does not overwrite trusted MAC."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test.db")
        # Trust first seen MAC for gateway
        monitor = ARPMonitor(gateway_ip="192.168.1.1", gateway_mac=None, db_path=db_path)

        # 1. Legitimate gateway packet seen first
        legit_pkt = _create_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:01")
        assert monitor.process_packet(legit_pkt) is None
        assert monitor.gateway_mac == "aa:aa:aa:aa:aa:01"

        # 2. Rogue ARP reply claiming gateway IP with different MAC
        rogue_pkt = _create_arp_reply("192.168.1.1", "de:ad:be:ef:00:01")
        result = monitor.process_packet(rogue_pkt)

        # Assert returned message starts with 'CRITICAL: Gateway impersonation'
        assert result is not None
        assert result.startswith("CRITICAL: Gateway impersonation")
        assert "192.168.1.1" in result
        assert "aa:aa:aa:aa:aa:01" in result
        assert "de:ad:be:ef:00:01" in result

        # Ensure trusted gateway MAC was NOT overwritten
        assert monitor.gateway_mac == "aa:aa:aa:aa:aa:01"

        # Assert stdout output
        captured = capsys.readouterr().out
        assert "CRITICAL: Gateway impersonation" in captured
        assert "would isolate 192.168.1.1 de:ad:be:ef:00:01" in captured

        # Assert database contains exactly one CRITICAL alert
        alerts = get_alerts(path=db_path)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["type"] == "gateway_impersonation"
        assert alert["severity"] == "CRITICAL"
        assert "192.168.1.1" in alert["detail"]
        assert "aa:aa:aa:aa:aa:01" in alert["detail"]
        assert "de:ad:be:ef:00:01" in alert["detail"]


def test_non_gateway_mac_change_writes_warning(capsys):
    """Verify that a MAC change on a non-gateway IP writes a WARNING row."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test.db")
        monitor = ARPMonitor(gateway_ip="192.168.1.1", db_path=db_path)

        # 1. Initial binding learned
        pkt1 = _create_arp_reply("192.168.1.50", "aa:aa:aa:aa:aa:50")
        assert monitor.process_packet(pkt1) is None

        # 2. Changed MAC for the non-gateway host
        pkt2 = _create_arp_reply("192.168.1.50", "bb:bb:bb:bb:bb:50")
        result = monitor.process_packet(pkt2)

        # Assert warning returned and logged to console
        assert result is not None
        assert "WARNING: Possible ARP Spoofing Detected!" in result
        captured = capsys.readouterr().out
        assert "WARNING: Possible ARP Spoofing Detected!" in captured

        # Assert database contains exactly one WARNING alert
        alerts = get_alerts(path=db_path)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["type"] == "mac_change"
        assert alert["severity"] == "WARNING"
        assert "192.168.1.50" in alert["detail"]
        assert "aa:aa:aa:aa:aa:50" in alert["detail"]
        assert "bb:bb:bb:bb:bb:50" in alert["detail"]


def test_mac_addresses_normalized_case_insensitively():
    """Verify that MAC addresses are compared case-insensitively without triggering warnings."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test.db")
        monitor = ARPMonitor(
            gateway_ip="192.168.1.1",
            gateway_mac="AA:AA:AA:AA:AA:01",
            db_path=db_path,
        )

        # Send lowercase equivalent of gateway MAC
        pkt_gw_lower = _create_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:01")
        assert monitor.process_packet(pkt_gw_lower) is None

        # Send mixed-case host MAC
        pkt_h1 = _create_arp_reply("192.168.1.20", "AA:bb:CC:dd:EE:20")
        assert monitor.process_packet(pkt_h1) is None

        # Send lowercase equivalent of host MAC
        pkt_h1_lower = _create_arp_reply("192.168.1.20", "aa:bb:cc:dd:ee:20")
        assert monitor.process_packet(pkt_h1_lower) is None

        # No alerts should be raised
        assert len(get_alerts(path=db_path)) == 0


def test_pcap_mode_demo_pcap_produces_one_critical_and_one_warning():
    """Verify pcap mode on demo.pcap with --gateway 192.168.1.1 produces exactly 1 CRITICAL and 1 WARNING."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        pcap_file = os.path.join(tmp_dir, "test_demo.pcap")
        db_file = os.path.join(tmp_dir, "sentinel_test.db")

        # Generate demo pcap
        make_demo_pcap(pcap_file)

        # Run monitor in pcap mode with --gateway 192.168.1.1
        main(["--pcap", pcap_file, "--gateway", "192.168.1.1", "--db", db_file])

        alerts = get_alerts(path=db_file)
        critical_alerts = [a for a in alerts if a["severity"] == "CRITICAL"]
        warning_alerts = [a for a in alerts if a["severity"] == "WARNING"]

        assert len(critical_alerts) == 1
        assert critical_alerts[0]["type"] == "gateway_impersonation"
        assert "192.168.1.1" in critical_alerts[0]["detail"]
        assert "aa:aa:aa:aa:aa:01" in critical_alerts[0]["detail"]
        assert "de:ad:be:ef:00:01" in critical_alerts[0]["detail"]

        assert len(warning_alerts) == 1
        assert warning_alerts[0]["type"] == "mac_change"
        assert "192.168.1.20" in warning_alerts[0]["detail"]

        assert len(alerts) == 2

        # Check devices table
        devices = {d["ip"]: d["mac"] for d in get_devices(path=db_file)}
        assert devices.get("192.168.1.1") == "aa:aa:aa:aa:aa:01"
        assert devices.get("192.168.1.20") == "de:ad:be:ef:00:20"
        assert devices.get("192.168.1.21") == "aa:aa:aa:aa:aa:21"
