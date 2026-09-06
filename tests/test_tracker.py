"""Unit tests for Sentinel-ARP m2_enforcement/tracker.py using fake packet objects."""

from __future__ import annotations

import io
import sys
import time
from typing import NamedTuple

import pytest
from scapy.all import ARP, Ether, IP, TCP, UDP  # type: ignore

from m2_enforcement.tracker import BandwidthTracker, format_bytes


class FakePacket:
    """Lightweight fake packet mock for testing duck-typing."""

    def __init__(self, src: str, size: int) -> None:
        self.src = src
        self.size = size

    def __len__(self) -> int:
        return self.size


def test_dictionary_format_and_initial_packet() -> None:
    """Verify dictionary structure matches {ip: {'bytes': int, 'window_start': timestamp}}."""
    tracker = BandwidthTracker(window_duration=60.0)
    fake_pkt = IP(src="192.168.1.100") / TCP(dport=80) / b"Hello Sentinel"
    pkt_len = len(fake_pkt)

    start_time = 1000.0
    updated_ip = tracker.process_packet(fake_pkt, current_time=start_time)

    assert updated_ip == "192.168.1.100"
    assert "192.168.1.100" in tracker.devices

    device_entry = tracker.devices["192.168.1.100"]
    assert set(device_entry.keys()) == {"bytes", "window_start"}
    assert device_entry["bytes"] == pkt_len
    assert device_entry["window_start"] == start_time


def test_accumulation_within_window() -> None:
    """Verify bytes accumulate properly when subsequent packets arrive within 60s."""
    tracker = BandwidthTracker(window_duration=60.0)
    pkt1 = IP(src="192.168.1.10") / UDP(dport=53) / (b"A" * 50)
    pkt2 = IP(src="192.168.1.10") / UDP(dport=53) / (b"B" * 70)

    len1 = len(pkt1)
    len2 = len(pkt2)

    t0 = 500.0
    tracker.process_packet(pkt1, current_time=t0)
    tracker.process_packet(pkt2, current_time=t0 + 25.0)  # 25 seconds later (< 60s)

    entry = tracker.devices["192.168.1.10"]
    assert entry["bytes"] == len1 + len2
    assert entry["window_start"] == t0  # Window start remains initial timestamp


def test_window_reset_after_60_seconds() -> None:
    """Verify byte counter resets after 60 seconds have elapsed."""
    tracker = BandwidthTracker(window_duration=60.0)
    pkt1 = IP(src="192.168.1.10") / TCP(dport=443) / b"FirstWindowData"
    pkt2 = IP(src="192.168.1.10") / TCP(dport=443) / b"SecondWindowData"

    len1 = len(pkt1)
    len2 = len(pkt2)

    t0 = 1000.0
    tracker.process_packet(pkt1, current_time=t0)
    assert tracker.devices["192.168.1.10"]["bytes"] == len1

    # Packet arrives 60.5s later (> 60s window)
    t1 = t0 + 60.5
    tracker.process_packet(pkt2, current_time=t1)

    entry = tracker.devices["192.168.1.10"]
    assert entry["bytes"] == len2  # Reset to only the new packet's size
    assert entry["window_start"] == t1  # New window start


def test_per_device_independent_windows() -> None:
    """Verify different IPs have independent window starts and byte counts."""
    tracker = BandwidthTracker(window_duration=60.0)
    pkt_a = IP(src="10.0.0.1") / TCP() / b"HostA"
    pkt_b = IP(src="10.0.0.2") / TCP() / b"HostB"

    tracker.process_packet(pkt_a, current_time=100.0)
    tracker.process_packet(pkt_b, current_time=140.0)

    # At t=165.0, Host A has elapsed 65s (>60s), but Host B has only elapsed 25s (<60s)
    pkt_a_new = IP(src="10.0.0.1") / TCP() / b"HostANew"
    pkt_b_new = IP(src="10.0.0.2") / TCP() / b"HostBNew"

    tracker.process_packet(pkt_a_new, current_time=165.0)
    tracker.process_packet(pkt_b_new, current_time=165.0)

    # Host A should have reset
    assert tracker.devices["10.0.0.1"]["bytes"] == len(pkt_a_new)
    assert tracker.devices["10.0.0.1"]["window_start"] == 165.0

    # Host B should have accumulated
    assert tracker.devices["10.0.0.2"]["bytes"] == len(pkt_b) + len(pkt_b_new)
    assert tracker.devices["10.0.0.2"]["window_start"] == 140.0


def test_sorted_usage_descending_order() -> None:
    """Verify get_sorted_usage() returns devices sorted descending by byte usage."""
    tracker = BandwidthTracker(window_duration=60.0)

    p_low = FakePacket(src="192.168.1.2", size=100)
    p_high = FakePacket(src="192.168.1.3", size=5000)
    p_mid = FakePacket(src="192.168.1.4", size=1500)

    tracker.process_packet(p_low, current_time=10.0)
    tracker.process_packet(p_high, current_time=10.0)
    tracker.process_packet(p_mid, current_time=10.0)

    sorted_list = tracker.get_sorted_usage()

    expected_ips = ["192.168.1.3", "192.168.1.4", "192.168.1.2"]
    actual_ips = [ip for ip, _ in sorted_list]
    actual_bytes = [data["bytes"] for _, data in sorted_list]

    assert actual_ips == expected_ips
    assert actual_bytes == [5000, 1500, 100]


def test_non_ip_packets_ignored() -> None:
    """Verify non-IP packets (e.g. pure ARP or Ethernet) are ignored without errors."""
    tracker = BandwidthTracker(window_duration=60.0)

    # ARP packet without IP layer
    arp_pkt = Ether() / ARP(pdst="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff")
    result = tracker.process_packet(arp_pkt)

    assert result is None
    assert len(tracker.devices) == 0


def test_duck_typed_fake_packet_support() -> None:
    """Verify tracker seamlessly works with custom fake/mock packet objects."""
    tracker = BandwidthTracker(window_duration=60.0)

    fake1 = FakePacket("172.16.0.5", 256)
    fake2 = FakePacket("172.16.0.5", 512)

    tracker.process_packet(fake1, current_time=50.0)
    tracker.process_packet(fake2, current_time=60.0)

    assert tracker.devices["172.16.0.5"]["bytes"] == 768
    assert tracker.devices["172.16.0.5"]["window_start"] == 50.0


def test_print_report_output(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify print_report outputs formatted header and sorted device list."""
    tracker = BandwidthTracker(window_duration=60.0)
    tracker.process_packet(FakePacket("192.168.1.50", 2048), current_time=100.0)
    tracker.process_packet(FakePacket("192.168.1.20", 4096), current_time=100.0)

    tracker.print_report(current_time=110.0)

    captured = capsys.readouterr().out
    assert "[Sentinel-ARP] Bandwidth Usage Report" in captured
    assert "192.168.1.20" in captured
    assert "192.168.1.50" in captured
    # 192.168.1.20 should appear before 192.168.1.50 due to higher usage
    pos_higher = captured.find("192.168.1.20")
    pos_lower = captured.find("192.168.1.50")
    assert pos_higher < pos_lower


def test_format_bytes_utility() -> None:
    """Verify byte formatting helper formats bytes, KB, and MB accurately."""
    assert format_bytes(500) == "500.00 B"
    assert format_bytes(1024) == "1.00 KB"
    assert format_bytes(1024 * 1024 * 5) == "5.00 MB"


def test_reporting_thread_start_and_stop() -> None:
    """Verify background reporting thread starts and stops gracefully."""
    tracker = BandwidthTracker(report_interval=0.1)
    tracker.start_reporting()
    assert tracker._report_thread is not None
    assert tracker._report_thread.is_alive()

    # Calling start again should be a no-op
    tracker.start_reporting()

    time.sleep(0.15)
    tracker.stop_reporting()
    assert tracker._report_thread is None
