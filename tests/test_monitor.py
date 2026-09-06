"""Unit tests for ARPMonitor MAC change detection logic."""

import pytest
from unittest.mock import MagicMock
from scapy.all import ARP, Ether

from m1_arp_monitor.monitor import ARPMonitor


class MockARPPacket:
    """Mock ARP packet object simulating Scapy ARP packet attributes."""

    def __init__(self, op: int, psrc: str, hwsrc: str):
        self.op = op
        self.psrc = psrc
        self.hwsrc = hwsrc

    def haslayer(self, layer):
        return layer == ARP or layer == "ARP"

    def __getitem__(self, layer):
        if layer == ARP or layer == "ARP":
            return self
        raise KeyError(f"Layer {layer} not found")


def test_learn_initial_ip_mac_mapping():
    """Test that a new ARP reply is learned into the in-memory table without warnings."""
    monitor = ARPMonitor()
    
    # Simulate an ARP reply (op=2, is-at) from 192.168.1.100 with MAC aa:bb:cc:dd:ee:01
    pkt = MockARPPacket(op=2, psrc="192.168.1.100", hwsrc="AA:BB:CC:DD:EE:01")
    warning = monitor.process_packet(pkt)

    assert warning is None
    assert "192.168.1.100" in monitor.ip_mac_table
    assert monitor.ip_mac_table["192.168.1.100"] == "aa:bb:cc:dd:ee:01"


def test_same_mac_reply_no_warning():
    """Test that subsequent ARP replies with the same MAC address produce no warning."""
    monitor = ARPMonitor()
    
    pkt1 = MockARPPacket(op=2, psrc="192.168.1.100", hwsrc="aa:bb:cc:dd:ee:01")
    monitor.process_packet(pkt1)

    # Receive second reply from same IP and same MAC
    pkt2 = MockARPPacket(op=2, psrc="192.168.1.100", hwsrc="aa:bb:cc:dd:ee:01")
    warning = monitor.process_packet(pkt2)

    assert warning is None
    assert monitor.ip_mac_table["192.168.1.100"] == "aa:bb:cc:dd:ee:01"


def test_mac_change_detection_triggers_warning(capsys):
    """Test that an ARP reply with a conflicting MAC triggers a warning with required details."""
    monitor = ARPMonitor()
    
    # Step 1: Initial legitimate ARP reply
    pkt_legit = MockARPPacket(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55")
    monitor.process_packet(pkt_legit)
    assert monitor.ip_mac_table["192.168.1.1"] == "00:11:22:33:44:55"

    # Step 2: Rogue ARP reply claiming same IP with different MAC
    pkt_rogue = MockARPPacket(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    warning = monitor.process_packet(pkt_rogue)
    captured = capsys.readouterr().out

    # Assert warning message structure
    assert warning is not None
    assert "WARNING" in warning
    assert "192.168.1.1" in warning
    assert "00:11:22:33:44:55" in warning
    assert "aa:bb:cc:dd:ee:ff" in warning
    assert "UTC" in warning  # Timestamp verified

    # Assert console output matches warning
    assert "WARNING: Possible ARP Spoofing Detected!" in captured
    assert "IP: 192.168.1.1" in captured
    assert "Old MAC: 00:11:22:33:44:55" in captured
    assert "New MAC: aa:bb:cc:dd:ee:ff" in captured

    # Table should now reflect updated state
    assert monitor.ip_mac_table["192.168.1.1"] == "aa:bb:cc:dd:ee:ff"


def test_real_scapy_packet_structure_and_arp_request_ignored():
    """Test using actual Scapy ARP objects: verify ARP requests are ignored and replies work."""
    monitor = ARPMonitor()

    # ARP Request (op=1, who-has): should be ignored by the reply-learning mechanism
    req_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="192.168.1.50", hwsrc="00:aa:00:bb:00:cc", pdst="192.168.1.1")
    warning_req = monitor.process_packet(req_pkt)
    assert warning_req is None
    assert "192.168.1.50" not in monitor.ip_mac_table

    # ARP Reply (op=2, is-at)
    reply_pkt1 = Ether(dst="00:aa:00:bb:00:cc") / ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55")
    monitor.process_packet(reply_pkt1)
    assert monitor.ip_mac_table["192.168.1.1"] == "00:11:22:33:44:55"

    # Conflicting ARP Reply using Scapy layer
    reply_pkt2 = Ether(dst="00:aa:00:bb:00:cc") / ARP(op=2, psrc="192.168.1.1", hwsrc="de:ad:be:ef:00:01")
    warning_reply = monitor.process_packet(reply_pkt2)
    assert warning_reply is not None
    assert "192.168.1.1" in warning_reply
    assert "00:11:22:33:44:55" in warning_reply
    assert "de:ad:be:ef:00:01" in warning_reply
