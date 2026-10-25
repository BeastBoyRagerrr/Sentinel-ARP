"""Traffic generator tool for Sentinel-ARP.

Creates `demo_traffic.pcap` with:
- 192.168.1.30 sending ~3 MB of UDP packets
- 192.168.1.31 sending ~100 KB of UDP packets
- 192.168.1.32 sending TCP SYN (TTL 64, window 64240) from MAC1,
  and later a TCP SYN (TTL 128, window 8192) from MAC2 (different MAC).
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List

from scapy.all import Ether, IP, TCP, UDP, wrpcap


def generate_demo_packets() -> List[Any]:
    """Construct traffic packets for demonstration according to specification."""
    packets = []

    mac_30 = "00:50:56:c0:00:30"
    mac_31 = "00:50:56:c0:00:31"
    mac_32_first = "00:50:56:c0:00:32"
    mac_32_second = "00:50:56:c0:00:99"
    gateway_mac = "00:50:56:c0:00:01"
    target_ip = "192.168.1.1"

    # 1. Host 192.168.1.32 sends initial TCP SYN (TTL 64, window 64240) from MAC 1
    syn1 = (
        Ether(src=mac_32_first, dst=gateway_mac)
        / IP(src="192.168.1.32", dst=target_ip, ttl=64)
        / TCP(sport=49152, dport=80, flags="S", window=64240)
    )
    packets.append(syn1)

    # 2. Host 192.168.1.30 sends ~3 MB of UDP packets
    payload_chunk = b"X" * 1400
    pkt_template_30 = (
        Ether(src=mac_30, dst=gateway_mac)
        / IP(src="192.168.1.30", dst=target_ip, ttl=64)
        / UDP(sport=5000, dport=5000)
        / payload_chunk
    )
    pkt_len_30 = len(pkt_template_30)
    target_30_bytes = 3 * 1024 * 1024  # 3 MB
    count_30 = (target_30_bytes // pkt_len_30) + 1
    for _ in range(count_30):
        packets.append(pkt_template_30)

    # 3. Host 192.168.1.31 sends ~100 KB of UDP packets
    pkt_template_31 = (
        Ether(src=mac_31, dst=gateway_mac)
        / IP(src="192.168.1.31", dst=target_ip, ttl=64)
        / UDP(sport=5001, dport=5001)
        / payload_chunk
    )
    pkt_len_31 = len(pkt_template_31)
    target_31_bytes = 100 * 1024  # 100 KB
    count_31 = (target_31_bytes // pkt_len_31) + 1
    for _ in range(count_31):
        packets.append(pkt_template_31)

    # 4. Host 192.168.1.32 sends TCP SYN from a different source MAC (TTL 128, window 8192)
    syn2 = (
        Ether(src=mac_32_second, dst=gateway_mac)
        / IP(src="192.168.1.32", dst=target_ip, ttl=128)
        / TCP(sport=49153, dport=80, flags="S", window=8192)
    )
    packets.append(syn2)

    return packets


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate demo_traffic.pcap")
    parser.add_argument(
        "-o",
        "--output",
        default="demo_traffic.pcap",
        help="Output pcap filename (default: demo_traffic.pcap)",
    )
    args = parser.parse_args()

    print(f"[*] Generating demo traffic packets...")
    packets = generate_demo_packets()
    wrpcap(args.output, packets)
    print(f"[+] Wrote {len(packets)} packets to {args.output} ({os.path.getsize(args.output)} bytes)")


if __name__ == "__main__":
    main()
