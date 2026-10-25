"""Generate demo.pcap for ARP spoofing and gateway impersonation testing."""

import argparse
from pathlib import Path
from scapy.all import ARP, Ether, wrpcap


def make_demo_pcap(output_path: str = "demo.pcap") -> str:
    """Write demo.pcap with normal, forged gateway, and changed host ARP replies."""
    packets = [
        # Normal ARP reply from gateway 192.168.1.1 with MAC aa:aa:aa:aa:aa:01
        Ether(src="aa:aa:aa:aa:aa:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:01", pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff"),

        # Normal ARP reply from host 192.168.1.20
        Ether(src="aa:aa:aa:aa:aa:20", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, psrc="192.168.1.20", hwsrc="aa:aa:aa:aa:aa:20", pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff"),

        # Normal ARP reply from host 192.168.1.21
        Ether(src="aa:aa:aa:aa:aa:21", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, psrc="192.168.1.21", hwsrc="aa:aa:aa:aa:aa:21", pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff"),

        # Forged ARP reply claiming 192.168.1.1 with MAC de:ad:be:ef:00:01
        Ether(src="de:ad:be:ef:00:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, psrc="192.168.1.1", hwsrc="de:ad:be:ef:00:01", pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff"),

        # Changed MAC for host 192.168.1.20
        Ether(src="de:ad:be:ef:00:20", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, psrc="192.168.1.20", hwsrc="de:ad:be:ef:00:20", pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff"),
    ]

    wrpcap(str(output_path), packets)
    return str(output_path)


def main():
    parser = argparse.ArgumentParser(description="Generate demo.pcap for Sentinel-ARP testing")
    parser.add_argument(
        "-o",
        "--output",
        default="demo.pcap",
        help="Output pcap file path (default: demo.pcap)",
    )
    args = parser.parse_args()
    out = make_demo_pcap(args.output)
    print(f"[*] Generated demo PCAP at: {out}")


if __name__ == "__main__":
    main()
