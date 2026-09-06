"""ARP Monitoring module for passive detection of MAC address changes."""

import argparse
from datetime import datetime, timezone
import sys
import threading
import time
from typing import Dict, Optional

try:
    from scapy.all import ARP, sniff
except ImportError:
    # Scapy might be mocked or unavailable during certain lightweight test environments
    ARP = None
    sniff = None


class ARPMonitor:
    """Passively monitors ARP replies and tracks IP-to-MAC associations."""

    def __init__(self):
        # In-memory mapping of IP address -> MAC address
        self.ip_mac_table: Dict[str, str] = {}
        self._lock = threading.Lock()

    def process_packet(self, packet) -> Optional[str]:
        """Process a single packet and inspect ARP replies for MAC changes.

        Args:
            packet: Scapy packet object or mock object.

        Returns:
            Warning message string if a MAC change is detected, else None.
        """
        # Check if the packet contains an ARP layer
        if ARP is not None and hasattr(packet, "haslayer") and packet.haslayer(ARP):
            arp_layer = packet[ARP]
        elif hasattr(packet, "op") and hasattr(packet, "psrc") and hasattr(packet, "hwsrc"):
            # Direct ARP layer or mock object
            arp_layer = packet
        elif hasattr(packet, "getlayer") and packet.getlayer("ARP"):
            arp_layer = packet.getlayer("ARP")
        else:
            return None

        # Only process ARP replies (op == 2 / 'is-at')
        # Scapy uses integer 2 or string representation 'is-at'
        op = getattr(arp_layer, "op", None)
        if op != 2 and op != "is-at":
            return None

        ip = getattr(arp_layer, "psrc", None)
        mac = getattr(arp_layer, "hwsrc", None)

        if not ip or not mac:
            return None

        # Normalize MAC address to lower-case
        mac = str(mac).lower().strip()
        ip = str(ip).strip()

        warning_msg = None

        with self._lock:
            if ip in self.ip_mac_table:
                old_mac = self.ip_mac_table[ip]
                if old_mac != mac:
                    # Timestamp in ISO 8601 UTC format
                    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    warning_msg = (
                        f"[{timestamp}] WARNING: Possible ARP Spoofing Detected! "
                        f"IP: {ip} | Old MAC: {old_mac} | New MAC: {mac}"
                    )
                    print(warning_msg, file=sys.stdout, flush=True)
                    # Update the record with the latest observed MAC
                    self.ip_mac_table[ip] = mac
            else:
                # First time seeing this IP address
                self.ip_mac_table[ip] = mac

        return warning_msg


def start_arp_monitor(
    interface: str = "eth0",
    monitor: Optional[ARPMonitor] = None,
    stop_event: Optional[threading.Event] = None,
) -> threading.Thread:
    """Starts the ARP packet sniffer in a non-blocking background thread.

    Args:
        interface: Network interface name to sniff on (e.g. 'eth0', 'Ethernet').
        monitor: Optional existing ARPMonitor instance.
        stop_event: Optional threading.Event to signal sniffing termination.

    Returns:
        The started background threading.Thread instance.
    """
    if monitor is None:
        monitor = ARPMonitor()

    def _sniff_worker():
        if sniff is None:
            raise RuntimeError("Scapy 'sniff' is not available.")
        
        # Passive sniffing loop filtered for ARP packets
        sniff(
            iface=interface,
            filter="arp",
            prn=monitor.process_packet,
            store=0,
            stop_filter=lambda p: stop_event.is_set() if stop_event else False,
        )

    thread = threading.Thread(
        target=_sniff_worker,
        name=f"ARPMonitor-{interface}",
        daemon=True,
    )
    thread.start()
    return thread


def main():
    """Command line entrypoint for ARP monitoring."""
    parser = argparse.ArgumentParser(
        description="Passive ARP Monitor - Detects unauthorized IP/MAC mappings in real-time."
    )
    parser.add_argument(
        "interface",
        nargs="?",
        default="eth0",
        help="Network interface name to sniff on (default: 'eth0')",
    )
    parser.add_argument(
        "-i",
        "--iface",
        dest="interface_opt",
        help="Network interface name to sniff on (alternative to positional argument)",
    )

    args = parser.parse_args()
    interface = args.interface_opt or args.interface

    print(f"[*] Starting passive ARP monitor on interface '{interface}'...")
    monitor = ARPMonitor()
    stop_event = threading.Event()
    
    try:
        thread = start_arp_monitor(interface=interface, monitor=monitor, stop_event=stop_event)
        print(f"[*] Sniffer thread started (Thread ID: {thread.name}). Press Ctrl+C to stop.")
        while thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping ARP monitor...")
        stop_event.set()
    except Exception as e:
        print(f"[-] Error running ARP monitor: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
