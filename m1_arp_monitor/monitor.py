"""ARP Monitoring module for passive detection of MAC address changes."""

import argparse
from datetime import datetime, timezone
import logging
from pathlib import Path
import sys
import threading
import time
from typing import Dict, Optional

# Ensure workspace root is in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from common.db import init_db, insert_alert, upsert_device

try:
    from scapy.all import ARP, conf, getmacbyip, sniff
except ImportError:
    # Scapy might be mocked or unavailable during certain lightweight test environments
    ARP = None
    conf = None
    getmacbyip = None
    sniff = None

logger = logging.getLogger(__name__)


def isolate_device(ip: str, mac: str) -> None:
    """Isolate a rogue device (stub implementation)."""
    msg = f"would isolate {ip} {mac}"
    logger.info(msg)
    print(msg, file=sys.stdout, flush=True)


class ARPMonitor:
    """Passively monitors ARP replies and tracks IP-to-MAC associations."""

    def __init__(
        self,
        gateway_ip: Optional[str] = None,
        gateway_mac: Optional[str] = None,
        db_path: Optional[str] = None,
    ):
        # In-memory mapping of IP address -> MAC address
        self.ip_mac_table: Dict[str, str] = {}
        self.gateway_ip: Optional[str] = str(gateway_ip).strip() if gateway_ip else None
        self.gateway_mac: Optional[str] = str(gateway_mac).lower().strip() if gateway_mac else None
        self.db_path: Optional[str] = db_path
        self._lock = threading.Lock()

        if self.gateway_ip and self.gateway_mac:
            self.ip_mac_table[self.gateway_ip] = self.gateway_mac
            if self.db_path:
                upsert_device(self.gateway_ip, self.gateway_mac, path=self.db_path)

    def process_packet(self, packet) -> Optional[str]:
        """Process a single packet and inspect ARP replies for MAC changes.

        Args:
            packet: Scapy packet object or mock object.

        Returns:
            Warning/Critical message string if an anomaly is detected, else None.
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
        op = getattr(arp_layer, "op", None)
        if op != 2 and op != "is-at":
            return None

        ip = getattr(arp_layer, "psrc", None)
        mac = getattr(arp_layer, "hwsrc", None)

        if not ip or not mac:
            return None

        # Normalize MAC address to lower-case and strip whitespace
        mac = str(mac).lower().strip()
        ip = str(ip).strip()

        with self._lock:
            # Check for gateway impersonation if gateway_ip is configured
            if self.gateway_ip and ip == self.gateway_ip:
                if self.gateway_mac is None:
                    # Trust the first MAC seen for the gateway IP
                    self.gateway_mac = mac
                    self.ip_mac_table[ip] = mac
                    if self.db_path:
                        upsert_device(ip, mac, path=self.db_path)
                    return None
                elif mac == self.gateway_mac:
                    # Legitimate gateway reply
                    if self.db_path:
                        upsert_device(ip, mac, path=self.db_path)
                    return None
                else:
                    # Gateway impersonation: claimed MAC differs from trusted MAC
                    # The trusted gateway MAC is NEVER overwritten.
                    crit_msg = (
                        f"CRITICAL: Gateway impersonation detected! "
                        f"IP: {ip} | Trusted MAC: {self.gateway_mac} | Claimed MAC: {mac}"
                    )
                    print(crit_msg, file=sys.stdout, flush=True)
                    isolate_device(ip, mac)
                    if self.db_path:
                        insert_alert(
                            alert_type="gateway_impersonation",
                            severity="CRITICAL",
                            detail=crit_msg,
                            path=self.db_path,
                        )
                    return crit_msg

            # Non-gateway IP processing (or gateway_ip not configured)
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
                    if self.db_path:
                        insert_alert(
                            alert_type="mac_change",
                            severity="WARNING",
                            detail=warning_msg,
                            path=self.db_path,
                        )
                        upsert_device(ip, mac, path=self.db_path)
                    return warning_msg
                else:
                    if self.db_path:
                        upsert_device(ip, mac, path=self.db_path)
            else:
                # First time seeing this IP address
                self.ip_mac_table[ip] = mac
                if self.db_path:
                    upsert_device(ip, mac, path=self.db_path)

        return None


def start_arp_monitor(
    interface: Optional[str] = None,
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
    if interface is None:
        interface = str(conf.iface) if conf and hasattr(conf, "iface") else "eth0"

    if monitor is None:
        monitor = ARPMonitor()

    def _sniff_worker():
        if sniff is None:
            raise RuntimeError("Scapy 'sniff' is not available.")

        def _packet_callback(pkt):
            monitor.process_packet(pkt)

        # Passive sniffing loop filtered for ARP packets
        sniff(
            iface=interface,
            filter="arp",
            prn=_packet_callback,
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


def main(args_list: Optional[list] = None):
    """Command line entrypoint for ARP monitoring."""
    default_iface = getattr(conf, "iface", "eth0") if conf else "eth0"
    default_iface_str = str(default_iface) if default_iface is not None else "eth0"

    parser = argparse.ArgumentParser(
        description="Passive ARP Monitor - Detects unauthorized IP/MAC mappings in real-time."
    )
    parser.add_argument(
        "interface",
        nargs="?",
        default=default_iface_str,
        help=f"Network interface name to sniff on (default: {default_iface_str})",
    )
    parser.add_argument(
        "-i",
        "--iface",
        dest="interface_opt",
        help="Network interface name to sniff on (alternative to positional argument)",
    )
    parser.add_argument(
        "--gateway",
        dest="gateway",
        default=None,
        help="Gateway IP address to monitor and protect",
    )
    parser.add_argument(
        "--gateway-mac",
        dest="gateway_mac",
        default=None,
        help="Trusted Gateway MAC address (if not provided, trust first seen)",
    )
    parser.add_argument(
        "--db",
        dest="db",
        default="sentinel.db",
        help="SQLite database path for storing alerts and devices (default: sentinel.db)",
    )
    parser.add_argument(
        "--pcap",
        dest="pcap",
        default=None,
        help="Read offline PCAP file instead of live sniffing",
    )

    args = parser.parse_args(args_list)

    gateway_ip = args.gateway
    gateway_mac = args.gateway_mac
    db_path = args.db

    if not args.pcap:
        # Live mode startup: auto-detect gateway IP and MAC if not provided
        if not gateway_ip:
            try:
                if conf and hasattr(conf, "route"):
                    gateway_ip = conf.route.route("0.0.0.0")[2]
            except Exception as e:
                logger.warning("Could not auto-detect gateway IP: %s", e)
                gateway_ip = None

        if gateway_ip and not gateway_mac:
            try:
                if getmacbyip:
                    mac_found = getmacbyip(gateway_ip)
                    if mac_found:
                        gateway_mac = mac_found
            except Exception as e:
                logger.warning("Could not resolve gateway MAC for %s: %s", gateway_ip, e)
                gateway_mac = None

    print(f"[*] Gateway: {gateway_ip} | Trusted MAC: {gateway_mac}")

    if args.pcap:
        print(f"[*] Reading offline PCAP file '{args.pcap}'...")
        monitor = ARPMonitor(gateway_ip=gateway_ip, gateway_mac=gateway_mac, db_path=db_path)
        def _packet_callback(pkt):
            monitor.process_packet(pkt)

        sniff(offline=args.pcap, prn=_packet_callback, store=0)
        print("[*] Finished processing PCAP.")
        return

    interface = args.interface_opt or args.interface or default_iface_str
    print(f"[*] Starting passive ARP monitor on interface '{interface}'...")
    monitor = ARPMonitor(gateway_ip=gateway_ip, gateway_mac=gateway_mac, db_path=db_path)
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
