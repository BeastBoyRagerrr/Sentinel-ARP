"""Sentinel-ARP: Bandwidth & Traffic Tracker Module.

Tracks network byte counts per source IP address using Scapy packet capture.
Maintains in-memory per-device metrics with a 60-second sliding/fixed window
and periodically reports sorted bandwidth usage to the console.
Extends tracking with passive TCP/IP fingerprinting, MAC change detection,
fair-usage rolling window throttling, and SQLite database persistence.
"""

from __future__ import annotations

import argparse
from collections import deque
import ipaddress
import logging
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import common.db
from m2_enforcement.config import FAIR_USAGE_BYTES, FAIR_USAGE_WINDOW_SECONDS

try:
    from scapy.all import IP, IPv6, Ether, TCP, UDP, conf, sniff  # type: ignore
except ImportError:
    IP = None  # type: ignore
    IPv6 = None  # type: ignore
    Ether = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    conf = None  # type: ignore
    sniff = None  # type: ignore

logger = logging.getLogger(__name__)


def format_bytes(byte_count: int) -> str:
    """Format byte counts into a human-readable string (B, KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(byte_count) < 1024.0:
            return f"{byte_count:3.2f} {unit}"
        byte_count /= 1024.0  # type: ignore
    return f"{byte_count:.2f} PB"


def _is_valid_ip(address: Any) -> bool:
    """Check if address is a valid IPv4 or IPv6 address string."""
    if not isinstance(address, str):
        return False
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def bucket_ttl(ttl: Optional[int]) -> Optional[int]:
    """Round the IP TTL up to the nearest of 64, 128, or 255.
    
    Returns:
        64, 128, or 255 if ttl is valid, else None.
    """
    if ttl is None:
        return None
    try:
        val = int(ttl)
    except (TypeError, ValueError):
        return None
    if val <= 64:
        return 64
    elif val <= 128:
        return 128
    else:
        return 255


class BandwidthTracker:
    """Tracks network traffic per source IP address over a sliding time window.

    Maintains in-memory per-device metrics with a 60-second display counter:
        self.devices = {ip: {'bytes': int, 'window_start': float}}
    Also maintains device fingerprints, rolling fair-usage monitoring, and alerts.
    """

    def __init__(
        self,
        window_duration: float = 60.0,
        report_interval: float = 10.0,
        db_path: Optional[str] = None,
        fair_usage_bytes: Optional[int] = None,
        fair_usage_window: Optional[float] = None,
    ) -> None:
        """Initialize the bandwidth tracker.

        Args:
            window_duration: Seconds before a device's display byte counter resets (default 60s).
            report_interval: Interval in seconds between live console reports (default 10s).
            db_path: Path to SQLite DB. If None, nothing is written.
            fair_usage_bytes: Bandwidth threshold in bytes (default from config).
            fair_usage_window: Time window in seconds for fair usage (default from config).
        """
        self.window_duration: float = window_duration
        self.report_interval: float = report_interval
        self.db_path: Optional[str] = db_path
        self.fair_usage_bytes: int = (
            fair_usage_bytes if fair_usage_bytes is not None else FAIR_USAGE_BYTES
        )
        self.fair_usage_window: float = (
            float(fair_usage_window)
            if fair_usage_window is not None
            else float(FAIR_USAGE_WINDOW_SECONDS)
        )

        # In-memory dictionary for display reporting (asserted strictly in existing tests)
        self.devices: Dict[str, Dict[str, Any]] = {}

        # Internal metadata dictionary for fingerprinting, MAC tracking, rolling usage, and DB sync
        self._device_meta: Dict[str, Dict[str, Any]] = {}

        # In-memory list of alerts
        self.alerts: List[Dict[str, Any]] = []

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._report_thread: Optional[threading.Thread] = None

        if self.db_path:
            common.db.init_db(self.db_path)

    def _extract_source_ip_and_size(self, packet: Any) -> Tuple[Optional[str], int]:
        """Extract source IP address and byte length from a packet."""
        src_candidate: Optional[str] = None
        byte_count: int = 0

        # Determine byte count
        try:
            byte_count = len(packet)
        except (TypeError, AttributeError):
            byte_count = getattr(packet, "size", 0)

        # 1. Scapy layer lookup
        if hasattr(packet, "haslayer"):
            if IP is not None and packet.haslayer(IP):
                src_candidate = str(packet[IP].src)
            elif IPv6 is not None and packet.haslayer(IPv6):
                src_candidate = str(packet[IPv6].src)
            else:
                return None, 0

        # 2. Duck-typed object with .src attribute
        elif hasattr(packet, "src"):
            src_candidate = str(getattr(packet, "src"))

        # 3. Duck-typed dictionary or mapping
        elif isinstance(packet, dict):
            src_candidate = str(packet.get("src") or packet.get("ip") or "")

        # 4. Fallback subscript lookup
        elif hasattr(packet, "__getitem__"):
            try:
                ip_layer = packet["IP"]
                src_candidate = str(getattr(ip_layer, "src", None))
            except (KeyError, IndexError, TypeError):
                pass

        if src_candidate and _is_valid_ip(src_candidate):
            return src_candidate, byte_count

        return None, 0

    def _extract_mac(self, packet: Any) -> Optional[str]:
        """Extract source MAC address from Ethernet layer or duck-typed packet."""
        if Ether is not None and hasattr(packet, "haslayer") and packet.haslayer(Ether):
            try:
                return str(packet[Ether].src).lower().strip()
            except Exception:
                pass
        if hasattr(packet, "getlayer") and packet.getlayer("Ether"):
            try:
                return str(packet.getlayer("Ether").src).lower().strip()
            except Exception:
                pass
        # Duck-typed attribute checks (never check .src directly since that may be an IP)
        for attr in ("src_mac", "mac", "hwsrc"):
            val = getattr(packet, attr, None)
            if val is not None:
                return str(val).lower().strip()
        return None

    def _extract_ttl(self, packet: Any) -> Optional[int]:
        """Extract TTL from IP layer or duck-typed packet."""
        if IP is not None and hasattr(packet, "haslayer") and packet.haslayer(IP):
            try:
                return int(packet[IP].ttl)
            except Exception:
                pass
        if hasattr(packet, "getlayer") and packet.getlayer("IP"):
            try:
                return int(packet.getlayer("IP").ttl)
            except Exception:
                pass
        val = getattr(packet, "ttl", None)
        if val is not None:
            try:
                return int(val)
            except Exception:
                pass
        return None

    def _extract_tcp_syn_and_window(self, packet: Any) -> Tuple[bool, Optional[int]]:
        """Check if packet is TCP SYN (SYN set, ACK not set) and extract window size."""
        tcp_layer = None
        if TCP is not None and hasattr(packet, "haslayer") and packet.haslayer(TCP):
            tcp_layer = packet[TCP]
        elif hasattr(packet, "getlayer") and packet.getlayer("TCP"):
            tcp_layer = packet.getlayer("TCP")
        elif hasattr(packet, "flags") or hasattr(packet, "window"):
            tcp_layer = packet

        if tcp_layer is None:
            return False, None

        flags = getattr(tcp_layer, "flags", None)
        is_syn = False
        if flags is not None:
            try:
                val = int(flags)
                is_syn = (val & 0x02 != 0) and (val & 0x10 == 0)
            except (TypeError, ValueError):
                s = str(flags).upper()
                is_syn = ("S" in s) and ("A" not in s)

        window = getattr(tcp_layer, "window", None)
        if window is not None:
            try:
                window = int(window)
            except (TypeError, ValueError):
                window = None

        return is_syn, window

    def _save_alert(
        self,
        alert_type: str,
        severity: str,
        ip: str,
        message: str = "",
        current_time: Optional[float] = None,
    ) -> None:
        """Record an alert in-memory and write to database if db_path is set."""
        ts = current_time if current_time is not None else time.time()
        alert_record = {
            "timestamp": ts,
            "alert_type": alert_type,
            "type": alert_type,
            "severity": severity,
            "ip": ip,
            "message": message,
        }
        self.alerts.append(alert_record)
        if self.db_path:
            detail = f"{ip}: {message}" if ip else message
            common.db.insert_alert(
                alert_type=alert_type,
                detail=detail,
                severity=severity,
                path=self.db_path,
            )

    def throttle_device(self, ip: str) -> None:
        """Apply throttling policy to a device exceeding fair usage limits.
        
        Currently only logs the action.
        """
        logger.warning(f"Throttling device: {ip}")

    def flush_db(self) -> None:
        """Flush latest device records to database if db_path is set."""
        if not self.db_path:
            return
        with self._lock:
            for ip, meta in self._device_meta.items():
                bw = self.devices.get(ip, {}).get("bytes", 0)
                common.db.upsert_device(
                    ip=ip,
                    mac=meta.get("mac") or "",
                    fingerprint=meta.get("fingerprint"),
                    bandwidth_bytes=bw,
                    path=self.db_path,
                )

    def process_packet(self, packet: Any, current_time: Optional[float] = None) -> Optional[str]:
        """Process an individual network packet and accumulate byte usage.

        Args:
            packet: Scapy packet or fake packet object.
            current_time: Optional timestamp (defaults to time.time()).

        Returns:
            The source IP that was updated, or None if packet had no valid IP.
        """
        src_ip, packet_bytes = self._extract_source_ip_and_size(packet)
        if not src_ip or packet_bytes <= 0:
            return None

        now = time.time() if current_time is None else current_time

        with self._lock:
            # 1. Update 60-second display window counter
            if src_ip not in self.devices:
                self.devices[src_ip] = {
                    "bytes": packet_bytes,
                    "window_start": now,
                }
            else:
                record = self.devices[src_ip]
                elapsed = now - record["window_start"]
                if elapsed >= self.window_duration:
                    record["bytes"] = packet_bytes
                    record["window_start"] = now
                else:
                    record["bytes"] += packet_bytes

            # 2. Extract packet fingerprinting attributes
            mac = self._extract_mac(packet)
            ttl = self._extract_ttl(packet)
            is_syn, syn_window = self._extract_tcp_syn_and_window(packet)

            # 3. Track device fingerprint and detect MAC/fingerprint changes
            if src_ip not in self._device_meta:
                ttl_bucket = bucket_ttl(ttl)
                tcp_window = syn_window if is_syn else None
                win_str = str(tcp_window) if tcp_window is not None else "na"
                fingerprint = f"{ttl_bucket}-{win_str}" if ttl_bucket is not None else None

                self._device_meta[src_ip] = {
                    "mac": mac,
                    "ttl_bucket": ttl_bucket,
                    "tcp_window": tcp_window,
                    "fingerprint": fingerprint,
                    "last_db_save": 0.0,
                    "rolling_traffic": deque(),
                    "throttled": False,
                }
            else:
                meta = self._device_meta[src_ip]
                old_mac = meta.get("mac")
                old_fingerprint = meta.get("fingerprint")
                old_window = meta.get("tcp_window")
                old_ttl_bucket = meta.get("ttl_bucket")

                new_ttl_bucket = bucket_ttl(ttl) if ttl is not None else old_ttl_bucket
                if is_syn and syn_window is not None:
                    current_window = syn_window
                    new_window_known = True
                else:
                    current_window = old_window
                    new_window_known = False

                win_str = str(current_window) if current_window is not None else "na"
                current_fingerprint = (
                    f"{new_ttl_bucket}-{win_str}" if new_ttl_bucket is not None else old_fingerprint
                )

                # Check if MAC changed for this known IP
                if mac is not None and old_mac is not None and mac != old_mac:
                    if old_fingerprint is not None and current_fingerprint is not None:
                        if current_fingerprint == old_fingerprint:
                            print("MAC changed, fingerprint consistent")
                            self._save_alert(
                                alert_type="mac_change_same_fingerprint",
                                severity="INFO",
                                ip=src_ip,
                                message=(
                                    f"MAC changed for {src_ip} ({old_mac} -> {mac}), "
                                    f"fingerprint consistent ({current_fingerprint})"
                                ),
                                current_time=now,
                            )
                        else:
                            old_window_known = (old_window is not None)
                            if old_window_known and new_window_known:
                                self._save_alert(
                                    alert_type="fingerprint_mismatch",
                                    severity="WARNING",
                                    ip=src_ip,
                                    message=(
                                        f"Fingerprint mismatch for {src_ip}: MAC changed ({old_mac} -> {mac}) "
                                        f"and fingerprint changed ({old_fingerprint} -> {current_fingerprint})"
                                    ),
                                    current_time=now,
                                )
                    meta["mac"] = mac
                elif mac is not None and old_mac is None:
                    meta["mac"] = mac

                if new_ttl_bucket is not None:
                    meta["ttl_bucket"] = new_ttl_bucket
                if is_syn and syn_window is not None:
                    meta["tcp_window"] = syn_window
                if current_fingerprint is not None:
                    meta["fingerprint"] = current_fingerprint

            # 4. Rolling fair-usage tracking
            meta = self._device_meta[src_ip]
            rolling = meta["rolling_traffic"]
            rolling.append((now, packet_bytes))

            cutoff = now - self.fair_usage_window
            while rolling and rolling[0][0] <= cutoff:
                rolling.popleft()

            rolling_bytes = sum(b for _, b in rolling)
            if rolling_bytes > self.fair_usage_bytes:
                if not meta["throttled"]:
                    print(f"would throttle {src_ip}")
                    self._save_alert(
                        alert_type="fair_usage_exceeded",
                        severity="WARNING",
                        ip=src_ip,
                        message=(
                            f"Device {src_ip} exceeded fair usage limit: {rolling_bytes} bytes "
                            f"(limit: {self.fair_usage_bytes} bytes)"
                        ),
                        current_time=now,
                    )
                    self.throttle_device(src_ip)
                    meta["throttled"] = True
            else:
                meta["throttled"] = False

            # 5. DB synchronization throttled to at most once every 5 seconds per device
            if self.db_path:
                last_save = meta.get("last_db_save", 0.0)
                if now - last_save >= 5.0:
                    common.db.upsert_device(
                        ip=src_ip,
                        mac=meta.get("mac") or "",
                        fingerprint=meta.get("fingerprint"),
                        bandwidth_bytes=self.devices[src_ip]["bytes"],
                        path=self.db_path,
                    )
                    meta["last_db_save"] = now

        return src_ip

    def get_sorted_usage(self) -> List[Tuple[str, Dict[str, Any]]]:
        """Return all tracked devices sorted by byte usage in descending order.

        Returns:
            List of (ip, {'bytes': int, 'window_start': float}) tuples.
        """
        with self._lock:
            snapshot = {ip: dict(data) for ip, data in self.devices.items()}

        return sorted(
            snapshot.items(),
            key=lambda item: item[1]["bytes"],
            reverse=True,
        )

    def print_report(self, current_time: Optional[float] = None) -> None:
        """Print a live per-device bandwidth report to the console, sorted descending."""
        now = time.time() if current_time is None else current_time
        sorted_devices = self.get_sorted_usage()

        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        border = "=" * 70

        print(f"\n{border}")
        print(f" [Sentinel-ARP] Bandwidth Usage Report - {timestamp_str}")
        print(f" Tracking Window: {self.window_duration:.0f}s | Active Devices: {len(sorted_devices)}")
        print(border)
        print(f"{'Rank':<6}{'Source IP':<18}{'Bytes Used':<16}{'Human Readable':<16}{'Window Elapsed'}")
        print("-" * 70)

        if not sorted_devices:
            print("  (No IP traffic recorded yet)")
        else:
            for rank, (ip, data) in enumerate(sorted_devices, start=1):
                raw_bytes = data["bytes"]
                readable = format_bytes(raw_bytes)
                elapsed = max(0.0, now - data["window_start"])
                print(
                    f"{rank:<6}{ip:<18}{raw_bytes:<16}{readable:<16}{elapsed:.1f}s"
                )

        print(f"{border}\n")

    def _reporting_loop(self) -> None:
        """Background worker that prints bandwidth reports every report_interval seconds."""
        while not self._stop_event.is_set():
            if self._stop_event.wait(timeout=self.report_interval):
                break
            try:
                self.print_report()
            except Exception as err:
                logger.error(f"Error generating bandwidth report: {err}")

    def start_reporting(self) -> None:
        """Start the background reporting thread."""
        if self._report_thread is not None and self._report_thread.is_alive():
            return
        self._stop_event.clear()
        self._report_thread = threading.Thread(
            target=self._reporting_loop,
            name="BandwidthTrackerReportThread",
            daemon=True,
        )
        self._report_thread.start()

    def stop_reporting(self) -> None:
        """Stop the background reporting thread."""
        self._stop_event.set()
        if self._report_thread is not None:
            self._report_thread.join(timeout=2.0)
            self._report_thread = None

    def start_capture(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip",
        packet_count: int = 0,
        offline: Optional[str] = None,
    ) -> None:
        """Start packet capture using Scapy and track bandwidth.

        Args:
            interface: Network interface to listen on (None selects default).
            bpf_filter: Berkeley Packet Filter expression (default "ip").
            packet_count: Number of packets to capture (0 for infinite).
            offline: Optional pcap file path for offline packet replay.
        """
        if sniff is None:
            raise RuntimeError(
                "Scapy is required for packet capture. Install via `pip install scapy`."
            )

        self.start_reporting()
        try:
            if offline:
                print(f"[*] Reading packets from pcap file '{offline}'...")
                sniff(
                    offline=offline,
                    prn=self.process_packet,
                    store=False,
                    count=packet_count,
                )
            else:
                print(f"[*] Starting packet capture on interface '{interface or 'default'}' (Filter: '{bpf_filter}')")
                print("[*] Press Ctrl+C to stop capture.")
                sniff(
                    iface=interface,
                    filter=bpf_filter,
                    prn=self.process_packet,
                    store=False,
                    count=packet_count,
                )
        except KeyboardInterrupt:
            print("\n[*] Stopping packet capture...")
        finally:
            self.stop_reporting()
            self.flush_db()
            self.print_report()


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments for the bandwidth tracker."""
    parser = argparse.ArgumentParser(
        description="Sentinel-ARP: Bandwidth Enforcement & Fingerprint Tracker"
    )

    default_iface = None
    if conf is not None:
        try:
            default_iface = conf.iface
        except Exception:
            default_iface = None

    parser.add_argument(
        "-i",
        "--iface",
        default=default_iface,
        help="Network interface to sniff on (default: scapy conf.iface)",
    )
    parser.add_argument(
        "--pcap",
        dest="pcap",
        metavar="FILE",
        default=None,
        help="Path to pcap file for offline analysis",
    )
    parser.add_argument(
        "--db",
        dest="db",
        metavar="PATH",
        default="sentinel.db",
        help="Path to SQLite database file (default: sentinel.db)",
    )
    parser.add_argument(
        "--limit-mb",
        dest="limit_mb",
        metavar="N",
        type=float,
        default=None,
        help="Override fair-usage byte limit in megabytes (e.g. 1 for 1MB demo)",
    )
    parser.add_argument(
        "--window",
        dest="window",
        metavar="SECONDS",
        type=float,
        default=None,
        help="Override fair-usage time window in seconds",
    )

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    """CLI entrypoint for BandwidthTracker."""
    args = parse_args(argv)
    fair_bytes = int(args.limit_mb * 1024 * 1024) if args.limit_mb is not None else None
    tracker = BandwidthTracker(
        window_duration=60.0,
        db_path=args.db,
        fair_usage_bytes=fair_bytes,
        fair_usage_window=args.window,
    )
    if args.pcap:
        tracker.start_capture(offline=args.pcap)
    else:
        tracker.start_capture(interface=args.iface)


if __name__ == "__main__":
    main()
