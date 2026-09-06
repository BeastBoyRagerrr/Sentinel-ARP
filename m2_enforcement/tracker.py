"""Sentinel-ARP: Bandwidth & Traffic Tracker Module.

Tracks network byte counts per source IP address using Scapy packet capture.
Maintains in-memory per-device metrics with a 60-second sliding/fixed window
and periodically reports sorted bandwidth usage to the console.
"""

from __future__ import annotations

import ipaddress
import logging
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    from scapy.all import IP, IPv6, sniff  # type: ignore
except ImportError:
    IP = None  # type: ignore
    IPv6 = None  # type: ignore
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


class BandwidthTracker:
    """Tracks network traffic per source IP address over a sliding time window.

    Stores per-device totals in an in-memory dictionary:
        {ip: {'bytes': int, 'window_start': float}}
    """

    def __init__(self, window_duration: float = 60.0, report_interval: float = 10.0) -> None:
        """Initialize the bandwidth tracker.

        Args:
            window_duration: Seconds before a device's byte counter resets (default 60s).
            report_interval: Interval in seconds between live console reports (default 10s).
        """
        self.window_duration: float = window_duration
        self.report_interval: float = report_interval
        self.devices: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._report_thread: Optional[threading.Thread] = None

    def _extract_source_ip_and_size(self, packet: Any) -> Tuple[Optional[str], int]:
        """Extract source IP address and byte length from a packet.

        Supports Scapy packet objects as well as mock/fake packet objects for testing.
        """
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
                # Scapy packet without IP/IPv6 layer (e.g., pure ARP, Ether, etc.)
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

    def process_packet(self, packet: Any, current_time: Optional[float] = None) -> Optional[str]:
        """Process an individual network packet and accumulate byte usage.

        Resets a device's counter if window_duration has elapsed since window_start.

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
            if src_ip not in self.devices:
                self.devices[src_ip] = {
                    "bytes": packet_bytes,
                    "window_start": now,
                }
            else:
                record = self.devices[src_ip]
                elapsed = now - record["window_start"]
                if elapsed >= self.window_duration:
                    # Reset counter for a new window
                    record["bytes"] = packet_bytes
                    record["window_start"] = now
                else:
                    record["bytes"] += packet_bytes

        return src_ip

    def get_sorted_usage(self) -> List[Tuple[str, Dict[str, Any]]]:
        """Return all tracked devices sorted by byte usage in descending order.

        Returns:
            List of (ip, {'bytes': int, 'window_start': float}) tuples.
        """
        with self._lock:
            # Create a snapshot copy of the devices dictionary
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
    ) -> None:
        """Start packet capture using Scapy and track bandwidth.

        Args:
            interface: Network interface to listen on (None selects default).
            bpf_filter: Berkeley Packet Filter expression (default "ip").
            packet_count: Number of packets to capture (0 for infinite).
        """
        if sniff is None:
            raise RuntimeError(
                "Scapy is required for live packet capture. Install via `pip install scapy`."
            )

        self.start_reporting()
        try:
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
            self.print_report()


if __name__ == "__main__":
    tracker = BandwidthTracker(window_duration=60.0, report_interval=10.0)
    tracker.start_capture()
