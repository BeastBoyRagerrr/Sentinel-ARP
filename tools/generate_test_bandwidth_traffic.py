# Coursework test utility intended only for use on networks owned and operated by the team, to validate the Sentinel-ARP monitoring system.
"""Controlled UDP test traffic generator for Sentinel-ARP bandwidth threshold testing."""

import argparse
import ipaddress
import socket
import sys
import time

PAYLOAD_SIZE = 1024
MAX_SECONDS_LIMIT = 300
MAX_MBPS_LIMIT = 100
ALLOWED_PRIVATE_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def is_allowed_private_address(ip_str: str) -> bool:
    """Validate that an IP string belongs strictly to RFC 1918 private IPv4 ranges."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.IPv4Address(ip_str.strip())
        return any(ip in net for net in ALLOWED_PRIVATE_NETWORKS)
    except (ValueError, ipaddress.AddressValueError):
        return False


def run_bandwidth_test(
    target_ip: str,
    port: int,
    seconds: int = 20,
    mbps: float = 5.0,
    sock=None,
) -> tuple[int, int, float]:
    """
    Transmit UDP packets at approximately target mbps for the specified duration.

    Returns:
        (total_packets, total_bytes_sent, total_elapsed_seconds)
    """
    bytes_per_sec = (mbps * 1_000_000) / 8.0
    payload = b"\x00" * PAYLOAD_SIZE

    created_socket = False
    if sock is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        created_socket = True

    try:
        start_time = time.time()
        end_time = start_time + seconds
        total_bytes_sent = 0
        total_packets = 0
        last_progress_time = start_time

        print(
            f"[*] Starting rate-paced UDP stream to {target_ip}:{port}\n"
            f"    Target Rate: ~{mbps:.1f} Mbps | Duration: {seconds}s | Packet Size: {PAYLOAD_SIZE} bytes",
            flush=True,
        )

        while True:
            now = time.time()
            if now >= end_time:
                break

            sock.sendto(payload, (target_ip, port))
            total_bytes_sent += len(payload)
            total_packets += 1

            # Progress update every 5 seconds
            if now - last_progress_time >= 5.0:
                elapsed_so_far = now - start_time
                mb_sent = total_bytes_sent / (1024 * 1024)
                achieved_mbps = (total_bytes_sent * 8.0 / elapsed_so_far) / 1_000_000.0 if elapsed_so_far > 0 else 0.0
                print(
                    f"[PROGRESS] {int(elapsed_so_far)}s elapsed | {total_packets} packets | "
                    f"{mb_sent:.2f} MB sent | ~{achieved_mbps:.2f} Mbps",
                    flush=True,
                )
                last_progress_time = now

            # Pacing calculation to prevent rate overrun
            expected_elapsed = total_bytes_sent / bytes_per_sec
            sleep_time = (start_time + expected_elapsed) - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

        total_elapsed = time.time() - start_time
        mb_total = total_bytes_sent / (1024 * 1024)
        avg_mbps = (total_bytes_sent * 8.0 / total_elapsed) / 1_000_000.0 if total_elapsed > 0 else 0.0

        print(
            f"[SUMMARY] Completed {total_elapsed:.2f}s | {total_packets} packets | "
            f"{mb_total:.2f} MB ({total_bytes_sent} bytes) | Average rate: ~{avg_mbps:.2f} Mbps",
            flush=True,
        )
        return total_packets, total_bytes_sent, total_elapsed
    except KeyboardInterrupt:
        total_elapsed = time.time() - start_time
        mb_total = total_bytes_sent / (1024 * 1024)
        print(f"\n[*] Test interrupted by user at {total_elapsed:.2f}s ({mb_total:.2f} MB sent).", flush=True)
        return total_packets, total_bytes_sent, total_elapsed
    finally:
        if created_socket:
            sock.close()


def parse_args(args=None):
    """Parse and validate command line arguments."""
    parser = argparse.ArgumentParser(
        description="Controlled UDP bandwidth test traffic generator for Sentinel-ARP fair-usage testing."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Destination private IPv4 address (10.x, 172.16-31.x, 192.168.x)",
    )
    parser.add_argument(
        "--port",
        required=True,
        type=int,
        help="Destination UDP port (1 - 65535)",
    )
    parser.add_argument(
        "--seconds",
        default=20,
        type=int,
        help="Test duration in seconds (default: 20, max: 300)",
    )
    parser.add_argument(
        "--mbps",
        default=5.0,
        type=float,
        help="Approximate transmission rate in Megabits per second (default: 5.0, max: 100)",
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

    # Validate port
    if not (1 <= parsed.port <= 65535):
        sys.stderr.write(f"[-] Error: Port must be between 1 and 65535, got {parsed.port}.\n")
        sys.exit(1)

    # Validate duration
    if parsed.seconds <= 0:
        sys.stderr.write(f"[-] Error: Duration must be greater than 0, got {parsed.seconds}.\n")
        sys.exit(1)

    if parsed.seconds > MAX_SECONDS_LIMIT:
        sys.stderr.write(
            f"[-] Error: Duration {parsed.seconds}s exceeds safety cap of {MAX_SECONDS_LIMIT}s.\n"
        )
        sys.exit(1)

    # Validate rate
    if parsed.mbps <= 0:
        sys.stderr.write(f"[-] Error: Target rate must be positive, got {parsed.mbps}.\n")
        sys.exit(1)

    if parsed.mbps > MAX_MBPS_LIMIT:
        sys.stderr.write(
            f"[-] Error: Target rate {parsed.mbps} Mbps exceeds safety cap of {MAX_MBPS_LIMIT} Mbps.\n"
        )
        sys.exit(1)

    run_bandwidth_test(
        target_ip=parsed.target,
        port=parsed.port,
        seconds=parsed.seconds,
        mbps=parsed.mbps,
    )


if __name__ == "__main__":
    main()
