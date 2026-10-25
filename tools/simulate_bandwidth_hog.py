# For use only on a network operated by the project team, to test our own bandwidth-monitoring detector.
"""Rate-controlled UDP traffic generator for Sentinel-ARP bandwidth detection testing."""

import argparse
import ipaddress
import socket
import sys
import time

PAYLOAD_SIZE = 1024


def is_allowed_address(ip_str: str) -> bool:
    """Validate that the target IP address belongs strictly to RFC 1918 private ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        allowed_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        return any(ip in net for net in allowed_networks)
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Controlled UDP traffic generator for fair-usage detector testing."
    )
    parser.add_argument(
        "--target",
        required=True,
        type=str,
        help="Target IPv4 address (must be in private or loopback test ranges)",
    )
    parser.add_argument(
        "--port",
        required=True,
        type=int,
        help="Target UDP destination port",
    )
    parser.add_argument(
        "--seconds",
        default=20,
        type=int,
        help="Duration to transmit traffic in seconds (default: 20)",
    )
    parser.add_argument(
        "--mbps",
        default=5,
        type=float,
        help="Target transmission rate in Megabits per second (default: 5)",
    )

    args = parser.parse_args()

    # Safety validation: target must be in allowed private ranges
    if not is_allowed_address(args.target):
        sys.stderr.write(
            f"[-] Error: Target IP '{args.target}' is outside allowed private ranges "
            "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Sending aborted.\n"
        )
        sys.exit(1)

    bytes_per_sec = (args.mbps * 1_000_000) / 8.0
    payload = b"\x00" * PAYLOAD_SIZE

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        start_time = time.time()
        end_time = start_time + args.seconds
        total_bytes_sent = 0
        last_progress_time = start_time

        print(
            f"[*] Starting rate-paced UDP stream to {args.target}:{args.port} | "
            f"Target Rate: ~{args.mbps:.1f} Mbps | Duration: {args.seconds}s",
            flush=True,
        )

        while True:
            now = time.time()
            if now >= end_time:
                break

            sock.sendto(payload, (args.target, args.port))
            total_bytes_sent += len(payload)

            # Check if 5-second progress report interval elapsed
            if now - last_progress_time >= 5.0:
                elapsed_so_far = now - start_time
                mb_sent = total_bytes_sent / (1024 * 1024)
                achieved_mbps = (total_bytes_sent * 8.0 / elapsed_so_far) / 1_000_000.0
                print(
                    f"[PROGRESS] {int(elapsed_so_far)}s elapsed | {mb_sent:.1f} MB sent | ~{achieved_mbps:.1f} Mbps",
                    flush=True,
                )
                last_progress_time = now

            # Pacing sleep calculation to adhere to the target rate without drift
            expected_elapsed = total_bytes_sent / bytes_per_sec
            sleep_time = (start_time + expected_elapsed) - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

        total_elapsed = time.time() - start_time
        mb_total = total_bytes_sent / (1024 * 1024)
        avg_mbps = (total_bytes_sent * 8.0 / total_elapsed) / 1_000_000.0 if total_elapsed > 0 else 0.0
        print(
            f"[SUMMARY] Finished {total_elapsed:.2f}s | Total sent: {mb_total:.2f} MB "
            f"({total_bytes_sent} bytes) | Average rate: ~{avg_mbps:.1f} Mbps",
            flush=True,
        )
    finally:
        sock.close()


if __name__ == "__main__":
    main()
