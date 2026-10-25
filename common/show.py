"""CLI tool to display Sentinel database contents as plain text."""

import argparse
from typing import Any, Sequence
from common.db import get_alerts, get_devices, get_policies


def format_table(title: str, headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Format a list of rows into an aligned plain text table."""
    lines = [f"=== {title} ==="]
    if not rows:
        lines.append("(empty)")
        return "\n".join(lines)

    str_rows = [[str(item) if item is not None else "" for item in row] for row in rows]
    col_widths = [len(h) for h in headers]
    for row in str_rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(val))

    header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    separator_line = "  ".join("-" * col_widths[i] for i in range(len(headers)))
    lines.append(header_line)
    lines.append(separator_line)

    for row in str_rows:
        lines.append("  ".join(val.ljust(col_widths[i]) for i, val in enumerate(row)))

    return "\n".join(lines)


def show_database(path: str = "sentinel.db") -> None:
    """Read and display devices, alerts, and policies tables."""
    devices = get_devices(path=path)
    alerts = get_alerts(limit=50, path=path)
    policies = get_policies(path=path)

    device_rows = [
        [
            d.get("ip"),
            d.get("mac"),
            d.get("fingerprint"),
            d.get("last_seen"),
            d.get("bandwidth_bytes"),
        ]
        for d in devices
    ]
    print(
        format_table(
            "Devices",
            ["IP", "MAC", "Fingerprint", "Last Seen", "Bandwidth (Bytes)"],
            device_rows,
        )
    )
    print()

    alert_rows = [
        [
            a.get("id"),
            a.get("timestamp"),
            a.get("type"),
            a.get("severity"),
            a.get("detail"),
        ]
        for a in alerts
    ]
    print(
        format_table(
            "Alerts",
            ["ID", "Timestamp", "Type", "Severity", "Detail"],
            alert_rows,
        )
    )
    print()

    policy_rows = [
        [
            p.get("ip"),
            p.get("action"),
            p.get("updated"),
        ]
        for p in policies
    ]
    print(format_table("Policies", ["IP", "Action", "Updated"], policy_rows))


def main() -> None:
    parser = argparse.ArgumentParser(description="Print Sentinel database tables as plain text.")
    parser.add_argument(
        "--db",
        default="sentinel.db",
        help="Path to database file (default: sentinel.db)",
    )
    args = parser.parse_args()
    show_database(path=args.db)


if __name__ == "__main__":
    main()
