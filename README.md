# Sentinel-ARP

Sentinel-ARP is a context-aware firewall designed for shared local area networks (LANs) that actively detects ARP-spoofing and poisoning attacks while dynamically enforcing host-level bandwidth constraints and traffic policies. By continuously inspecting ARP traffic patterns and maintaining real-time IP-to-MAC state bindings, the system identifies rogue network behavior, applies automated traffic-shaping or isolation rules to suspicious hosts, and exposes operational telemetry through an interactive management dashboard.

## Project Structure

- `m1_arp_monitor/` - ARP traffic sniffing, cache monitoring, and spoofing anomaly detection.
- `m2_enforcement/` - Dynamic firewall filtering, traffic shaping, and bandwidth throttling enforcement.
- `m3_dashboard/` - Telemetry APIs and interactive real-time monitoring dashboard.
- `tests/` - Automated unit and integration tests.
- `docs/` - System architecture and network documentation.

## Setup & Dependencies

Target Environment: Python 3.11

Install dependencies via:
```bash
pip install -r requirements.txt
```
