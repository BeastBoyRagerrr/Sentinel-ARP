# Sentinel-ARP Architectural Decision Records (ADR)

This document formalizes key architectural decisions established during Week 10 development.

---

## Decision 1: Host-Centric Deployment (Run on the Victim Machine)

### Context
In switched Ethernet and modern WPA2/WPA3 Wi-Fi networks, access points and switches maintain CAM (Content Addressable Memory) tables and unicast frames directly to the designated destination MAC address rather than broadcasting packets across all physical ports.

### Decision
Sentinel-ARP is configured to run directly on the protected host (the target victim device), rather than attempting bystander promiscuous monitoring from an unrelated third machine on the same subnet.

### Consequences
- **Positive**: Guarantees that all forged ARP replies (`is-at`) and high-volume UDP/TCP floods directed specifically at the host are observed by Scapy's packet capture engine without requiring port mirroring (SPAN) or physical network tap hardware.
- **Negative**: Requires local agent execution on the endpoint machine.

---

## Decision 2: Passive TCP/IP Fingerprinting via SYN-Only Window & TTL Bucketing

### Context
Passive OS fingerprinting attempts to identify client operating systems by inspecting IP header Time-To-Live (TTL) values and TCP receive window parameters. However, in live network traffic:
1. TTL degrades by 1 across every intermediate routing hop.
2. The TCP window size dynamically changes across packets due to dynamic window scaling, TCP flow control, and application-level buffer saturation.

### Decision
1. **TTL Bucketing**: Recorded IP TTLs are rounded up to the nearest standard OS initial TTL threshold:
   - `≤ 64` → bucket `64` (Linux, macOS, iOS, Android)
   - `65 - 128` → bucket `128` (Windows NT / 10 / 11)
   - `129 - 255` → bucket `255` (Cisco IOS, network appliances, Solaris)
2. **SYN-Only Window Sampling**: TCP window size is recorded only from connection handshake initiation packets where the `SYN` flag is set and `ACK` is unset. Window adjustments in data packets are ignored.

### Consequences
- **Positive**: Eliminates false-positive `fingerprint_mismatch` alerts while accurately distinguishing between Windows and Unix/Linux machines.
- **Positive**: Captures stable OS identities even when legitimate hosts engage in high-throughput data transfers.

---

## Decision 3: Zero-CDN, Self-Contained Web Dashboard Architecture

### Context
Sentinel-ARP is frequently evaluated in isolated university lab environments, offline testbeds, or closed subnets where external Internet access and public DNS resolution may be unavailable or explicitly firewalled.

### Decision
The M3 management dashboard (`m3_dashboard/app.py`) is designed with zero external runtime dependencies:
- No external CDNs (no remote Google Fonts, Bootstrap CDN, Tailwind CDN, or CDN-hosted charting libraries).
- All CSS styling, flexbox/grid layouts, relative bandwidth visualization bars, and color-coded alert badges are rendered with inline CSS.
- Real-time auto-refresh polling is implemented with vanilla browser JavaScript (`fetch('/status')` on a 3000ms timer).

### Consequences
- **Positive**: The dashboard loads instantly and reliably in completely air-gapped test networks without connection timeouts or missing asset warnings.
- **Positive**: Streamlines security posture by preventing third-party script injection vectors on the monitoring console.
