# Sentinel-ARP

Sentinel-ARP is a context-aware network defense system designed for shared local area networks (LANs). It passively and actively detects ARP-spoofing and gateway impersonation attacks, provides passive TCP/IP OS fingerprinting, dynamically tracks per-host bandwidth usage against configurable fair-usage limits, and exposes real-time telemetry through a high-performance web dashboard.

---

## Project Architecture

- **`m1_arp_monitor/`**: Passive ARP traffic sniffer, dynamic cache monitor, MAC change tracker, and gateway impersonation detector.
- **`m2_enforcement/`**: Per-host bandwidth usage tracker, passive TCP SYN/TTL OS fingerprinting, and fair-usage throttling monitor.
- **`m3_dashboard/`**: FastAPI backend telemetry service and self-contained zero-dependency HTML5/CSS3 real-time dashboard.
- **`common/`**: Shared SQLite database helper (`db.py`) operating in WAL mode with timeout guarantees and CLI inspector (`show.py`).
- **`tools/`**: Network traffic simulation utilities (`simulate_arp_spoof.py`, `simulate_bandwidth_hog.py`) and offline demo capture generators.
- **`tests/`**: Comprehensive automated test suites across all components.

---

## Prerequisites & Installation

### 1. Python Environment
Target Environment: Python 3.11+
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Windows Npcap Driver & Administrator Rights
> [!IMPORTANT]
> **Windows Requirement**: Live packet sniffing and raw packet injection require the [Npcap Driver](https://npcap.com/). During Npcap installation, make sure to check **"Install Npcap in WinPcap API-compatible Mode"**.
> Always run your PowerShell or terminal windows **as Administrator** so Scapy can bind directly to network interfaces.

Verify interface detection with:
```powershell
python -c "from scapy.all import conf; print(conf.iface); print(conf.route.route('0.0.0.0'))"
```

---

## Running Sentinel-ARP (Live Run)

Open **three separate PowerShell windows as Administrator** on the monitor/victim laptop:

### Window 1: M1 ARP Monitor
```powershell
python -m m1_arp_monitor.monitor --gateway <your-gateway-IP>
```
*(If `--gateway` is omitted, Sentinel-ARP automatically detects your default gateway via routing tables).*

### Window 2: M2 Bandwidth Enforcement
```powershell
python -m m2_enforcement.tracker --limit-mb 2
```
*(Use `--limit-mb 2` during demonstrations so the fair-usage threshold triggers quickly).*

### Window 3: M3 Dashboard
```powershell
python -m uvicorn m3_dashboard.app:app --host 0.0.0.0 --port 8000
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser. The dashboard updates every 3 seconds with zero external CDNs or libraries required.

---

## Attacker / Verification Device Commands

On a second laptop connected to the same private test network (or within the test subnet):

### 1. ARP Spoof Simulation
```powershell
python tools/simulate_arp_spoof.py --target <victim-IP> --gateway <gateway-IP> --iface "<interface-name>"
```
*Sends a controlled sequence of 3 forged ARP replies with 1-second pacing. The dashboard will display a red **CRITICAL** `gateway_impersonation` alert row.*

### 2. Bandwidth Fair-Usage Simulation
```powershell
python tools/simulate_bandwidth_hog.py --target <victim-IP> --port 9999 --mbps 5 --seconds 20
```
*Generates rate-paced UDP traffic for 20 seconds. The M2 console logs `would throttle <ip>`, and the dashboard displays an amber **WARNING** `fair_usage_exceeded` alert with a relative bandwidth usage bar.*

---

## Offline Demo Mode (Single Laptop)

If presenting on a single device without a second test laptop:

1. **Generate offline PCAP traces**:
   ```powershell
   python tools/make_demo_pcap.py
   python tools/make_demo_traffic_pcap.py
   ```
2. **Replay ARP Spoofing against M1**:
   ```powershell
   python -m m1_arp_monitor.monitor --pcap demo.pcap --gateway 192.168.1.1
   ```
3. **Replay Traffic Hogging against M2**:
   ```powershell
   python -m m2_enforcement.tracker --pcap demo_traffic.pcap --limit-mb 1
   ```
4. **Inspect Captured State**:
   ```powershell
   python -m common.show
   ```

---

## Automated Tests

Run the full suite of 71 automated tests:
```powershell
python -m pytest tests/ -q
```
*(All tests use isolated mock objects and temporary databases, requiring no live network connection).*
