# Sentinel-ARP Engineering Logbook (Week 10)

This logbook records technical challenges encountered during system integration, root-cause analyses, and the engineering solutions implemented to resolve them.

---

## Log Entry 1: Multi-Process SQLite Database Lock Contention

- **Component**: `common/db.py`
- **What Broke**: When running M1 (ARP monitor), M2 (bandwidth tracker), and M3 (dashboard API server) simultaneously, worker threads threw `sqlite3.OperationalError: database is locked`.
- **Root Cause**: SQLite defaults to a rollback journal mode (`DELETE`), which locks the entire database file during write transactions. Multiple concurrent write operations from packet sniffers collided with reads from the dashboard's 3-second status polling loop.
- **Engineering Fix**:
  1. Enabled Write-Ahead Logging (`PRAGMA journal_mode=WAL;`), allowing concurrent readers and writers without blocking.
  2. Configured a 5.0-second busy timeout (`sqlite3.connect(..., timeout=5.0)`).
  3. Ensured connections are opened on demand and closed immediately using a generator context manager rather than maintaining a persistent global connection.

---

## Log Entry 2: Socket Port Address Binding Conflict ([WinError 10048])

- **Component**: `m3_dashboard/app.py` / Uvicorn Server
- **What Broke**: Starting `uvicorn m3_dashboard.app:app --host 0.0.0.0 --port 8000` resulted in:
  `ERROR: [Errno 10048] error while attempting to bind on address ('0.0.0.0', 8000): only one usage of each socket address is normally permitted`.
- **Root Cause**: A detached or background Python process from a prior test run was still holding port 8000 open in the background.
- **Engineering Fix**:
  1. Identified the active listener using PowerShell:
     `Get-NetTCPConnection -LocalPort 8000 | Select-Object OwningProcess`
  2. Terminated the orphaned process cleanly using `Stop-Process -Id <PID> -Force`.
  3. Documented port collision handling and diagnostic steps in the operations checklist.

---

## Log Entry 3: Dynamic TCP Receive Window Volatility in Passive Fingerprinting

- **Component**: `m2_enforcement/tracker.py`
- **What Broke**: The passive OS fingerprinting module was raising repeated false-positive `fingerprint_mismatch` alerts for legitimate hosts during active downloads.
- **Root Cause**: The initial implementation extracted the TCP window size from every observed TCP packet. Because TCP dynamic flow control and buffer scaling constantly adjust the window size throughout a session, the fingerprint changed continuously.
- **Engineering Fix**:
  1. Restricted TCP window recording strictly to connection initiation packets (TCP `SYN=1`, `ACK=0`).
  2. Retained the initial window size as the device baseline and ignored subsequent window fluctuations in established streams.
  3. Normalized IP TTL values by rounding up to standard operating system initial TTL buckets (`64` for Linux/macOS/Android, `128` for Windows, `255` for networking hardware).

---

## Log Entry 4: Network Interface Naming & Layer-2 Sniffing on Windows

- **Component**: `m1_arp_monitor/monitor.py` & `tools/simulate_arp_spoof.py`
- **What Broke**: Running the sniffer with default arguments failed with missing interface errors on Windows machines (`Interface 'eth0' not found`).
- **Root Cause**: Scapy defaults to `eth0` on POSIX systems, which does not exist in the Windows NDIS architecture (where interfaces use GUIDs like `\Device\NPF_{...}` or friendly aliases like `"Wi-Fi"`). Additionally, packet sniffing without Npcap installed in WinPcap-compatible mode cannot bind to physical adapters.
- **Engineering Fix**:
  1. Replaced the hardcoded `'eth0'` default with Scapy's dynamically detected `conf.iface`.
  2. Added fallback logic to retrieve the default route via `conf.route.route('0.0.0.0')`.
  3. Added explicit user-friendly error messages advising installation of Npcap in WinPcap-compatible mode and launching PowerShell with Administrator privileges.
