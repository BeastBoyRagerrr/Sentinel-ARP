"""FastAPI monitoring and management dashboard for Sentinel-ARP."""

from contextlib import asynccontextmanager
import os
from typing import Any
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from common.db import get_alerts, get_devices, get_policies, init_db, set_policy


def get_db_path() -> str:
    """Return the database path from SENTINEL_DB or default to sentinel.db."""
    return os.getenv("SENTINEL_DB", "sentinel.db")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager that initializes the SQLite database on startup."""
    init_db(get_db_path())
    yield


app = FastAPI(
    title="Sentinel-ARP Dashboard",
    description="Network monitoring, traffic enforcement, and alert management",
    lifespan=lifespan,
)


class PolicyRequest(BaseModel):
    action: str


HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel-ARP Dashboard</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-hover: #0284c7;
      --alert-critical-bg: #451a1a;
      --alert-critical-border: #ef4444;
      --alert-critical-text: #fca5a5;
      --alert-warning-bg: #453011;
      --alert-warning-border: #f59e0b;
      --alert-warning-text: #fcd34d;
      --alert-info-bg: #27272a;
      --alert-info-border: #71717a;
      --alert-info-text: #e4e4e7;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      padding: 24px;
      line-height: 1.5;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
      flex-wrap: wrap;
      gap: 16px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .logo-badge {
      background: linear-gradient(135deg, #0284c7, #38bdf8);
      color: white;
      font-weight: 700;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 16px;
      letter-spacing: 0.5px;
    }

    h1 {
      font-size: 22px;
      font-weight: 600;
    }

    .stats-bar {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }

    .stat-card {
      background-color: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 16px 20px;
    }

    .stat-title {
      font-size: 13px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }

    .stat-value {
      font-size: 26px;
      font-weight: 700;
      color: var(--text);
    }

    .refresh-time {
      font-size: 16px;
      font-weight: 500;
      color: var(--accent);
    }

    section {
      background-color: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 28px;
    }

    h2 {
      font-size: 18px;
      margin-bottom: 16px;
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 14px;
    }

    th, td {
      padding: 12px 14px;
      border-bottom: 1px solid var(--card-border);
    }

    th {
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 12px;
      letter-spacing: 0.5px;
    }

    tr:last-child td {
      border-bottom: none;
    }

    .bandwidth-container {
      width: 100%;
      min-width: 140px;
    }

    .bandwidth-text {
      font-size: 12px;
      margin-bottom: 4px;
      font-family: monospace;
      color: var(--text-muted);
    }

    .bar-bg {
      background-color: #334155;
      height: 8px;
      border-radius: 4px;
      width: 100%;
      overflow: hidden;
    }

    .bar-fill {
      background: linear-gradient(90deg, #0284c7, #38bdf8);
      height: 100%;
      border-radius: 4px;
      transition: width 0.3s ease;
    }

    .policy-tag {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }

    .policy-allow {
      background-color: #064e3b;
      color: #6ee7b7;
      border: 1px solid #059669;
    }

    .policy-block {
      background-color: #7f1d1d;
      color: #fca5a5;
      border: 1px solid #dc2626;
    }

    .policy-none {
      background-color: #27272a;
      color: #a1a1aa;
      border: 1px solid #52525b;
    }

    .alerts-container {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .alert-row {
      padding: 14px 16px;
      border-radius: 6px;
      border-left: 4px solid;
      display: grid;
      grid-template-columns: 100px 180px 180px 1fr;
      align-items: center;
      gap: 14px;
      font-size: 14px;
    }

    .alert-row.CRITICAL {
      background-color: var(--alert-critical-bg);
      border-left-color: var(--alert-critical-border);
      color: var(--alert-critical-text);
    }

    .alert-row.WARNING, .alert-row.WARN {
      background-color: var(--alert-warning-bg);
      border-left-color: var(--alert-warning-border);
      color: var(--alert-warning-text);
    }

    .alert-row.INFO {
      background-color: var(--alert-info-bg);
      border-left-color: var(--alert-info-border);
      color: var(--alert-info-text);
    }

    .alert-severity {
      font-weight: 700;
      text-transform: uppercase;
      font-size: 12px;
      letter-spacing: 0.5px;
    }

    .alert-time {
      font-size: 12px;
      opacity: 0.8;
      font-family: monospace;
    }

    .alert-type {
      font-weight: 600;
    }

    .alert-detail {
      word-break: break-word;
    }

    .no-data {
      padding: 24px;
      text-align: center;
      color: var(--text-muted);
      font-style: italic;
      background-color: rgba(51, 65, 85, 0.2);
      border-radius: 6px;
      border: 1px dashed var(--card-border);
    }

    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    @media (max-width: 768px) {
      .alert-row {
        grid-template-columns: 1fr;
        gap: 6px;
      }
      table {
        display: block;
        overflow-x: auto;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <span class="logo-badge">SENTINEL-ARP</span>
        <h1>Security & Traffic Engine</h1>
      </div>
    </header>

    <div class="stats-bar">
      <div class="stat-card">
        <div class="stat-title">Active Devices</div>
        <div class="stat-value" id="device-count">0</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Total Alerts</div>
        <div class="stat-value" id="alert-count">0</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Last Refresh</div>
        <div class="refresh-time" id="last-refresh">Connecting...</div>
      </div>
    </div>

    <section>
      <h2>Devices</h2>
      <div id="devices-wrapper">
        <div class="no-data">No data yet (waiting for discovery)</div>
      </div>
    </section>

    <section>
      <h2>Alerts (Newest First)</h2>
      <div id="alerts-wrapper">
        <div class="no-data">No data yet (no alerts logged)</div>
      </div>
    </section>
  </div>

  <script>
    function formatBytes(bytes) {
      if (bytes === 0 || bytes === null || bytes === undefined) return "0 B";
      const k = 1024;
      const sizes = ["B", "KB", "MB", "GB", "TB"];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return (bytes / Math.pow(k, i)).toFixed(1) + " " + sizes[i];
    }

    function formatTimestamp(ts) {
      if (!ts) return "-";
      try {
        const dt = new Date(ts);
        if (isNaN(dt.getTime())) return ts;
        return dt.toLocaleTimeString() + " (" + dt.toLocaleDateString() + ")";
      } catch (e) {
        return ts;
      }
    }

    async function fetchStatus() {
      try {
        const response = await fetch("/status");
        if (!response.ok) {
          throw new Error("HTTP error " + response.status);
        }
        const data = await response.json();
        renderDashboard(data);
      } catch (err) {
        console.error("Failed to load status:", err);
        const refreshElem = document.getElementById("last-refresh");
        if (refreshElem) {
          refreshElem.textContent = "Error updating (" + new Date().toLocaleTimeString() + ")";
        }
      }
    }

    function renderDashboard(data) {
      const devices = data.devices || [];
      const alerts = data.alerts || [];
      const policies = data.policies || [];

      // Update Header Stats
      document.getElementById("device-count").textContent = devices.length;
      document.getElementById("alert-count").textContent = alerts.length;
      document.getElementById("last-refresh").textContent = new Date().toLocaleTimeString();

      // Build Policies Map
      const policyMap = {};
      policies.forEach(p => {
        if (p && p.ip) {
          policyMap[p.ip] = (p.action || "").toLowerCase();
        }
      });

      // Render Devices Table
      const devicesWrapper = document.getElementById("devices-wrapper");
      if (devices.length === 0) {
        devicesWrapper.innerHTML = '<div class="no-data">No data yet (no devices discovered)</div>';
      } else {
        let maxBytes = 0;
        devices.forEach(d => {
          const b = Number(d.bandwidth_bytes) || 0;
          if (b > maxBytes) maxBytes = b;
        });
        if (maxBytes === 0) maxBytes = 1;

        let tableHtml = '<table>' +
          '<thead><tr>' +
          '<th>IP Address</th>' +
          '<th>MAC Address</th>' +
          '<th>Fingerprint</th>' +
          '<th>Bandwidth Usage</th>' +
          '<th>Last Seen</th>' +
          '<th>Policy</th>' +
          '</tr></thead><tbody>';

        devices.forEach(d => {
          const bytes = Number(d.bandwidth_bytes) || 0;
          const pct = Math.min(100, Math.round((bytes / maxBytes) * 100));
          const p = policyMap[d.ip] || "none";
          let policyClass = "policy-none";
          let policyLabel = "DEFAULT";
          if (p === "allow") {
            policyClass = "policy-allow";
            policyLabel = "ALLOW";
          } else if (p === "block") {
            policyClass = "policy-block";
            policyLabel = "BLOCK";
          } else if (p !== "none") {
            policyLabel = p.toUpperCase();
          }

          tableHtml += '<tr>' +
            '<td class="mono"><strong>' + (d.ip || "-") + '</strong></td>' +
            '<td class="mono">' + (d.mac || "-") + '</td>' +
            '<td>' + (d.fingerprint || '<span style="color:#64748b">Unknown</span>') + '</td>' +
            '<td>' +
              '<div class="bandwidth-container">' +
                '<div class="bandwidth-text">' + formatBytes(bytes) + ' (' + bytes.toLocaleString() + ' B)</div>' +
                '<div class="bar-bg"><div class="bar-fill" style="width: ' + pct + '%"></div></div>' +
              '</div>' +
            '</td>' +
            '<td>' + formatTimestamp(d.last_seen) + '</td>' +
            '<td><span class="policy-tag ' + policyClass + '">' + policyLabel + '</span></td>' +
            '</tr>';
        });

        tableHtml += '</tbody></table>';
        devicesWrapper.innerHTML = tableHtml;
      }

      // Render Alerts List (newest first)
      const alertsWrapper = document.getElementById("alerts-wrapper");
      if (alerts.length === 0) {
        alertsWrapper.innerHTML = '<div class="no-data">No data yet (no alerts recorded)</div>';
      } else {
        let alertsHtml = '<div class="alerts-container">';
        alerts.forEach(a => {
          const severity = (a.severity || "INFO").toUpperCase();
          let sevClass = "INFO";
          if (severity === "CRITICAL") sevClass = "CRITICAL";
          else if (severity === "WARNING" || severity === "WARN") sevClass = "WARNING";

          alertsHtml += '<div class="alert-row ' + sevClass + '">' +
            '<div class="alert-severity">' + severity + '</div>' +
            '<div class="alert-type mono">' + (a.type || "ALERT") + '</div>' +
            '<div class="alert-time">' + formatTimestamp(a.timestamp) + '</div>' +
            '<div class="alert-detail">' + (a.detail || "-") + '</div>' +
            '</div>';
        });
        alertsHtml += '</div>';
        alertsWrapper.innerHTML = alertsHtml;
      }
    }

    // Initial fetch and auto-refresh every 3 seconds
    fetchStatus();
    setInterval(fetchStatus, 3000);
  </script>
</body>
</html>
"""


@app.get("/health")
def health() -> dict[str, bool]:
    """Healthcheck endpoint."""
    return {"ok": True}


@app.get("/status")
def status_endpoint() -> dict[str, list[dict[str, Any]]]:
    """Return network devices, alerts (newest first, limit 50), and active policies."""
    db_path = get_db_path()
    devices = get_devices(path=db_path)
    alerts = get_alerts(limit=50, path=db_path)
    policies = get_policies(path=db_path)
    return {
        "devices": devices,
        "alerts": alerts,
        "policies": policies,
    }


@app.post("/policy/{ip}")
def set_policy_endpoint(ip: str, payload: PolicyRequest) -> dict[str, Any]:
    """
    Set enforcement policy for a given IP address.

    Accepts {'action': 'allow'} or {'action': 'block'}. Returns 400 for any other action.
    """
    action = payload.action.strip().lower()
    if action not in ("allow", "block"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid action. Allowed actions are 'allow' or 'block'.",
        )
    db_path = get_db_path()
    set_policy(ip, action, path=db_path)
    return {"ok": True, "ip": ip, "action": action}


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    """Serve the single-page monitoring dashboard."""
    return HTMLResponse(content=HTML_CONTENT, status_code=200)
