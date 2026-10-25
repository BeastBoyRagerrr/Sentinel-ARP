"""Configuration constants for Sentinel-ARP M2 Enforcement module."""

from __future__ import annotations

# Fair-usage bandwidth constraints
FAIR_USAGE_BYTES: int = 50 * 1024 * 1024  # 50 MB
FAIR_USAGE_WINDOW_SECONDS: int = 300      # 300 seconds (5 minutes)
