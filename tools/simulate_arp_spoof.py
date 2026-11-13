# For use only on a network operated by the project team, to test our own ARP spoofing detector.
"""Simulate ARP spoofing for Sentinel-ARP coursework detection validation."""

from pathlib import Path
import sys

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tools.generate_test_arp_traffic import main

if __name__ == "__main__":
    main()
