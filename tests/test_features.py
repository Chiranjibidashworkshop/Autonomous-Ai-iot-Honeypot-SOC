from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.iot_honeypot.threat_intel import ThreatIntel


def test_private_ips_are_not_lookup_targets():
    assert ThreatIntel.safe_target("127.0.0.1") is False
    assert ThreatIntel.safe_target("192.168.1.10") is False
    assert ThreatIntel.safe_target("8.8.8.8") is True
