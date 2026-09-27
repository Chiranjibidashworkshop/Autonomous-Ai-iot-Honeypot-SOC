from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.iot_honeypot.mitigation import IPTablesMitigator


def test_dry_run_never_executes_block():
    m = IPTablesMitigator(False, True, 60, False, "127.0.0.1,192.168.0.0/16")
    result = m.block("8.8.8.8", "unit-test")
    assert result.applied is False
    assert result.action == "BLOCK"


def test_private_ip_is_protected():
    m = IPTablesMitigator(False, True, 60, False, "127.0.0.1,192.168.0.0/16")
    result = m.block("192.168.1.10", "unit-test")
    assert result.action == "BLOCK_SKIPPED"
