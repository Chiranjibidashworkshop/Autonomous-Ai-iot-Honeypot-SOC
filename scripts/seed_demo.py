from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.iot_honeypot.config import load_settings, load_yaml
from src.iot_honeypot.db import Database
from src.iot_honeypot.mitigation import IPTablesMitigator
from src.iot_honeypot.ml_profiler import BehavioralProfiler
from src.iot_honeypot.models import HoneypotEvent
from src.iot_honeypot.pipeline import DetectionPipeline
from src.iot_honeypot.threat_intel import DEMO_INTEL, ThreatIntel


def main() -> None:
    settings = load_settings()
    config = load_yaml(settings)
    db = Database(settings.db_path)
    if db.query("SELECT id FROM events LIMIT 1"):
        print("Demo database already contains telemetry; skipping seed.")
        return

    profiler = BehavioralProfiler(settings.model_path)
    intel = ThreatIntel(demo_mode=True)
    mitigator = IPTablesMitigator(False, True, settings.block_seconds, False, settings.whitelist_ips)
    pipeline = DetectionPipeline(
        db,
        profiler,
        intel,
        mitigator,
        (min(float(config["policy"]["block_score"]), 0.82) if settings.demo_mode else float(config["policy"]["block_score"])),
        float(config["policy"]["investigate_score"]),
        int(config["policy"]["require_repeated_events"]),
    )

    profiles = [
        ("HTTP", 8080, "camera", "/admin/login", 0, 1),
        ("SSH", 2222, "router", "admin", 2, 2),
        ("TELNET", 2323, "router", "login admin", 2, 2),
        ("MQTT", 1883, "smart_plug", "topic=sensors/#", 1, 1),
        ("FTP", 2121, "nas", "USER admin", 2, 2),
    ]
    ips = list(DEMO_INTEL)

    for i in range(64):
        ip = ips[i % len(ips)]
        protocol, port, persona, detail, failed, commands = profiles[i % len(profiles)]
        event = HoneypotEvent(
            src_ip=ip,
            src_port=35000 + i,
            protocol=protocol,
            local_port=port,
            event_type="http_request" if protocol == "HTTP" else "session",
            device_persona=persona,
            bytes_in=500 + (i * 37) % 7000,
            bytes_out=200 + (i * 53) % 4000,
            auth_failed=failed if i % 3 else 0,
            command_count=commands,
            request_path=detail if protocol == "HTTP" else "",
            detail=detail,
        )
        pipeline.process(event)

    print("Seeded 64 synthetic SOC events for presentation mode.")


if __name__ == "__main__":
    main()
