from __future__ import annotations

import asyncio
import logging
import random
from pathlib import Path
from threading import Lock

from .config import load_settings, load_yaml
from .db import Database
from .listeners import BannerListener, HTTPListener, MQTTListener
from .mitigation import IPTablesMitigator
from .ml_profiler import BehavioralProfiler
from .models import HoneypotEvent
from .pipeline import DetectionPipeline
from .threat_intel import DEMO_INTEL, ThreatIntel


async def demo_traffic_loop(pipeline: DetectionPipeline, interval: float) -> None:
    protocols = [
        ("HTTP", 8080, "camera", "http_request", 0, 1, "/admin/login"),
        ("SSH", 2222, "router", "session", 2, 1, ""),
        ("TELNET", 2323, "router", "session", 2, 1, "login admin"),
        ("MQTT", 1883, "smart_plug", "mqtt_connect", 1, 1, "topic=sensors/#"),
        ("FTP", 2121, "nas", "session", 2, 1, "USER admin"),
    ]
    ips = list(DEMO_INTEL)
    idx = 0
    while True:
        ip = ips[idx % len(ips)]
        protocol, port, persona, event_type, failed, commands, detail = protocols[idx % len(protocols)]
        burst = (idx % 4) >= 1
        event = HoneypotEvent(
            src_ip=ip,
            src_port=random.randint(32000, 62000),
            protocol=protocol,
            local_port=port,
            event_type=event_type,
            device_persona=persona,
            bytes_in=random.randint(220, 3200) if burst else random.randint(60, 700),
            bytes_out=random.randint(100, 2400),
            auth_failed=failed if burst else 0,
            command_count=commands if burst else 1,
            request_path=detail if protocol == "HTTP" else "",
            detail=detail,
        )
        try:
            result = await asyncio.to_thread(pipeline.process, event)
            logging.getLogger(__name__).info(
                "[DEMO] event_id=%s src=%s proto=%s threat=%.3f action=%s",
                result["event_id"], ip, protocol, result["threat_score"], result["action"],
            )
        except Exception:
            logging.getLogger(__name__).exception("Demo telemetry generation failed")
        idx += 1
        await asyncio.sleep(max(0.4, interval))


def configure_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not root.handlers:
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(console)
        root.addHandler(file_handler)


async def main() -> None:
    settings = load_settings()
    configure_logging(settings.log_path)
    config = load_yaml(settings)

    db = Database(settings.db_path)
    profiler = BehavioralProfiler(settings.model_path)
    intel = ThreatIntel(settings.abuseipdb_api_key, settings.virustotal_api_key, settings.geoip_enabled, settings.demo_mode)
    mitigator = IPTablesMitigator(
        settings.mitigation_enabled,
        settings.dry_run,
        settings.block_seconds,
        settings.allow_private_blocking,
        settings.whitelist_ips,
    )
    pipeline = DetectionPipeline(
        db,
        profiler,
        intel,
        mitigator,
        (min(float(config["policy"]["block_score"]), 0.82) if settings.demo_mode else float(config["policy"]["block_score"])),
        float(config["policy"]["investigate_score"]),
        int(config["policy"]["require_repeated_events"]),
    )

    process_lock = Lock()

    async def emit(event: HoneypotEvent) -> None:
        def run() -> dict:
            with process_lock:
                return pipeline.process(event)
        result = await asyncio.to_thread(run)
        logging.getLogger(__name__).info(
            "event_id=%s src=%s proto=%s score=%.3f action=%s",
            result["event_id"], event.src_ip, event.protocol, result["threat_score"], result["action"],
        )

    srv = config["server"]
    lst = config["listeners"]
    listeners = [
        HTTPListener(srv["bind"], int(srv["http_port"]), lst["http_persona"], emit),
        BannerListener(srv["bind"], int(srv["ssh_port"]), lst["ssh_persona"], emit, banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11\r\n", protocol="SSH"),
        BannerListener(srv["bind"], int(srv["telnet_port"]), lst["telnet_persona"], emit, banner="EdgeLink login service ready\r\nlogin: ", protocol="TELNET"),
        MQTTListener(srv["bind"], int(srv["mqtt_port"]), lst["mqtt_persona"], emit),
        BannerListener(srv["bind"], int(srv["ftp_port"]), lst["ftp_persona"], emit, banner="220 DataHarbor NAS FTP ready\r\n", protocol="FTP"),
    ]

    logging.getLogger(__name__).info("============================================================")
    logging.getLogger(__name__).info("AUTONOMOUS AI-DRIVEN IoT HONEYPOT SOC")
    logging.getLogger(__name__).info("DEMO_MODE=%s MITIGATION_ENABLED=%s DRY_RUN=%s", settings.demo_mode, settings.mitigation_enabled, settings.dry_run)
    logging.getLogger(__name__).info("============================================================")

    tasks = [asyncio.create_task(x.start()) for x in listeners]
    if settings.demo_mode:
        tasks.append(asyncio.create_task(demo_traffic_loop(pipeline, settings.demo_event_interval)))
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
