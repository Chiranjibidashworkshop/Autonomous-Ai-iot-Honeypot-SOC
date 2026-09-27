from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    db_path: Path
    model_path: Path
    log_path: Path
    config_path: Path
    mitigation_enabled: bool
    dry_run: bool
    block_seconds: int
    min_block_score: float
    allow_private_blocking: bool
    whitelist_ips: str
    abuseipdb_api_key: str
    virustotal_api_key: str
    geoip_enabled: bool
    demo_mode: bool
    demo_event_interval: float


def load_settings() -> Settings:
    return Settings(
        db_path=BASE_DIR / os.getenv("DB_PATH", "data/events.db"),
        model_path=BASE_DIR / os.getenv("MODEL_PATH", "models/behavior_model.joblib"),
        log_path=BASE_DIR / os.getenv("LOG_PATH", "logs/honeypot.log"),
        config_path=BASE_DIR / os.getenv("CONFIG_PATH", "config.yaml"),
        mitigation_enabled=env_bool("MITIGATION_ENABLED", False),
        dry_run=env_bool("DRY_RUN", True),
        block_seconds=int(os.getenv("BLOCK_SECONDS", "900")),
        min_block_score=float(os.getenv("MIN_BLOCK_SCORE", "0.92")),
        allow_private_blocking=env_bool("ALLOW_PRIVATE_BLOCKING", False),
        whitelist_ips=os.getenv("WHITELIST_IPS", "127.0.0.1"),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
        geoip_enabled=env_bool("GEOIP_ENABLED", True),
        demo_mode=env_bool("DEMO_MODE", True),
        demo_event_interval=float(os.getenv("DEMO_EVENT_INTERVAL", "1.2")),
    )


def load_yaml(settings: Settings) -> dict[str, Any]:
    with settings.config_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)
