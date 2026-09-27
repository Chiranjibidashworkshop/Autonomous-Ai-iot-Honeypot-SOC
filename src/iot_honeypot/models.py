from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class HoneypotEvent:
    src_ip: str
    src_port: int
    protocol: str
    local_port: int
    event_type: str
    device_persona: str
    bytes_in: int = 0
    bytes_out: int = 0
    auth_failed: int = 0
    command_count: int = 0
    request_path: str = ""
    detail: str = ""
    ts: str = ""

    def __post_init__(self) -> None:
        if not self.ts:
            self.ts = utc_now()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
