from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import HoneypotEvent


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.init_schema()

    def init_schema(self) -> None:
        with self.lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ts TEXT NOT NULL,
                  src_ip TEXT NOT NULL,
                  src_port INTEGER,
                  protocol TEXT NOT NULL,
                  local_port INTEGER,
                  event_type TEXT,
                  device_persona TEXT,
                  bytes_in INTEGER,
                  bytes_out INTEGER,
                  auth_failed INTEGER,
                  command_count INTEGER,
                  request_path TEXT,
                  detail TEXT
                );
                CREATE TABLE IF NOT EXISTS assessments (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  event_id INTEGER NOT NULL,
                  ts TEXT NOT NULL,
                  ml_attack_probability REAL,
                  anomaly_score REAL,
                  threat_score REAL,
                  action TEXT,
                  reasons TEXT,
                  intel_json TEXT,
                  FOREIGN KEY(event_id) REFERENCES events(id)
                );
                CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
                """
            )
            self.conn.commit()

    def insert_event(self, event: HoneypotEvent) -> int:
        with self.lock:
            cur = self.conn.execute(
                """INSERT INTO events(
                  ts,src_ip,src_port,protocol,local_port,event_type,device_persona,
                  bytes_in,bytes_out,auth_failed,command_count,request_path,detail
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.ts,
                    event.src_ip,
                    event.src_port,
                    event.protocol,
                    event.local_port,
                    event.event_type,
                    event.device_persona,
                    event.bytes_in,
                    event.bytes_out,
                    event.auth_failed,
                    event.command_count,
                    event.request_path,
                    event.detail,
                ),
            )
            self.conn.commit()
            return int(cur.lastrowid)

    def count_recent_events(self, src_ip: str, seconds: int = 300) -> int:
        with self.lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE src_ip=? AND julianday(ts) >= julianday('now', ?) ",
                (src_ip, f"-{seconds} seconds"),
            ).fetchone()
            return int(row["n"] if row else 0)

    def insert_assessment(
        self,
        event_id: int,
        ts: str,
        ml_prob: float,
        anomaly: float,
        threat: float,
        action: str,
        reasons: list[str],
        intel: dict[str, Any],
    ) -> None:
        with self.lock:
            self.conn.execute(
                """INSERT INTO assessments(
                  event_id,ts,ml_attack_probability,anomaly_score,threat_score,
                  action,reasons,intel_json
                ) VALUES (?,?,?,?,?,?,?,?)""",
                (
                    event_id,
                    ts,
                    ml_prob,
                    anomaly,
                    threat,
                    action,
                    json.dumps(reasons),
                    json.dumps(intel),
                ),
            )
            self.conn.commit()

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self.lock:
            return list(self.conn.execute(sql, params).fetchall())
