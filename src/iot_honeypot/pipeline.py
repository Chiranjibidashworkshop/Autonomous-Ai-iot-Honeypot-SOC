from __future__ import annotations

import logging
from typing import Any

from .db import Database
from .mitigation import IPTablesMitigator
from .ml_profiler import BehavioralProfiler
from .models import HoneypotEvent
from .threat_intel import ThreatIntel

LOGGER = logging.getLogger(__name__)


class DetectionPipeline:
    def __init__(self, db: Database, profiler: BehavioralProfiler, intel: ThreatIntel, mitigator: IPTablesMitigator, block_score: float, investigate_score: float, repeat_events: int):
        self.db = db
        self.profiler = profiler
        self.intel = intel
        self.mitigator = mitigator
        self.block_score = block_score
        self.investigate_score = investigate_score
        self.repeat_events = repeat_events

    def process(self, event: HoneypotEvent) -> dict[str, Any]:
        event_id = self.db.insert_event(event)
        event_dict = event.to_dict()
        ml_prob, anomaly, features = self.profiler.observe(event_dict)
        ti = self.intel.lookup(event.src_ip)

        threat_score = min(1.0, 0.72 * ml_prob + 0.18 * anomaly + 0.10 * (min(ti.get("abuse_score", 0), 100) / 100.0))
        recent_events = self.db.count_recent_events(event.src_ip)
        reasons: list[str] = []
        if ml_prob >= 0.75:
            reasons.append("ML classifier indicates attack-like behavior")
        if anomaly >= 0.55:
            reasons.append("Behavior is anomalous for the observed baseline")
        if ti.get("abuse_score", 0) >= 50:
            reasons.append("Threat intelligence reports significant abuse confidence")
        if recent_events >= self.repeat_events:
            reasons.append(f"Repeated source observed {recent_events} times in rolling window")

        if threat_score >= self.block_score and recent_events >= self.repeat_events and event.src_ip not in {"127.0.0.1", "::1"}:
            action = "BLOCK"
        elif threat_score >= self.investigate_score:
            action = "INVESTIGATE"
        else:
            action = "MONITOR"

        mitigation_message = ""
        if action == "BLOCK":
            result = self.mitigator.block(event.src_ip, "; ".join(reasons) or "high threat score")
            mitigation_message = result.message
            if result.action == "BLOCK_SKIPPED" and not (self.intel.demo_mode and ti.get("demo")):
                action = "INVESTIGATE"

        self.db.insert_assessment(event_id, event.ts, ml_prob, anomaly, threat_score, action, reasons, ti)
        LOGGER.info("event=%s ip=%s protocol=%s action=%s threat=%.3f", event_id, event.src_ip, event.protocol, action, threat_score)
        return {
            "event_id": event_id,
            "ml_probability": ml_prob,
            "anomaly": anomaly,
            "threat_score": threat_score,
            "action": action,
            "reasons": reasons,
            "intel": ti,
            "features": features,
            "mitigation": mitigation_message,
        }
