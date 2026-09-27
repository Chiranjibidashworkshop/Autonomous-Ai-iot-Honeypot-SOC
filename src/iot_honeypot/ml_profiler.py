from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from time import time

import joblib
import numpy as np
import pandas as pd

FEATURE_NAMES = [
    "event_count",
    "failed_auth_count",
    "unique_ports",
    "unique_protocols",
    "bytes_in",
    "bytes_out",
    "command_count",
    "connection_rate",
    "auth_attempt_rate",
]


@dataclass
class Profile:
    events: deque
    ports: set[int]
    protocols: set[str]
    failed_auth: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    commands: int = 0


class BehavioralProfiler:
    def __init__(self, model_path: Path) -> None:
        self.model_path = model_path
        bundle = joblib.load(model_path)
        self.classifier = bundle["classifier"]
        self.anomaly = bundle["anomaly"]
        self.profiles: dict[str, Profile] = defaultdict(
            lambda: Profile(events=deque(maxlen=200), ports=set(), protocols=set())
        )

    def observe(self, event: dict) -> tuple[float, float, dict[str, float]]:
        now = time()
        ip = event["src_ip"]
        p = self.profiles[ip]
        p.events.append(now)
        # Keep rolling 5-minute state.
        while p.events and now - p.events[0] > 300:
            p.events.popleft()
        p.ports.add(int(event["local_port"]))
        p.protocols.add(event["protocol"])
        p.failed_auth += int(event.get("auth_failed", 0))
        p.bytes_in += int(event.get("bytes_in", 0))
        p.bytes_out += int(event.get("bytes_out", 0))
        p.commands += int(event.get("command_count", 0))

        window = max(1.0, now - p.events[0]) if p.events else 1.0
        event_count = len(p.events)
        failed_rate = p.failed_auth / 5.0
        connection_rate = event_count / window
        auth_attempt_rate = p.failed_auth / window
        values = np.array(
            [[
                event_count,
                p.failed_auth,
                len(p.ports),
                len(p.protocols),
                p.bytes_in,
                p.bytes_out,
                p.commands,
                connection_rate,
                auth_attempt_rate,
            ]],
            dtype=float,
        )
        feature_frame = pd.DataFrame(values, columns=FEATURE_NAMES)
        attack_prob = float(self.classifier.predict_proba(feature_frame)[0][1])
        raw = float(self.anomaly.decision_function(feature_frame)[0])
        # Convert Isolation Forest output to intuitive [0,1] anomaly signal.
        anomaly_score = float(np.clip(0.5 - raw, 0.0, 1.0))
        features = dict(zip(FEATURE_NAMES, values[0].tolist()))
        return attack_prob, anomaly_score, features
