from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

rng = np.random.default_rng(42)
n = 1800
benign = pd.DataFrame({
    "event_count": rng.poisson(2, n),
    "failed_auth_count": rng.poisson(0.2, n),
    "unique_ports": rng.integers(1, 2, n),
    "unique_protocols": rng.integers(1, 2, n),
    "bytes_in": rng.integers(30, 2500, n),
    "bytes_out": rng.integers(40, 4000, n),
    "command_count": rng.integers(0, 3, n),
    "connection_rate": rng.uniform(0.01, 0.4, n),
    "auth_attempt_rate": rng.uniform(0, 0.2, n),
})
attack = pd.DataFrame({
    "event_count": rng.poisson(14, n),
    "failed_auth_count": rng.poisson(8, n),
    "unique_ports": rng.integers(2, 6, n),
    "unique_protocols": rng.integers(1, 5, n),
    "bytes_in": rng.integers(1000, 25000, n),
    "bytes_out": rng.integers(500, 12000, n),
    "command_count": rng.integers(3, 20, n),
    "connection_rate": rng.uniform(0.8, 8.0, n),
    "auth_attempt_rate": rng.uniform(0.5, 4.0, n),
})
df = pd.concat([benign.assign(label=0), attack.assign(label=1)], ignore_index=True)
X = df.drop(columns="label")
y = df["label"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

clf = RandomForestClassifier(n_estimators=250, random_state=42, class_weight="balanced")
clf.fit(X_train, y_train)
print(classification_report(y_test, clf.predict(X_test), digits=3))

anomaly = IsolationForest(n_estimators=200, contamination=0.08, random_state=42)
anomaly.fit(X_train)

joblib.dump({"classifier": clf, "anomaly": anomaly}, MODEL_DIR / "behavior_model.joblib")
print(f"Wrote {MODEL_DIR / 'behavior_model.joblib'}")
