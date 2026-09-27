# Autonomous AI-Driven IoT Honeypot SOC & Automated Mitigation Platform

A presentation-ready cybersecurity research platform that combines:

- low-interaction IoT deception for HTTP, SSH-banner, Telnet, MQTT and FTP
- simulated edge-device personas (camera, router, smart plug, NAS)
- SQLite security telemetry
- Random Forest behavioral classification
- Isolation Forest anomaly detection
- optional AbuseIPDB / VirusTotal / GeoIP enrichment
- policy decisions: MONITOR / INVESTIGATE / BLOCK
- guarded Linux `iptables` mitigation (disabled by default)
- a live Streamlit SOC console
- **built-in synthetic demo telemetry**, so the dashboard is populated immediately for demonstrations
- Windows-safe startup with no PowerShell heredoc commands and no `py` launcher dependency

## The one-click experience

### Windows / VS Code

1. Extract this folder.
2. Open the folder in VS Code.
3. Double-click **`START_HERE.bat`**.
4. The launcher automatically:
   - finds Python 3.11+
   - creates `.venv`
   - installs dependencies
   - creates a safe `.env`
   - trains the ML model
   - starts the honeypot
   - starts Streamlit
   - opens `http://127.0.0.1:8501`
5. The dashboard immediately displays **synthetic/demo SOC telemetry**.

You do **not** need to manually paste multi-line Python into PowerShell.

### VS Code task

Open the folder, then:

**Terminal → Run Task → `ONE-CLICK SHOWCASE`**

## Showcase mode vs live lab

### Showcase mode (default)

`START_HERE.bat` forces:

```text
DEMO_MODE=true
MITIGATION_ENABLED=false
DRY_RUN=true
```

The honeypot continuously creates synthetic telemetry using RFC-reserved documentation IPs. The dashboard labels this as **SYNTHETIC DEMO TELEMETRY**.

### Live lab mode

Use **`START_LIVE_LAB.bat`** after the one-click environment has been prepared. This sets:

```text
DEMO_MODE=false
MITIGATION_ENABLED=false
DRY_RUN=true
```

Now the dashboard waits for real lab traffic on:

```text
HTTP     8080
SSH      2222
Telnet   2323
MQTT     1883
FTP      2121
```

You can generate local test traffic with:

```text
python scripts/generate_lab_traffic.py
```

## Dashboard

The Streamlit console provides:

- live SOC header and operational mode
- total attack events
- unique attacker count
- policy block decisions
- high-risk events
- attack map using synthetic/available geolocation
- attack-type donut chart
- top attacking countries
- recent attack table
- attacker profiles
- ML and anomaly scores
- threat-intelligence panel
- live system logs
- honeypot service status

The dashboard refreshes automatically every 2.5 seconds.

## Platform architecture

```text
                  ┌─────────────────────────────────────┐
                  │       IoT DECEPTION LAYER            │
                  │ HTTP | SSH | Telnet | MQTT | FTP    │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                           ┌──────────────────┐
                           │ SQLite Telemetry │
                           └────────┬─────────┘
                                    │
                 ┌──────────────────┴──────────────────┐
                 │                                     │
                 ▼                                     ▼
        ┌──────────────────┐                 ┌──────────────────┐
        │ Behavioral ML   │                 │ Threat Intel      │
        │ RF + Isolation  │                 │ AbuseIPDB / VT    │
        └────────┬─────────┘                 └────────┬─────────┘
                 └──────────────────┬─────────────────┘
                                    ▼
                         ┌────────────────────┐
                         │ Autonomous Policy  │
                         │ MONITOR / INVEST.  │
                         │ / BLOCK            │
                         └─────────┬──────────┘
                                   │
                         ┌─────────▼─────────┐
                         │ Linux netfilter   │
                         │ iptables (guarded)│
                         └─────────┬─────────┘
                                   │
                                   ▼
                          ┌──────────────────┐
                          │ Streamlit SOC    │
                          │ live monitoring  │
                          └──────────────────┘
```

## Safety

The presentation build is **not an Internet-facing honeypot**. Default mitigation is:

```text
MITIGATION_ENABLED=false
DRY_RUN=true
```

Real `iptables` enforcement is intended for an isolated Linux/Ubuntu/WSL2 environment after reviewing the allowlist and thresholds.

## Why the demo is useful

A clean deployment should not depend on somebody attacking the honeypot during a project presentation. The demo stream provides deterministic, clearly labeled synthetic activity so the SOC interface is populated immediately. When you switch to live-lab mode, the same dashboard can visualize real authorized test traffic.

## Stop / reset

- `STOP_PROJECT.bat` — stop the two project processes started by the launcher.
- `RESET_SHOWCASE.bat` — stop the project and delete the local demo database/logs so the next showcase starts clean.

## Important distinction

The visual dashboard is a real Streamlit implementation in `src/soc_dashboard/app.py`; synthetic telemetry is real application data written through the same pipeline/database that live lab traffic uses. Synthetic data is explicitly labeled and should not be presented as measurements from real-world attackers.
