from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv
from streamlit_autorefresh import st_autorefresh

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")
DB_PATH = ROOT / os.getenv("DB_PATH", "data/events.db")
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() in {"1", "true", "yes", "on"}
MITIGATION_ENABLED = os.getenv("MITIGATION_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
DRY_RUN = os.getenv("DRY_RUN", "true").lower() in {"1", "true", "yes", "on"}

st.set_page_config(page_title="Autonomous IoT Honeypot SOC", page_icon="🍯", layout="wide", initial_sidebar_state="expanded")
st_autorefresh(interval=2500, key="soc_live_refresh")

CSS = """
<style>
[data-testid="stAppViewContainer"] { background: #07111a; }
[data-testid="stHeader"] { background: rgba(0,0,0,0); }
.block-container { max-width: 1600px; padding-top: 1.3rem; padding-bottom: 1.5rem; }
.hero { border: 1px solid #163a52; background: linear-gradient(135deg,#071723,#0a1824 55%,#062331); border-radius: 18px; padding: 22px 26px; box-shadow: 0 0 35px rgba(0,195,255,.08); }
.hero h1 { margin: 0; font-size: 2.2rem; letter-spacing: .02em; color: #f4fbff; }
.hero p { margin: 8px 0 0; color: #98afbf; }
.badge { display:inline-block; padding:5px 10px; border-radius:999px; margin-right:7px; font-size:.82rem; font-weight:700; }
.badge-green { background:#073d31; color:#39f2b2; border:1px solid #0a6c54; }
.badge-cyan { background:#073246; color:#41d9ff; border:1px solid #0f6c8b; }
.badge-amber { background:#49310a; color:#ffc763; border:1px solid #8e5f10; }
.card { background: linear-gradient(180deg,#0a1b28,#08151f); border:1px solid #17374a; border-radius:16px; padding:16px; height:100%; }
.small { color:#89a2b4; font-size:.84rem; }
.value { color:#f7fcff; font-size:2rem; font-weight:800; margin-top:3px; }
.section { color:#ebf5fa; font-size:1.05rem; font-weight:750; margin: 10px 0 8px; }
.status-dot { width:10px; height:10px; border-radius:50%; display:inline-block; background:#24e6a5; box-shadow:0 0 12px #24e6a5; margin-right:7px; }
hr { border-color:#163a52; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


def service_open(port: int) -> bool:
    log_path = ROOT / os.getenv("LOG_PATH", "logs/honeypot.log")
    if not log_path.exists():
        return False
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return f":{port}" in text and "listening on" in text


def load_events() -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(
            """
            SELECT e.*, a.ml_attack_probability, a.anomaly_score, a.threat_score,
                   a.action, a.reasons, a.intel_json
            FROM events e
            LEFT JOIN assessments a ON a.event_id=e.id
            ORDER BY e.id DESC
            LIMIT 1000
            """,
            conn,
        )
    finally:
        conn.close()
    return df


def intel_rows(events: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in events.dropna(subset=["intel_json"]).iterrows():
        try:
            intel = json.loads(row["intel_json"] or "{}")
        except Exception:
            continue
        geo = intel.get("geo") or {}
        rows.append(
            {
                "IP": row["src_ip"],
                "Country": geo.get("country", "Unknown"),
                "City": geo.get("city", "-"),
                "ASN": geo.get("asn", "-"),
                "Organization": geo.get("org", "-"),
                "Abuse score": intel.get("abuse_score", 0),
                "Reports": intel.get("abuse_total_reports", 0),
                "VT malicious": intel.get("vt_malicious", 0),
                "Sources": ", ".join(intel.get("sources", [])),
            }
        )
    return pd.DataFrame(rows).drop_duplicates("IP") if rows else pd.DataFrame()


def render_metric(label: str, value: str, hint: str) -> None:
    st.markdown(f'<div class="card"><div class="small">{label}</div><div class="value">{value}</div><div class="small">{hint}</div></div>', unsafe_allow_html=True)


st.markdown(
    f"""
    <div class="hero">
      <div><span class="badge badge-green"><span class="status-dot"></span>SYSTEM ACTIVE</span>
      <span class="badge badge-cyan">AI / ML SOC</span>
      <span class="badge badge-amber">{'SYNTHETIC DEMO TELEMETRY' if DEMO_MODE else 'LIVE LAB TELEMETRY'}</span></div>
      <h1>🍯 Autonomous AI-Driven IoT Honeypot SOC</h1>
      <p>Low-interaction IoT deception · behavioral ML · threat intelligence · policy-driven mitigation · Linux netfilter ready</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---- Sidebar ----
st.sidebar.markdown("## SOC Control Center")
st.sidebar.write("Live telemetry refreshes every 2.5 seconds.")
mode = "DEMO / DRY-RUN" if DEMO_MODE or DRY_RUN else "LIVE ENFORCEMENT"
st.sidebar.info(f"Mode: {mode}")
st.sidebar.markdown("### Honeypot Services")
services = [("HTTP Honeypot", 8080), ("SSH Honeypot", 2222), ("Telnet Honeypot", 2323), ("MQTT Honeypot", 1883), ("FTP Honeypot", 2121)]
for name, port in services:
    ok = service_open(port)
    st.sidebar.markdown(f"{'🟢' if ok else '🔴'} **{name}**  \\nPort `{port}`")
st.sidebar.markdown("### Mitigation")
st.sidebar.write(f"Enabled: **{MITIGATION_ENABLED}**")
st.sidebar.write(f"Dry-run: **{DRY_RUN}**")
st.sidebar.caption("For real iptables enforcement, use the Linux deployment and review the allowlist first.")

now = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M:%S UTC")
st.sidebar.caption(f"Last dashboard render: {now}")

events = load_events()

# ---- KPI row ----
if events.empty:
    total = unique = blocks = high = 0
else:
    total = len(events)
    unique = events["src_ip"].nunique()
    blocks = int((events["action"] == "BLOCK").sum())
    high = int((events["threat_score"].fillna(0) >= 0.75).sum())

cols = st.columns(4)
with cols[0]: render_metric("TOTAL ATTACK EVENTS", f"{total:,}", "Captured by deception layer")
with cols[1]: render_metric("UNIQUE ATTACKERS", f"{unique:,}", "Distinct source addresses")
with cols[2]: render_metric("POLICY BLOCKS", f"{blocks:,}", "Block decisions / dry-run actions")
with cols[3]: render_metric("HIGH-RISK EVENTS", f"{high:,}", "Threat score ≥ 0.75")

if events.empty:
    st.warning("The backend is running but no telemetry has reached the database yet. Keep the honeypot terminal open for a few seconds or generate traffic against ports 8080/2222/2323/1883/2121.")
    st.stop()

# ---- Visual analytics ----
st.markdown('<div class="section">Live Attack Overview</div>', unsafe_allow_html=True)
left, center, right = st.columns([1.35, 1.0, 0.9])

with left:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Live Attack Map**")
    map_rows = []
    for _, row in events.iterrows():
        try:
            intel = json.loads(row.get("intel_json") or "{}")
            geo = intel.get("geo") or {}
            lat, lon = geo.get("lat"), geo.get("lon")
            if lat is not None and lon is not None:
                map_rows.append({"lat": float(lat), "lon": float(lon), "ip": row["src_ip"], "protocol": row["protocol"], "risk": float(row.get("threat_score") or 0)})
        except Exception:
            pass
    mdf = pd.DataFrame(map_rows).drop_duplicates("ip")
    if not mdf.empty:
        fig = px.scatter_geo(
            mdf,
            lat="lat",
            lon="lon",
            hover_name="ip",
            hover_data={"protocol": True, "risk": ":.2f", "lat": False, "lon": False},
            projection="natural earth",
        )
        fig.update_traces(marker={"size": 13, "color": "#25d6ff", "line": {"width": 1, "color": "#0a3d55"}})
        fig.update_geos(showland=True, landcolor="#0b2231", oceancolor="#061018", showocean=True, showcountries=True, countrycolor="#17384a")
        fig.update_layout(height=330, margin=dict(l=0,r=0,t=10,b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dcecf5")
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.info("No geolocated telemetry available yet.")
    st.markdown('</div>', unsafe_allow_html=True)

with center:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Attack Types**")
    protocol_counts = events["protocol"].value_counts().rename_axis("Protocol").reset_index(name="Count")
    fig = px.pie(protocol_counts, names="Protocol", values="Count", hole=0.60)
    fig.update_layout(height=330, margin=dict(l=0,r=0,t=10,b=0), showlegend=True, legend=dict(orientation="h", y=-0.05), paper_bgcolor="rgba(0,0,0,0)", font_color="#dcecf5")
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    st.markdown('</div>', unsafe_allow_html=True)

with right:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Top Attacking Countries**")
    ti = intel_rows(events)
    if not ti.empty:
        countries = ti.groupby("Country", as_index=False).size().sort_values("size", ascending=False).head(8).rename(columns={"size": "Attackers"})
        fig = px.bar(countries, x="Attackers", y="Country", orientation="h", text="Attackers")
        fig.update_traces(marker_color="#1cc7f4")
        fig.update_layout(height=330, margin=dict(l=0,r=0,t=10,b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dcecf5", yaxis_title="", xaxis_title="")
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.info("Threat-intelligence country data will appear here.")
    st.markdown('</div>', unsafe_allow_html=True)

# ---- Recent attacks and TI ----
st.markdown('<div class="section">Recent Attacks & Threat Intelligence</div>', unsafe_allow_html=True)
left, right = st.columns([1.55, 1.0])
with left:
    recent = events[["ts","src_ip","protocol","device_persona","threat_score","action","event_type"]].head(12).copy()
    recent["threat_score"] = recent["threat_score"].fillna(0).map(lambda x: f"{x:.2f}")
    recent.columns = ["Time","Source IP","Protocol","IoT Target","Threat Score","Action","Event"]
    st.dataframe(recent, use_container_width=True, hide_index=True, height=430)
with right:
    if not ti.empty:
        selected_ip = ti.iloc[0]["IP"]
        st.markdown('<div class="card">', unsafe_allow_html=True)
        selected = ti[ti["IP"] == selected_ip].iloc[0]
        st.markdown(f"### {selected['IP']}")
        st.metric("Reputation / Abuse", f"{int(selected['Abuse score'])}/100")
        st.write(f"**Country:** {selected['Country']}")
        st.write(f"**City:** {selected['City']}")
        st.write(f"**Organization:** {selected['Organization']}")
        st.write(f"**ASN:** {selected['ASN']}")
        st.write(f"**Threat feeds:** {selected['Sources']}")
        st.write(f"**Reports:** {int(selected['Reports'])}")
        st.write(f"**VirusTotal malicious:** {int(selected['VT malicious'])}")
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("No TI observations yet.")

# ---- ML + attacker profiles ----
st.markdown('<div class="section">Behavioral ML & Attacker Profiling</div>', unsafe_allow_html=True)
left, right = st.columns(2)
with left:
    scores = events[["ml_attack_probability","anomaly_score"]].copy().fillna(0)
    score_df = pd.DataFrame({"Metric": ["ML attack probability", "Isolation Forest anomaly"], "Average": [scores["ml_attack_probability"].mean(), scores["anomaly_score"].mean()]})
    fig = px.bar(score_df, x="Metric", y="Average", range_y=[0,1], text=score_df["Average"].map(lambda x: f"{x:.2f}"))
    fig.update_traces(marker_color="#7c62ff")
    fig.update_layout(height=300, margin=dict(l=0,r=0,t=10,b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dcecf5", xaxis_title="", yaxis_title="Score")
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
with right:
    profiles = (
        events.groupby("src_ip", as_index=False)
        .agg(Events=("id","count"), Max_Threat=("threat_score","max"), Last_Seen=("ts","max"), Protocols=("protocol",lambda x: ", ".join(sorted(set(x)))))
        .sort_values("Max_Threat", ascending=False)
        .head(10)
    )
    profiles["Max_Threat"] = profiles["Max_Threat"].fillna(0).map(lambda x: f"{x:.2f}")
    st.dataframe(profiles, use_container_width=True, hide_index=True, height=300)

# ---- Logs ----
st.markdown('<div class="section">Real-time System Logs</div>', unsafe_allow_html=True)
log_path = ROOT / os.getenv("LOG_PATH", "logs/honeypot.log")
if log_path.exists():
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-18:]
    st.code("\n".join(lines), language="text")
else:
    st.info("Log file will appear when the honeypot starts.")

st.caption("Research/presentation build. Synthetic demo telemetry is labeled explicitly; real firewall enforcement remains disabled by default.")
