import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from queue import Empty
import threading
import json
from streamlit_autorefresh import st_autorefresh

from shared_queue import event_queue
from collectors.eventlog import tail_security_log
from collectors.network import start_network_capture
from utils.normalizer import normalize_event
from components.rules import evaluate_rules

st.set_page_config(page_title="Offline SOC Simulator", layout="wide", page_icon="🛡️")

# ── Auto-refresh every 10 seconds ──
st_autorefresh(
    interval=10000,   # milliseconds
    limit=None,
    key="soc_refresh"
)

# ── Session state ──
if "events" not in st.session_state:
    st.session_state.events = []
if "alerts" not in st.session_state:
    st.session_state.alerts = []
if "collecting_win" not in st.session_state:
    st.session_state.collecting_win = False
if "collecting_net" not in st.session_state:
    st.session_state.collecting_net = False

# ── Drain queue safely ──
new_events = 0
while True:
    try:
        ev = event_queue.get_nowait()
        st.session_state.events.append(ev)
        # Basic alerting
        new_alerts = evaluate_rules(ev)
        for al in new_alerts:
            al["timestamp"] = ev["timestamp"]
            al["source_event"] = ev
            st.session_state.alerts.append(al)
        new_events += 1
    except Empty:
        break

# Limit memory
if len(st.session_state.events) > 10000:
    st.session_state.events = st.session_state.events[-10000:]
if len(st.session_state.alerts) > 5000:
    st.session_state.alerts = st.session_state.alerts[-5000:]

df_events = pd.DataFrame(st.session_state.events)
df_alerts = pd.DataFrame(st.session_state.alerts)

# ── Styling ──
st.markdown("""
<style>
    .metric-card {background:#1e293b; border-radius:8px; padding:16px; text-align:center; border:1px solid #334155;}
    .high {color:#ef4444; font-weight:bold;}
    .med {color:#f59e0b;}
    .low {color:#10b981;}
    .sidebar-title {font-size:1.4rem; color:#00d4ff; font-weight:bold;}
</style>
""", unsafe_allow_html=True)

# ── Sidebar (nav-like) ──
with st.sidebar:
    st.markdown('<div class="sidebar-title">Offline SOC Simulator</div>', unsafe_allow_html=True)
    st.markdown("**Mode:** Air-gapped • Educational")
    st.markdown(f"**Events:** {len(df_events)} | **Alerts:** {len(df_alerts)}")

    st.divider()

    if st.button("▶ Start Windows Logs", disabled=st.session_state.collecting_win):
        if not st.session_state.collecting_win:
            threading.Thread(target=tail_security_log, daemon=True).start()
            st.session_state.collecting_win = True
            st.success("Windows Security Log → Running")

    iface = st.text_input("Network Interface", placeholder="Wi-Fi or Ethernet")
    if st.button("▶ Start Network Capture", disabled=st.session_state.collecting_net):
        if not st.session_state.collecting_net:
            start_network_capture(iface if iface.strip() else None)
            st.session_state.collecting_net = True
            st.success("Network Capture → Running")

    if st.button("⏸ Pause Collection"):
        st.session_state.collecting_win = False
        st.session_state.collecting_net = False
        st.info("Collection paused (threads still alive but not reading)")

    st.divider()

    # Export
    if not df_events.empty:
        csv_events = df_events.to_csv(index=False).encode('utf-8')
        st.download_button("Export Events (CSV)", csv_events, "soc_events.csv", "text/csv")

    if not df_alerts.empty:
        csv_alerts = df_alerts.to_csv(index=False).encode('utf-8')
        st.download_button("Export Alerts (CSV)", csv_alerts, "soc_alerts.csv", "text/csv")

    # Save to JSONL
    if st.button("Append to events.jsonl"):
        with open("data/events.jsonl", "a", encoding="utf-8") as f:
            for ev in st.session_state.events[-new_events:]:
                f.write(json.dumps(ev) + "\n")
        st.success("Appended recent events to data/events.jsonl")

# ── Main Dashboard ──
st.title("🛡️ Offline SOC Simulator")
st.caption(f"Host: {df_events['host'].iloc[-1] if not df_events.empty else 'localhost'} • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if df_events.empty and df_alerts.empty:
    st.info("No events or alerts yet. Start Windows logs and/or Network capture to generate data.")
elif df_alerts.empty:
    st.info("Events are coming in, but no alerts triggered yet. Waiting for suspicious patterns…")
    
# Metrics row
cols = st.columns(4)

with cols[0]:
    if not df_alerts.empty and "severity" in df_alerts.columns:
        active_high = len(df_alerts[df_alerts["severity"] == "HIGH"])
    else:
        active_high = 0
    st.metric("Active Alerts", active_high, delta_color="inverse")

with cols[1]:
    failed_logins = len(df_events[df_events["event_id"] == 4625]) if not df_events.empty else 0
    st.metric("Failed Logins", failed_logins)

with cols[2]:
    port_probes = len(df_alerts[df_alerts["type"].str.contains("Port|Probe|Scan", na=False)]) if not df_alerts.empty and "type" in df_alerts.columns else 0
    st.metric("Port Probes", port_probes)

with cols[3]:
    priv_events = len(df_events[df_events["event_id"].isin([4672, 4728, 4726])]) if not df_events.empty else 0
    st.metric("Privilege Events", priv_events)

# ── Charts & Tables ──
tab1, tab2, tab3 = st.tabs(["Overview & Timeline", "Alerts & Incidents", "Raw Events"])

with tab1:
    if not df_events.empty:
        df_events["timestamp"] = pd.to_datetime(df_events["timestamp"])
        timeline = df_events.set_index("timestamp").resample("5min").size().reset_index(name="Count")
        fig = px.line(timeline, x="timestamp", y="Count", title="Event Rate (5-min bins)")
        st.plotly_chart(fig, use_container_width=True)

    col_left, col_right = st.columns(2)
    with col_left:
        if not df_events.empty:
            top_ids = df_events["event_id"].value_counts().head(8).reset_index()
            fig_ids = px.bar(top_ids, x="count", y="event_id", orientation="h", title="Top Event IDs")
            st.plotly_chart(fig_ids, use_container_width=True)

    with col_right:
        if not df_alerts.empty:
            sev_dist = df_alerts["severity"].value_counts()
            fig_sev = px.pie(sev_dist, names=sev_dist.index, values=sev_dist.values, title="Alert Severity")
            st.plotly_chart(fig_sev, use_container_width=True)

with tab2:
    st.subheader("Active Alerts")
    if not df_alerts.empty:
        def style_alert(row):
            colors = {"HIGH": "#4a1d1d", "MEDIUM": "#4a3d1d", "LOW": "#1d3a1d"}
            bg = colors.get(row["severity"], "")
            return [f"background-color:{bg}"] * len(row)

        st.dataframe(
            df_alerts[["timestamp", "type", "severity", "desc"]].sort_values("timestamp", ascending=False).head(50).style.apply(style_alert, axis=1),
            use_container_width=True
        )
    else:
        st.info("No alerts yet. Start collection → wait for suspicious patterns.")

with tab3:
    st.subheader("Live Event Feed")
    if not df_events.empty:
        display_cols = ["timestamp", "source", "event_id", "level", "severity", "message", "src_ip", "dst_ip", "protocol_name"]
        display_cols = [c for c in display_cols if c in df_events.columns]
        st.dataframe(df_events[display_cols].sort_values("timestamp", ascending=False).head(80), use_container_width=True)
    else:
        st.info("Start collection to see events...")

st.caption("Educational Prototype • v1.1 • Expand with Sigma rules, MITRE mapping, incident grouping...")