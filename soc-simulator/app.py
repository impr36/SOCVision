import streamlit as st
import pandas as pd
from shared_queue import event_queue
from collectors.eventlog import tail_security_log
from collectors.network import start_network_capture
from queue import Empty
import threading

st.set_page_config("SOC Simulator", layout="wide")
st.title("SOC Simulator Dashboard")

if "events" not in st.session_state:
    st.session_state.events = []

col1, col2 = st.columns(2)

with col1:
    if st.button("Start Windows Log Collection"):
        threading.Thread(target=tail_security_log, daemon=True).start()
        st.success("Windows Security Log Started")

with col2:
    iface = st.text_input("Network Interface (e.g. Wi-Fi)")
    if st.button("Start Network Capture"):
        start_network_capture(iface)
        st.success(f"Capturing on {iface}")

# Pull events (NO infinite loop)
for _ in range(20):
    try:
        ev = event_queue.get_nowait()
        st.session_state.events.append(ev)
    except Empty:
        break

if st.session_state.events:
    df = pd.DataFrame(st.session_state.events[-100:])
    st.dataframe(df)

    st.subheader("Event Sources")
    st.bar_chart(df["source"].value_counts())
