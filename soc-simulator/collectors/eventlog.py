import time
import win32evtlog
from utils.normalizer import normalize_event
from shared_queue import event_queue

def tail_security_log():
    server = "localhost"
    logtype = "Security"
    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    last_time = None

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            time.sleep(1.2)
            continue

        for ev in events:
            # Skip if same timestamp (avoid spam)
            if last_time == ev.TimeGenerated:
                continue
            last_time = ev.TimeGenerated

            data = {
                "EventID": ev.EventID & 0xFFFF,
                "LevelName": {0: "AUDIT_SUCCESS", 1: "AUDIT_FAILURE", 2: "INFO", 3: "WARN", 4: "ERROR"}.get(ev.EventType, "UNKNOWN"),
                "Message": " | ".join(ev.StringInserts) if ev.StringInserts else "N/A",
                "TimeGenerated": ev.TimeGenerated,
                "User": ev.ComputerName if ev.ComputerName else None,
            }
            normalized = normalize_event(data, "windows_event")
            event_queue.put(normalized)