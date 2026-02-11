def evaluate_rules(event):
    alerts = []

    if event["source"] == "windows_event":
        eid = event.get("event_id")
        if eid == 4625:
            alerts.append({"type": "Failed Login", "severity": "HIGH", "desc": f"Failed logon - {event.get('message', '')[:80]}"})
        if eid in [4672, 4728, 4732]:
            alerts.append({"type": "Privilege/Group Change", "severity": "MEDIUM", "desc": "Admin/privilege activity detected"})
        # Add for testing: trigger on ANY event occasionally
        # if random.random() < 0.05:  # ~5% chance
        #     alerts.append({"type": "Test Alert", "severity": "LOW", "desc": "Random test trigger"})

    if event["source"] == "network":
        dport = event.get("dst_port")
        if dport in [22, 23, 3389, 445, 1433, 3306]:
            alerts.append({"type": "Sensitive Port Access", "severity": "HIGH", "desc": f"Access to port {dport}"})
        if event.get("protocol_name") == "ICMP" and "echo-request" in str(event.get("raw", "")).lower():
            alerts.append({"type": "ICMP Activity", "severity": "LOW", "desc": "Ping detected"})

    return alerts