from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP

def normalize_event(raw, source_type):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "source": source_type,
        "event_id": None,
        "level": "INFO",
        "severity": "LOW",
        "message": "N/A",
        "host": "localhost",
        "user": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "raw": str(raw),
    }

    if source_type == "windows_event":
        event["timestamp"] = raw.get("TimeGenerated", datetime.utcnow()).isoformat()
        event["event_id"] = raw.get("EventID")
        event["level"] = raw.get("LevelName", "INFO")
        event["message"] = raw.get("Message", "N/A")
        event["user"] = raw.get("User", None)

        # Basic severity mapping (expand later)
        if event["event_id"] in [4625]:
            event["severity"] = "HIGH"
        elif event["event_id"] in [4624, 4672]:
            event["severity"] = "MEDIUM"

    elif source_type == "network" and hasattr(raw, 'time'):
        event["timestamp"] = datetime.fromtimestamp(raw.time).isoformat()
        if raw.haslayer(IP):
            ip = raw[IP]
            event["src_ip"] = ip.src
            event["dst_ip"] = ip.dst
            event["protocol"] = ip.proto  # number → can map to name later

            if raw.haslayer(TCP):
                tcp = raw[TCP]
                event["src_port"] = tcp.sport
                event["dst_port"] = tcp.dport
                event["protocol_name"] = "TCP"
            elif raw.haslayer(UDP):
                udp = raw[UDP]
                event["src_port"] = udp.sport
                event["dst_port"] = udp.dport
                event["protocol_name"] = "UDP"
            elif raw.haslayer(ICMP):
                event["protocol_name"] = "ICMP"

            # Quick suspicious check
            if event["dst_port"] in [22, 3389, 445, 1433] and "SYN" in str(raw):
                event["severity"] = "HIGH"

    return event