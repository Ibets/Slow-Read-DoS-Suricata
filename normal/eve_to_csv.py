import json
import csv
from collections import defaultdict

# Input and output filenames
INPUT_FILE = "normal.json"
OUTPUT_FILE = "slowread_flows.csv"

# Temp store by flow_id
flow_data = defaultdict(dict)

# Read line by line
with open(INPUT_FILE, "r") as f:
    for line in f:
        try:
            event = json.loads(line)
            flow_id = str(event.get("flow_id"))
            event_type = event.get("event_type")

            if not flow_id:
                continue

            # Store relevant fields by event type
            if event_type == "flow":
                flow_data[flow_id]["flow"] = event
            elif event_type == "alert":
                flow_data[flow_id]["alert"] = event
            elif event_type == "http":
                flow_data[flow_id]["http"] = event

        except json.JSONDecodeError:
            continue

# CSV headers
headers = [
    "flow_id", "timestamp", "src_ip", "src_port", "dest_ip", "dest_port",
    "proto", "app_proto", "in_iface",
    "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
    "flow_start", "flow_end", "duration", "flow_state", "tcp_flags",
    "alert_signature", "alert_severity", "alert_action",
    "http_method", "http_url", "http_status", "http_user_agent", "http_length",
    "flowbits_count"
]

# Write CSV
with open(OUTPUT_FILE, "w", newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=headers)
    writer.writeheader()

    for flow_id, data in flow_data.items():
        row = {"flow_id": flow_id}

        # Combine fields from all event types
        flow = data.get("flow", {})
        alert = data.get("alert", {})
        http = data.get("http", {})

        # Timestamp and basics
        row["timestamp"] = flow.get("timestamp") or alert.get("timestamp") or http.get("timestamp")
        row["src_ip"] = flow.get("src_ip") or alert.get("src_ip") or http.get("src_ip")
        row["src_port"] = flow.get("src_port") or alert.get("src_port") or http.get("src_port")
        row["dest_ip"] = flow.get("dest_ip") or alert.get("dest_ip") or http.get("dest_ip")
        row["dest_port"] = flow.get("dest_port") or alert.get("dest_port") or http.get("dest_port")
        row["proto"] = flow.get("proto") or alert.get("proto") or http.get("proto")
        row["in_iface"] = flow.get("in_iface") or alert.get("in_iface") or http.get("in_iface")
        row["app_proto"] = flow.get("app_proto") or alert.get("app_proto") or http.get("app_proto")

        # Flow section
        flow_info = flow.get("flow", {})
        row["pkts_toserver"] = flow_info.get("pkts_toserver")
        row["pkts_toclient"] = flow_info.get("pkts_toclient")
        row["bytes_toserver"] = flow_info.get("bytes_toserver")
        row["bytes_toclient"] = flow_info.get("bytes_toclient")
        row["flow_start"] = flow_info.get("start")
        row["flow_end"] = flow_info.get("end")
        if flow_info.get("start") and flow_info.get("end"):
            from datetime import datetime
            fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
            try:
                t1 = datetime.strptime(flow_info["start"], fmt)
                t2 = datetime.strptime(flow_info["end"], fmt)
                row["duration"] = (t2 - t1).total_seconds()
            except Exception:
                row["duration"] = ""
        row["flow_state"] = flow_info.get("state")

        # TCP Flags
        tcp = flow.get("tcp", {})
        row["tcp_flags"] = tcp.get("tcp_flags")

        # Alert info
        alert_info = alert.get("alert", {})
        row["alert_signature"] = alert_info.get("signature")
        row["alert_severity"] = alert_info.get("severity")
        row["alert_action"] = alert_info.get("action")

        # HTTP info
        http_info = http.get("http", {})
        row["http_method"] = http_info.get("http_method")
        row["http_url"] = http_info.get("url")
        row["http_status"] = http_info.get("status")
        row["http_user_agent"] = http_info.get("http_user_agent")
        row["http_length"] = http_info.get("length")

        # Flowbits metadata
        metadata = flow.get("metadata") or alert.get("metadata") or http.get("metadata") or {}
        flowbits = metadata.get("flowbits", [])
        row["flowbits_count"] = len(flowbits)

        writer.writerow(row)

print(f"✅ Done. Output written to {OUTPUT_FILE}")
