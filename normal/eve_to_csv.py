import json
import csv
from collections import defaultdict

# Load events grouped by flow_id
flow_data = defaultdict(dict)

with open("normal.json") as infile:
    for line in infile:
        try:
            entry = json.loads(line)
            flow_id = str(entry.get("flow_id"))
            event_type = entry.get("event_type")

            if not flow_id:
                continue

            # Store basic info
            base_fields = {
                "timestamp": entry.get("timestamp"),
                "flow_id": flow_id,
                "event_type": event_type,
                "src_ip": entry.get("src_ip"),
                "src_port": entry.get("src_port"),
                "dest_ip": entry.get("dest_ip"),
                "dest_port": entry.get("dest_port"),
                "proto": entry.get("proto"),
                "app_proto": entry.get("app_proto"),
            }
            flow_data[flow_id].update({k: v for k, v in base_fields.items() if v is not None})

            if event_type == "flow":
                flow = entry.get("flow", {})
                flow_data[flow_id].update({
                    "pkts_toserver": flow.get("pkts_toserver"),
                    "pkts_toclient": flow.get("pkts_toclient"),
                    "bytes_toserver": flow.get("bytes_toserver"),
                    "bytes_toclient": flow.get("bytes_toclient"),
                    "flow_state": flow.get("state"),
                    "flow_age": flow.get("age"),
                })

            elif event_type == "alert":
                alert = entry.get("alert", {})
                flow_data[flow_id].update({
                    "alert_signature": alert.get("signature"),
                    "alert_signature_id": alert.get("signature_id"),
                    "alert_severity": alert.get("severity"),
                })

            elif event_type == "http":
                http = entry.get("http", {})
                flow_data[flow_id].update({
                    "http_method": http.get("http_method"),
                    "http_url": http.get("url"),
                    "http_status": http.get("status"),
                    "http_length": http.get("length"),
                    "http_user_agent": http.get("http_user_agent"),
                    "http_host": http.get("hostname"),
                })

        except json.JSONDecodeError:
            continue

# Write to CSV
fieldnames = sorted(set().union(*(d.keys() for d in flow_data.values())))

with open("suricata_output.csv", "w", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in flow_data.values():
        writer.writerow(row)

print("✅ CSV saved as suricata_output.csv")
