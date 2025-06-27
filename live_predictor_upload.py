import json
import joblib
import pandas as pd
from time import sleep, time
from datetime import datetime

# Load trained model
model = joblib.load("rf_model.pkl")

# Define expected features used during training
features = ['duration', 'bytes_toserver','bytes_toclient', 'pkts_toserver', 'pkts_toclient']

# Store alert flow_id to track later in flows
alerted_flow_ids = set()

# Parse Suricata timestamp
def parse_time(ts_str):
    try:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        return None

# Extract features from flow event
def extract_features(event):
    try:
        flow = event["flow"]
        start = parse_time(flow["start"])
        end = parse_time(flow["end"])
        if not start or not end:
            return None
        duration = (end - start).total_seconds()

        return [
	    duration,
            flow.get("bytes_toserver", 0),
	    flow.get("bytes_toclient", 0),
	    flow.get("bytes_toserver", 0),
            flow.get("pkts_toclient", 0),
        ]
    except KeyError:
        return None

# Open eve.json and follow
with open("/var/log/suricata/eve.json", "r") as f:
    f.seek(0, 2)  # move to end

    while True:
        line = f.readline()
        if not line:
            sleep(0.1)
            continue

        try:
            event = json.loads(line)

            # Step 1: Track alerts and store flow_id
            if event.get("event_type") == "alert":
                if "flow_id" in event:
                    alerted_flow_ids.add(event["flow_id"])

            # Step 2: When a flow event arrives, check if its flow_id was in alert
            elif event.get("event_type") == "flow":
                flow_id = event.get("flow_id")
                if flow_id in alerted_flow_ids:
                    feats = extract_features(event)
                    if feats:
                        df = pd.DataFrame([feats], columns=features)
                        prediction = model.predict(df)[0]
                        label = "SLOWREAD" if prediction == 1 else "BENIGN"
                        src_ip = event.get("src_ip", "N/A")
                        dest_ip = event.get("dest_ip", "N/A")
                        print(f"[{event['timestamp']}] [{src_ip} → {dest_ip}] Prediction: {label}")
                    alerted_flow_ids.remove(flow_id)

        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
