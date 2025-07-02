import json
import joblib
import pandas as pd
from time import sleep
from datetime import datetime
import signal
import sys
import os

# Load trained model
model = joblib.load("rf_model.pkl")

# Features used in the model
features = ['bytes_toclient','bytes_toserver','flow_age','pkts_toclient','pkts_toserver' ]

# Set to track alerted flow_ids
alerted_flow_ids = set()

# Prepare results CSV
output_file = "classification_results.csv"
if not os.path.exists(output_file):
    pd.DataFrame(columns=[
        "timestamp", "src_ip", "dest_ip", "flow_id",
        *features, "prediction"
    ]).to_csv(output_file, index=False)

# Graceful shutdown flag
running = True

def signal_handler(sig, frame):
    global running
    print("\n[✓] Shutdown signal received. Exiting gracefully...")
    running = False

signal.signal(signal.SIGINT, signal_handler)

# Function to parse Suricata timestamp
def parse_time(ts_str):
    try:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        return None

# Extract features from flow event
def extract_features(event):
    try:
        flow = event["flow"]
        return [
            flow.get("bytes_toclient", 0),
            flow.get("bytes_toserver", 0),
	    flow.get("flow_age", 0),
            flow.get("bytes_toclient", 0),
            flow.get("pkts_toserver", 0)
        ]
    except KeyError:
        return None

# Open and follow eve.json
try:
    with open("/var/log/suricata/eve.json", "r") as f:
        f.seek(0, 2)  # tailing

        print("[✓] System started. Monitoring eve.json in real-time...")

        while running:
            line = f.readline()
            if not line:
                sleep(0.1)
                continue

            try:
                event = json.loads(line.strip())

                # Track alerts
                if event.get("event_type") == "alert":
                    if "flow_id" in event:
                        alerted_flow_ids.add(event["flow_id"])
                        print(f"[+] Alert detected - Flow ID {event['flow_id']} added to tracking list.")

                # Process flow events
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
                            timestamp = event.get("timestamp", "N/A")

                            print(f"[{timestamp}] {src_ip} → {dest_ip} | Flow ID: {flow_id} | Prediction: {label}")

                            # Save to CSV
                            result = {
                                "timestamp": timestamp,
                                "src_ip": src_ip,
                                "dest_ip": dest_ip,
                                "flow_id": flow_id,
                                "bytes_toserver": feats[0],
                                "bytes_toclient": feats[1],
                                "flow_age": feats[2],
                                "pkts_toserver": feats[3],
                                "pkts_toclient": feats[4],
                                "prediction": label
                            }
                            pd.DataFrame([result]).to_csv(output_file, mode='a', header=False, index=False)
                            print(f"[✓] Classification saved for Flow ID {flow_id}. Now removing from tracking.")

                        # Remove to prevent re-processing
                        alerted_flow_ids.remove(flow_id)

            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"[!] Unexpected error: {e}")

except FileNotFoundError:
    print("[✗] File /var/log/suricata/eve.json not found. Is Suricata running?")
    sys.exit(1)
