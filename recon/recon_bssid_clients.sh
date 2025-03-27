#!/bin/bash

if [ $# -ne 3 ]; then
    echo "Usage: $0 <interface> <BSSID> <channel>"
    exit 1
fi

INTERFACE=$1
BSSID=$2
CHANNEL=$3

# Run airodump-ng and filter clients connected to the given BSSID
airodump-ng --bssid "$BSSID" --write output --output-format csv --channel "$CHANNEL" "$INTERFACE" &
PID=$!

# Let it run for a few seconds
sleep 10
kill $PID
