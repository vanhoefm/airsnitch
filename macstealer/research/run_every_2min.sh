#!/bin/bash
# run_every_2min.sh
# Run the given command at the next even-minute 00-second.
# Usage: ./run_every_2min.sh "your command"

if [ -z "$1" ]; then
    echo "Usage: $0 \"command to run\""
    exit 1
fi

cmd="$1"

echo "[+] Current time: $(date '+%H:%M:%S')"

cur_min=$(date +%M)
cur_sec=$(date +%S)

cur_min_dec=$((10#$cur_min))
cur_sec_dec=$((10#$cur_sec))

if (( cur_min_dec % 2 == 0 )); then
    if (( cur_sec_dec == 0 )); then
        target_min=$cur_min_dec
    else
        target_min=$(( (cur_min_dec + 2) % 60 ))
    fi
else
    target_min=$(( (cur_min_dec + 1) % 60 ))
fi

cur_total=$(( cur_min_dec * 60 + cur_sec_dec ))
target_total=$(( target_min * 60 ))  # 秒数 = 分钟 * 60

if (( target_total <= cur_total )); then
    target_total=$(( target_total + 3600 ))
fi

sleep_time=$(( target_total - cur_total ))

echo "[+] Sleeping $sleep_time seconds until next even-minute 00-second..."
sleep $sleep_time

echo "[+] Running command at $(date '+%H:%M:%S')"
eval "$cmd"
