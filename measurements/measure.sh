#! /usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
python -u "$SCRIPT_DIR"/tft_measure.py flood --id 0  --batches 10 --batch_size 100 > "$SCRIPT_DIR"/node0.out 2>&1 &
python -u "$SCRIPT_DIR"/tft_measure.py flood --id 1  --batches 10 --batch_size 100 > "$SCRIPT_DIR"/node1.out 2>&1 &
python -u "$SCRIPT_DIR"/tft_measure.py flood --id 2  --batches 10 --batch_size 100 > "$SCRIPT_DIR"/node2.out 2>&1 &
python -u "$SCRIPT_DIR"/tft_measure.py flood --id 3  --batches 10 --batch_size 100 > "$SCRIPT_DIR"/node3.out 2>&1 &
echo "All nodes running"
python "$SCRIPT_DIR"/tft_measure.py monitor

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT
