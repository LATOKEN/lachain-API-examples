#! /usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
"$SCRIPT_DIR"/tft_measure.py flood --id 0 --cnt 1000  > "$SCRIPT_DIR"/node0.out 2>&1 &
"$SCRIPT_DIR"/tft_measure.py flood --id 1 --cnt 1000  > "$SCRIPT_DIR"/node1.out 2>&1 &
"$SCRIPT_DIR"/tft_measure.py flood --id 2 --cnt 1000 > "$SCRIPT_DIR"/node2.out 2>&1 &
"$SCRIPT_DIR"/tft_measure.py flood --id 3 --cnt 1000 --repeat > "$SCRIPT_DIR"/node3.out 2>&1 &


sleep 10
"$SCRIPT_DIR"/tft_measure.py measure
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT