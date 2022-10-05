#! /usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
"$SCRIPT_DIR"/tft_measure.py flood --id 0 --cnt 3000 > node0.out 2>&1 &
"$SCRIPT_DIR"/tft_measure.py flood --id 1 --cnt 3000 > node1.out 2>&1 &
"$SCRIPT_DIR"/tft_measure.py flood --id 2 --cnt 3000 > node2.out 2>&1 &
"$SCRIPT_DIR"/tft_measure.py flood --id 3 --cnt 3000 > node3.out 2>&1 &
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT