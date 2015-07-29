#!/bin/sh

BINARY=bin/sampler

BASEPATH=$1
shift
RUNSIZE=$1
shift
HOST=$1
shift
PORT=$1
shift
DELTAS=$@

BASE_DELTA=20000

for D in $DELTAS; do
{
    
    OUTPUT=`printf "${BASEPATH}_d%0.6d" $D`
    CASES="{\"short\":$BASE_DELTA,\"long\":$(($BASE_DELTA+$D))}"
    #echo "Running:" taskset -c 1 ./sampler.py -c "$CASES" "$OUTPUT" "$RUNSIZE" "$HOST" "$PORT"
    #taskset -c 1 ./sampler.py -c "$CASES" "$OUTPUT" "$RUNSIZE" "$HOST" "$PORT"
    echo "Running:" "$BINARY" -c "$CASES" "$OUTPUT" "$RUNSIZE" "$HOST" "$PORT"
    $BINARY -c "$CASES" "$OUTPUT" "$RUNSIZE" "$HOST" "$PORT"
} done
