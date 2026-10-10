#!/usr/bin/env bash
# Loopback throughput: Rust iroh (interop-probe bench) and jiroh, in all four client/server pairings.
# Usage: ./bench.sh [bytes] [streams] [java opts...]
set -u
cd "$(dirname "$0")"
BYTES=${1:-536870912}
STREAMS=${2:-1}
shift $(( $# > 2 ? 2 : $# ))
RUST=../interop-probe/target/release/bench
CP=$(./gradlew -q testClasses printTestClasspath 2>/dev/null | tail -1)
JAVA="java -Xmx2g --enable-native-access=ALL-UNNAMED $* -cp $CP org.peergos.iroh.Bench"
LOG=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf $LOG' EXIT

start() { # name cmd...
    "${@:2}" > $LOG/$1 2>&1 &
}
id_of() {
    for _ in $(seq 50); do grep -q "endpoint id" $LOG/$1 2>/dev/null && break; sleep 0.2; done
    grep "endpoint id" $LOG/$1 | cut -d' ' -f3
}
rust_client() { for _ in 1 2 3; do $RUST client 127.0.0.1:$1 $2 $3 $BYTES $STREAMS; done | sort -t= -k2 -n | tail -1; }
java_client() { $JAVA client 127.0.0.1:$1 $2 $3 $BYTES $STREAMS | tail -n +3 | sort -t= -k2 -n | tail -1; }

start rust $RUST server 127.0.0.1:4500
start java $JAVA server 4600
RID=$(id_of rust)
JID=$(id_of java)
for mode in up down; do
    echo "rust -> rust $mode: $(rust_client 4500 $RID $mode)"
    echo "java -> rust $mode: $(java_client 4500 $RID $mode)"
    echo "rust -> java $mode: $(rust_client 4600 $JID $mode)"
    echo "java -> java $mode: $(java_client 4600 $JID $mode)"
done
