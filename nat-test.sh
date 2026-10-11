#!/usr/bin/env bash
# Two endpoints behind separate NATs, with a relay on the "internet" between them: checks that NAT traversal finds a
# direct path. The NATs are Linux masquerade (endpoint-independent mapping, address and port dependent filtering) in
# network namespaces of an unprivileged user namespace, so no root is needed.
#
#   hostA 10.0.1.2 -- natA 198.18.0.1 --+-- relay 198.18.0.254
#   hostB 10.0.2.2 -- natB 198.18.0.2 --+
#
# Usage: ./nat-test.sh [java|rust] [java|rust] [portmap]: the server and the client, jiroh (default) or Rust iroh
# (the interop-probe binaries). The client knows only the server's relay; the test passes when it gets a direct path.
# With portmap, natA runs a PCP/NAT-PMP server (PortMappingGateway) and maps ports with DNAT rules, while its
# masquerading uses random ports, so the server is only reachable at its port mapped address.
set -eu
cd "$(dirname "$0")"
RELAY_BIN=${IROH_RELAY_BIN:-../iroh/target/release/iroh-relay}
if [ "${NAT_TEST_INSIDE:-}" != 1 ]; then
    CP=$(./gradlew -q testClasses printTestClasspath 2>/dev/null | tail -1)
    exec unshare -rnm --propagation private env NAT_TEST_INSIDE=1 CP="$CP" "$0" "$@"
fi
JAVA="java --enable-native-access=ALL-UNNAMED ${NAT_TEST_JAVA_OPTS:-} -cp $CP org.peergos.iroh.NatPeer"
PROBE=../interop-probe/target/release
JAVA_GATEWAY="java -cp $CP org.peergos.iroh.PortMappingGateway"
SERVER=${1:-java}
CLIENT=${2:-java}
PORTMAP=${3:-}
DIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; rm -rf $DIR' EXIT

mount -t tmpfs tmpfs /run
mkdir /run/netns
ns() { local ns=$1; shift; nsenter --net=/run/netns/$ns "$@"; }

ip link set lo up
ip link add br0 type bridge
ip addr add 198.18.0.254/24 dev br0
ip link set br0 up
for i in 1 2; do
    n=$([ $i = 1 ] && echo A || echo B)
    ip netns add nat$n
    ip netns add host$n
    ip link add wan$n type veth peer name wan netns nat$n
    ip link set wan$n master br0 up
    ip -n nat$n link set lo up
    ip -n nat$n addr add 198.18.0.$i/24 dev wan
    ip -n nat$n link set wan up
    ip -n nat$n link add lan type veth peer name eth0 netns host$n
    ip -n nat$n addr add 10.0.$i.1/24 dev lan
    ip -n nat$n link set lan up
    ip -n host$n link set lo up
    ip -n host$n addr add 10.0.$i.2/24 dev eth0
    ip -n host$n link set eth0 up
    ip -n host$n route add default via 10.0.$i.1
    ns nat$n sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
    # Internet latency, so (as on a real network) the client's probes leave before the server's, which wait for the
    # client's REACH_OUT to come through the relay, arrive. Without it, a server probe that reaches the client's NAT
    # first makes Linux conntrack map the client's probes to another port.
    ns nat$n tc qdisc add dev wan root netem delay ${NAT_TEST_DELAY_MS:-10}ms
    ns nat$n nft -f - <<NFT
table ip nat {
    chain prerouting { type nat hook prerouting priority dstnat; }
    chain postrouting { type nat hook postrouting priority srcnat; oifname "wan" masquerade $([ -n "$PORTMAP" ] && [ $n = A ] && echo random); }
}
table ip filter {
    chain forward { type filter hook forward priority filter; policy drop;
        iifname "lan" accept
        ct state established,related accept
        ct status dnat accept
    }
}
NFT
done
# NAT_TEST_NO_GATEWAY=1: the control, without which the portmap test must fail.
if [ -n "$PORTMAP" ] && [ -z "${NAT_TEST_NO_GATEWAY:-}" ]; then
    ns natA $JAVA_GATEWAY 10.0.1.1 198.18.0.1 > $DIR/gateway.log 2>&1 &
fi

# A CA (cert.pem, which the endpoints trust) and the relay's certificate: rustls rejects a CA as the end entity.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $DIR/ca-key.pem -out $DIR/cert.pem \
    -days 2 -subj /CN=nat-test-ca 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $DIR/key.pem -out $DIR/relay.csr \
    -subj /CN=198.18.0.254 2>/dev/null
printf 'subjectAltName=IP:198.18.0.254\nbasicConstraints=CA:FALSE\n' > $DIR/ext.cnf
openssl x509 -req -in $DIR/relay.csr -CA $DIR/cert.pem -CAkey $DIR/ca-key.pem -CAcreateserial -days 2 \
    -extfile $DIR/ext.cnf -out $DIR/relay-cert.pem 2>/dev/null
cat > $DIR/relay.toml <<TOML
enable_relay = true
http_bind_addr = "198.18.0.254:3340"
enable_quic_addr_discovery = true
enable_metrics = false
[tls]
https_bind_addr = "198.18.0.254:4433"
quic_bind_addr = "198.18.0.254:7842"
cert_mode = "Manual"
manual_cert_path = "$DIR/relay-cert.pem"
manual_key_path = "$DIR/key.pem"
TOML
$RELAY_BIN -c $DIR/relay.toml > $DIR/relay.log 2>&1 &
sleep 1
RELAY=https://198.18.0.254:4433/
if [ -n "${NAT_TEST_CAPTURE:-}" ]; then
    tcpdump -Z root -l -n -i br0 udp and not host 198.18.0.254 > $DIR/capture.log 2>&1 &
fi

if [ $SERVER = rust ]; then
    ns hostA env IROH_RELAY_CA=$DIR/cert.pem RUST_LOG=${NAT_TEST_RUST_LOG:-} $PROBE/server 0.0.0.0:0 - $RELAY > $DIR/server.log 2>&1 &
else
    ns hostA $JAVA server $RELAY $DIR/cert.pem 7842 > $DIR/server.log 2>&1 &
fi
for _ in $(seq 100); do grep -q "endpoint id" $DIR/server.log 2>/dev/null && break; sleep 0.2; done
sed 's/^/server: /' $DIR/server.log
ID=$(grep "endpoint id" $DIR/server.log | awk '{print $3}')
[ -n "$ID" ] || { echo "server did not start"; cat $DIR/relay.log; exit 1; }
set +e
if [ $CLIENT = rust ]; then
    ns hostB env IROH_RELAY_CA=$DIR/cert.pem IROH_CLIENT_LINGER_MS=8000 IROH_CLIENT_WAIT_ONLINE=1 $PROBE/iroh_client - $ID 3 $RELAY > $DIR/client.log 2>&1
    sed -e 's/^/client: /' -e 's/last_stats: .*/.../' $DIR/client.log
    # A path to the server's public address, i.e. through its NAT.
    grep -q "Opened { id: PathId([0-9]*), remote_addr: Ip(198.18.0.1:" $DIR/client.log
    STATUS=$?
else
    ns hostB $JAVA client $RELAY $DIR/cert.pem 7842 $ID 2>&1 | tee $DIR/client-java.log | sed 's/^/client: /'
    STATUS=${PIPESTATUS[0]}
fi
sed 's/^/server: /' $DIR/server.log | grep -v "endpoint id\|observed\|direct addresses" | sed 's/last_stats: .*/.../'
if [ -n "$PORTMAP" ]; then
    sed 's/^/gateway: /' $DIR/gateway.log
    # The direct path must go to the port mapped address.
    MAPPED=$(grep -o "198.18.0.1:[0-9]* ->" $DIR/gateway.log | head -1 | cut -d' ' -f1)
    [ -n "$MAPPED" ] && grep -q "$MAPPED" $DIR/client.log $DIR/client-java.log 2>/dev/null || STATUS=1
fi
if [ -n "${NAT_TEST_CAPTURE:-}" ]; then
    sleep 0.5
    sed 's/^/capture: /' $DIR/capture.log | head -${NAT_TEST_CAPTURE}
fi
exit $STATUS
