# jiroh

A Java implementation of [iroh](https://github.com/n0-computer/iroh) endpoints, interoperable with Rust iroh 1.x:
QUIC with raw public key TLS, iroh relays, QUIC address discovery, pkarr lookup on the mainline DHT, and multipath
(draft-ietf-quic-multipath-21).

It builds against Peergos's forks of kwik (QUIC) and agent15 (TLS 1.3), branch `iroh`, cloned next to it:

```
git clone -b iroh git@github.com:peergos/agent15.git
git clone -b iroh git@github.com:peergos/kwik.git
git clone git@github.com:peergos/jiroh.git
cd jiroh && ./gradlew test
```

Java 25. The fast Linux UDP path (GSO/GRO through FFM) needs `--enable-native-access=ALL-UNNAMED`; without it a
DatagramChannel is used.

The Rust interop tests need the `interop-probe` binaries and n0's `iroh-relay`; they are skipped when those are not
built. `bench.sh` measures throughput against Rust iroh.
