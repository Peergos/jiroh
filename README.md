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

The Rust interop tests need the [interop-probe](https://github.com/peergos/iroh-interop-probe) binaries (cloned as
`interop-probe` next to jiroh) and n0's `iroh-relay`; they are skipped when those are not built.

## Throughput

`./bench.sh [bytes] [streams] [java opts]` runs every pairing of Rust iroh and jiroh over loopback. One bidirectional
stream, 512 MiB, best of 5 runs, MiB/s (Ryzen 9 7940HS, Linux 6.8, Java 25, iroh 1.3):

| client → server | upload | download |
|---|---|---|
| Rust iroh → Rust iroh | 639 | 639 |
| jiroh → Rust iroh | 814 | 443 |
| Rust iroh → jiroh | 482 | 695 |
| jiroh → jiroh | 759 | 665 |

jiroh sends faster than Rust iroh, and jiroh to jiroh beats Rust iroh to Rust iroh: interleaving the two (same
machine load), jiroh↔jiroh got 695–767 up and 641–697 down against 642–661 and 586–649. Receiving from Rust iroh
is slower, 73–87% of Rust↔Rust: Rust's sender is the bottleneck there and spends more CPU per byte towards jiroh
(and towards a plain noq client) than towards iroh's own receiver. The machine runs a VM alongside, so absolute
numbers vary by 5–15% between runs (Rust↔Rust has measured 640–700).
