package org.peergos.iroh.pkarr;

import org.peergos.iroh.EndpointId;
import org.peergos.iroh.SecretKey;

import java.time.Duration;
import java.util.Optional;

/**
 * Publishing and resolving iroh endpoint info as pkarr packets, directly on the mainline DHT: no DNS and no pkarr
 * relays, so no single party sees which endpoints are looked up (iroh.md §5.2).
 */
public final class Pkarr {

    private final MainlineDht dht;

    public Pkarr(MainlineDht dht) {
        this.dht = dht;
    }

    /**
     * @return  the number of DHT nodes that stored the packet
     */
    public int publish(SignedPacket packet, Duration timeout) {
        return dht.put(new MainlineDht.MutableItem(packet.publicKey().toBytes(), packet.timestamp(), packet.signature(), packet.dnsPacket()), timeout);
    }

    public int publish(SecretKey key, EndpointInfo info, Duration timeout) {
        return publish(info.toSignedPacket(key, nowMicros()), timeout);
    }

    public Optional<SignedPacket> resolvePacket(EndpointId id, Duration timeout) {
        return dht.get(id.toBytes(), timeout)
                .map(item -> SignedPacket.fromParts(id, item.seq(), item.sig(), item.v()));
    }

    public Optional<EndpointInfo> resolve(EndpointId id, Duration timeout) {
        return resolvePacket(id, timeout).map(EndpointInfo::fromSignedPacket);
    }

    public static long nowMicros() {
        java.time.Instant now = java.time.Instant.now();
        return now.getEpochSecond() * 1_000_000 + now.getNano() / 1_000;
    }
}
