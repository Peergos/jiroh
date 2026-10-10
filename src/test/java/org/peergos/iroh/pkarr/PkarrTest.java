package org.peergos.iroh.pkarr;

import org.junit.jupiter.api.Test;
import org.peergos.iroh.SecretKey;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PkarrTest {

    @Test
    void z32RoundTrips() {
        byte[] key = SecretKey.generate().endpointId().toBytes();
        String encoded = Z32.encode(key);
        assertEquals(52, encoded.length());
        assertArrayEquals(key, Z32.decode(encoded));
    }

    @Test
    void bencodeRoundTripsWithSortedKeys() {
        byte[] encoded = Bencode.encode(Map.of("y", "q", "a", Map.of("id", new byte[]{1, 2}), "seq", 5L));
        assertEquals("d1:ad2:id2:\u0001\u0002e3:seqi5e1:y1:qe", new String(encoded, java.nio.charset.StandardCharsets.ISO_8859_1));
        Map<?, ?> decoded = (Map<?, ?>) Bencode.decode(encoded);
        assertEquals(5L, decoded.get("seq"));
    }

    @Test
    void signedPacketRoundTripsAndVerifies() throws Exception {
        SecretKey key = SecretKey.generate();
        EndpointInfo info = new EndpointInfo(key.endpointId(), List.of(URI.create("https://relay.example/")),
                List.of(new InetSocketAddress(InetAddress.getByName("203.0.113.7"), 4433),
                        new InetSocketAddress(InetAddress.getByName("2001:db8::1"), 4433)));
        SignedPacket packet = info.toSignedPacket(key, 1_700_000_000_000_000L);

        SignedPacket parsed = SignedPacket.fromBytes(packet.toBytes());
        assertEquals(1_700_000_000_000_000L, parsed.timestamp());
        assertEquals(List.of("relay=https://relay.example/", "addr=203.0.113.7:4433", "addr=[2001:db8::1]:4433"), parsed.txt("_iroh"));
        assertEquals(info, EndpointInfo.fromSignedPacket(parsed));
    }

    @Test
    void namesAreCompressed() {
        SecretKey key = SecretKey.generate();
        SignedPacket packet = SignedPacket.sign(key, List.of(
                DnsPacket.Record.txt("_iroh", 30, "a=1"), DnsPacket.Record.txt("_iroh", 30, "a=2")), 1);
        byte[] dns = packet.dnsPacket();
        // header (12) + first name (1+5 + 1+52 + 1) + type/class/ttl/len (10) + rdata (4), then a 2-byte pointer
        int secondName = 12 + 60 + 10 + 4;
        assertEquals((byte) 0xc0, dns[secondName]);
        assertEquals((byte) 12, dns[secondName + 1]);
    }

    @Test
    void tamperedPacketIsRejected() {
        SecretKey key = SecretKey.generate();
        byte[] bytes = SignedPacket.sign(key, List.of(DnsPacket.Record.txt("_iroh", 30, "addr=1.2.3.4:5")), 1).toBytes();
        bytes[bytes.length - 1] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> SignedPacket.fromBytes(bytes));
    }

    @Test
    void addressesAreNeverResolvedByName() {
        assertTrue(EndpointInfo.parse("example.com:80").isEmpty());
        assertTrue(EndpointInfo.parse("10.0.0.1:80").isPresent());
    }
}
