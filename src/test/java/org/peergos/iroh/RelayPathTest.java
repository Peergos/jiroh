package org.peergos.iroh;

import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicClientConnection;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * QUIC over a non-UDP path: the endpoints only reach each other through relay mapped addresses.
 */
class RelayPathTest {

    private static final InetSocketAddress LOCALHOST = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

    @Test
    void connectionShouldWorkOverRelayPath() throws Exception {
        FakeRelay relay = new FakeRelay();
        SecretKey keyA = SecretKey.generate();
        SecretKey keyB = SecretKey.generate();
        FakeRelay.Client relayA = relay.client(keyA.endpointId());
        FakeRelay.Client relayB = relay.client(keyB.endpointId());
        EchoProtocol echoA = new EchoProtocol();
        EchoProtocol echoB = new EchoProtocol();
        try (Endpoint a = Endpoint.bind(keyA, LOCALHOST, Map.of(EchoProtocol.ALPN, echoA), List.of(relayA));
             Endpoint b = Endpoint.bind(keyB, LOCALHOST, Map.of(EchoProtocol.ALPN, echoB), List.of(relayB))) {
            InetSocketAddress bViaRelay = relayA.addressFor(b.id());
            QuicClientConnection aToB = a.connect(b.id(), bViaRelay, EchoProtocol.ALPN);
            assertEquals("over the relay", EchoProtocol.echo(aToB, "over the relay"));
            assertTrue(MappedAddresses.isRelayMapped(echoB.lastRemoteAddress), echoB.lastRemoteAddress.toString());
            assertEquals(a.id(), echoB.lastRemote);

            // And back, while the first connection is still open.
            QuicClientConnection bToA = b.connect(a.id(), relayB.addressFor(a.id()), EchoProtocol.ALPN);
            assertEquals("and back", EchoProtocol.echo(bToA, "and back"));
            assertEquals(b.id(), echoA.lastRemote);

            assertTrue(relay.forwarded.get() > 0);
            aToB.close();
            bToA.close();
        }
    }
}
