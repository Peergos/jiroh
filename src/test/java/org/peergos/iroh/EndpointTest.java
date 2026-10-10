package org.peergos.iroh;

import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicClientConnection;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EndpointTest {

    private static final InetSocketAddress LOCALHOST = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

    @Test
    void endpointIdRoundTripsThroughPublicKey() {
        SecretKey key = SecretKey.generate();
        EndpointId id = key.endpointId();
        assertEquals(id, EndpointId.fromPublicKey(id.toPublicKey()));
        assertEquals(id, EndpointId.fromHex(id.toHex()));
        assertTrue(id.matches(key.keyPair().getPublic()));
    }

    @Test
    void secretKeyDerivationMatchesRfc8032() {
        // RFC 8032 section 7.1, TEST 1
        SecretKey key = SecretKey.fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        assertEquals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", key.endpointId().toHex());
    }

    @Test
    void javaEndpointsShouldConnectAndAuthenticateEachOther() throws Exception {
        EchoProtocol echo = new EchoProtocol();
        SecretKey clientKey = SecretKey.generate();
        try (Endpoint server = Endpoint.bind(SecretKey.generate(), LOCALHOST, Map.of(EchoProtocol.ALPN, echo));
             Endpoint client = Endpoint.bind(clientKey, LOCALHOST, Map.of())) {
            QuicClientConnection connection = client.connect(server.id(), server.localAddress(), EchoProtocol.ALPN);
            assertEquals("hello", EchoProtocol.echo(connection, "hello"));
            assertEquals(server.id(), EndpointId.fromPublicKey(connection.getPeerRawPublicKey()));
            assertEquals(clientKey.endpointId(), echo.lastRemote);
            // The outgoing connection uses the client endpoint's listening socket.
            assertEquals(client.localAddress().getPort(), echo.lastRemoteAddress.getPort());
            assertEquals(client.localAddress(), connection.getLocalAddress());
            connection.close();
        }
    }

    @Test
    void endpointsShouldConnectToEachOtherOverTheirListeningSockets() throws Exception {
        EchoProtocol echoA = new EchoProtocol();
        EchoProtocol echoB = new EchoProtocol();
        try (Endpoint a = Endpoint.bind(SecretKey.generate(), LOCALHOST, Map.of(EchoProtocol.ALPN, echoA));
             Endpoint b = Endpoint.bind(SecretKey.generate(), LOCALHOST, Map.of(EchoProtocol.ALPN, echoB))) {
            // Both directions at once: each endpoint is client and server on the same socket.
            QuicClientConnection aToB = a.connect(b.id(), b.localAddress(), EchoProtocol.ALPN);
            QuicClientConnection bToA = b.connect(a.id(), a.localAddress(), EchoProtocol.ALPN);
            for (int i = 0; i < 5; i++) {
                assertEquals("a" + i, EchoProtocol.echo(aToB, "a" + i));
                assertEquals("b" + i, EchoProtocol.echo(bToA, "b" + i));
            }
            assertEquals(a.localAddress().getPort(), echoB.lastRemoteAddress.getPort());
            assertEquals(b.localAddress().getPort(), echoA.lastRemoteAddress.getPort());
            assertEquals(a.id(), echoB.lastRemote);
            assertEquals(b.id(), echoA.lastRemote);
            aToB.close();
            bToA.close();
        }
    }

    @Test
    void connectShouldFailWhenRemoteHasDifferentKey() throws Exception {
        try (Endpoint server = Endpoint.bind(SecretKey.generate(), LOCALHOST, Map.of(EchoProtocol.ALPN, new EchoProtocol()));
             Endpoint client = Endpoint.bind(SecretKey.generate(), LOCALHOST, Map.of())) {
            EndpointId wrongId = SecretKey.generate().endpointId();
            assertThrows(IOException.class, () -> client.connect(wrongId, server.localAddress(), EchoProtocol.ALPN));
        }
    }
}
