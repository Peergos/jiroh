package org.peergos.iroh;

import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.send.QuicPath;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NatTraversalTest {

    private static final InetSocketAddress LOCALHOST = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

    @Test
    void clientConnectedOverTheRelayShouldFindTheDirectPath() throws Exception {
        FakeRelay relay = new FakeRelay();
        relay.delayMillis = 20;
        SecretKey keyA = SecretKey.generate();
        SecretKey keyB = SecretKey.generate();
        FakeRelay.Client relayA = relay.client(keyA.endpointId());
        FakeRelay.Client relayB = relay.client(keyB.endpointId());
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint a = Endpoint.builder(keyA).bind(LOCALHOST).publish(false).relayQuicPort(null).transport(relayA).build();
             Endpoint b = Endpoint.builder(keyB).bind(LOCALHOST).publish(false).relayQuicPort(null).transport(relayB)
                     .protocol(EchoProtocol.ALPN, echo).build()) {
            QuicClientConnection connection = a.connect(b.id(), relayA.addressFor(b.id()), EchoProtocol.ALPN);
            QuicConnectionImpl impl = (QuicConnectionImpl) connection;
            CompletableFuture<QuicPath> active = new CompletableFuture<>();
            impl.setPathListener(active::complete);
            assertEquals("over the relay", EchoProtocol.echo(connection, "over the relay"));
            assertTrue(impl.isNatTraversalEnabled());

            QuicPath direct = active.get(5, TimeUnit.SECONDS);
            assertEquals(b.localAddress(), direct.getPeerAddress());
            assertEquals(List.of(b.localAddress()), impl.getRemoteNatTraversalAddresses());
            assertEquals("direct", EchoProtocol.echo(connection, "direct"));
            connection.close();
        }
    }

    @Test
    void withoutNatTraversalTheConnectionStaysOnTheRelay() throws Exception {
        FakeRelay relay = new FakeRelay();
        SecretKey keyA = SecretKey.generate();
        SecretKey keyB = SecretKey.generate();
        FakeRelay.Client relayA = relay.client(keyA.endpointId());
        FakeRelay.Client relayB = relay.client(keyB.endpointId());
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint a = Endpoint.builder(keyA).bind(LOCALHOST).publish(false).relayQuicPort(null).transport(relayA)
                     .natTraversal(false).build();
             Endpoint b = Endpoint.builder(keyB).bind(LOCALHOST).publish(false).relayQuicPort(null).transport(relayB)
                     .protocol(EchoProtocol.ALPN, echo).build()) {
            QuicClientConnection connection = a.connect(b.id(), relayA.addressFor(b.id()), EchoProtocol.ALPN);
            QuicConnectionImpl impl = (QuicConnectionImpl) connection;
            assertEquals("over the relay", EchoProtocol.echo(connection, "over the relay"));
            assertTrue(!impl.isNatTraversalEnabled());
            Thread.sleep(1000);
            assertTrue(impl.getPaths().isEmpty());
            connection.close();
        }
    }
}
