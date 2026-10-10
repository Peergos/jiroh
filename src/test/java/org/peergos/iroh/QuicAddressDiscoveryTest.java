package org.peergos.iroh;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** QUIC address discovery against n0's iroh-relay 1.3. */
class QuicAddressDiscoveryTest {

    @Test
    void relayShouldReportEndpointsAddress() throws Exception {
        Assumptions.assumeTrue(IrohRelayProcess.available(), "iroh-relay not built");
        try (IrohRelayProcess relay = IrohRelayProcess.withQuicAddressDiscovery();
             Endpoint endpoint = Endpoint.bind(SecretKey.generate(), new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), Map.of())) {
            InetSocketAddress observed = QuicAddressDiscovery.observe(endpoint,
                    new InetSocketAddress(InetAddress.getLoopbackAddress(), relay.quicPort), relay.trustManager(), Duration.ofSeconds(10));
            // Over loopback there is no NAT, so the relay sees the endpoint's own socket, which proves the probe
            // went out from it.
            assertEquals(endpoint.localAddress(), observed);
        }
    }

    @Test
    void javaServerShouldReportClientsAddress() throws Exception {
        SecretKey serverKey = SecretKey.generate();
        java.net.DatagramSocket socket = new java.net.DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        tech.kwik.core.server.ServerConnector server = tech.kwik.core.server.ServerConnector.builder()
                .withSocket(socket)
                .withLogger(new tech.kwik.core.log.NullLogger())
                .withRawPublicKey(serverKey.keyPair())
                .requireClientRawPublicKey(key -> true)
                .build();
        server.registerApplicationProtocol(QuicAddressDiscovery.ALPN, new tech.kwik.core.server.ApplicationProtocolConnectionFactory() {
            @Override
            public tech.kwik.core.server.ApplicationProtocolConnection createConnection(String protocol, tech.kwik.core.QuicConnection connection) {
                return new tech.kwik.core.server.ApplicationProtocolConnection() {};
            }

            @Override
            public int maxConcurrentPeerInitiatedBidirectionalStreams() {
                return 0;
            }

            @Override
            public boolean sendObservedAddressReports() {
                return true;
            }
        });
        server.start();
        try (Endpoint client = Endpoint.bind(SecretKey.generate(), new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), Map.of())) {
            tech.kwik.core.QuicClientConnection connection = tech.kwik.core.QuicClientConnection.newBuilder()
                    .host("127.0.0.1")
                    .port(socket.getLocalPort())
                    .applicationProtocol(QuicAddressDiscovery.ALPN)
                    .serverRawPublicKey(serverKey.endpointId()::matches)
                    .clientRawPublicKey(SecretKey.generate().keyPair())
                    .addressDiscovery(false, true)
                    .sharedEndpoint(client.sharedEndpoint())
                    .build();
            java.util.concurrent.CompletableFuture<InetSocketAddress> observed = new java.util.concurrent.CompletableFuture<>();
            connection.setObservedAddressListener(observed::complete);
            connection.connect();
            assertEquals(client.localAddress(), observed.get(10, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(client.localAddress(), connection.getObservedAddress());
            connection.close();
        }
        finally {
            server.close();
            socket.close();
        }
    }
}
