package org.peergos.iroh;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.peergos.iroh.pkarr.MainlineDht;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.send.QuicPath;
import tech.kwik.core.impl.QuicConnectionImpl;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The endpoint layer: home relay, publishing with pkarr, dialing by endpoint id and racing paths. Uses n0's
 * iroh-relay and a local mainline DHT testnet.
 */
class EndpointLayerTest {

    private static final Path PROBE = Path.of(System.getProperty("interop.probe.dir", "../interop-probe/target/release"));
    private static final InetSocketAddress LOCALHOST = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

    private static Process testnet;
    private static List<InetSocketAddress> bootstrap;
    private static IrohRelayProcess relay;

    @BeforeAll
    static void start() throws Exception {
        Assumptions.assumeTrue(Files.isExecutable(PROBE.resolve("dht_testnet")), "interop-probe not built");
        Assumptions.assumeTrue(IrohRelayProcess.available(), "iroh-relay not built");
        testnet = new ProcessBuilder(PROBE.resolve("dht_testnet").toString(), "10").redirectErrorStream(true).start();
        String line = new BufferedReader(new InputStreamReader(testnet.getInputStream())).readLine();
        bootstrap = MainlineDht.resolve(Arrays.asList(line.substring("bootstrap: ".length()).split(" ")));
        relay = new IrohRelayProcess();
    }

    @AfterAll
    static void stop() throws Exception {
        if (relay != null) {
            relay.close();
        }
        if (testnet != null) {
            testnet.destroy();
            testnet.waitFor(5, TimeUnit.SECONDS);
        }
    }

    private static MainlineDht dht() throws Exception {
        return MainlineDht.start(LOCALHOST, bootstrap);
    }

    private static Endpoint.Builder endpoint(SecretKey key) throws Exception {
        return Endpoint.builder(key)
                .bind(LOCALHOST)
                .relays(List.of(relay.url))
                .relayQuicPort(null)
                .addressLookup(dht());
    }

    private static void assertActiveRelayPath(QuicClientConnection connection) throws InterruptedException {
        QuicConnectionImpl impl = (QuicConnectionImpl) connection;
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            if (impl.getPaths().stream().anyMatch(p -> p.getState() == QuicPath.State.ACTIVE && MappedAddresses.isRelayMapped(p.getPeerAddress()))) {
                return;
            }
            Thread.sleep(20);
        }
        fail("no active relay path: " + impl.getPaths());
    }

    @Test
    void endpointShouldPublishHomeRelayAndAddress() throws Exception {
        try (Endpoint b = endpoint(SecretKey.generate()).build()) {
            assertEquals(relay.url, b.homeRelay().orElseThrow());
            var published = b.published().orElseThrow();
            assertEquals(List.of(relay.url), published.relayUrls());
            assertEquals(List.of(b.localAddress()), published.directAddresses());
        }
    }

    @Test
    void endpointShouldDialById() throws Exception {
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint b = endpoint(SecretKey.generate()).protocol(EchoProtocol.ALPN, echo).build();
             Endpoint a = endpoint(SecretKey.generate()).publish(false).build()) {
            QuicClientConnection connection = a.connect(b.id(), EchoProtocol.ALPN);
            assertEquals("dialled by id", EchoProtocol.echo(connection, "dialled by id"));
            // The direct path won the race
            assertEquals(a.localAddress(), echo.lastRemoteAddress);
            // and the relay was added as a second path.
            assertActiveRelayPath(connection);
            connection.close();
        }
    }

    @Test
    void connectShouldFallBackToRelayWhenDirectAddressDoesNotWork() throws Exception {
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint b = endpoint(SecretKey.generate()).protocol(EchoProtocol.ALPN, echo).build();
             Endpoint a = endpoint(SecretKey.generate()).publish(false).build()) {
            // 192.0.2.1 (TEST-NET-1) never answers
            EndpointAddr addr = EndpointAddr.of(b.id())
                    .withDirect(new InetSocketAddress(InetAddress.getByName("192.0.2.1"), 4433))
                    .withRelay(relay.url);
            QuicClientConnection connection = a.connect(addr, EchoProtocol.ALPN);
            assertEquals("via the relay", EchoProtocol.echo(connection, "via the relay"));
            assertTrue(MappedAddresses.isRelayMapped(echo.lastRemoteAddress), String.valueOf(echo.lastRemoteAddress));
            connection.close();
        }
    }

    @Test
    void connectShouldReachRustIrohOverItsDirectAddressWhenRacingTheRelay() throws Exception {
        SecretKey serverKey = SecretKey.generate();
        int port;
        try (var s = new java.net.DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        Process server = new ProcessBuilder(PROBE.resolve("server").toString(), "127.0.0.1:" + port,
                HexFormat.of().formatHex(serverKey.toBytes()), relay.url.toString())
                .redirectErrorStream(true).start();
        try (Endpoint a = endpoint(SecretKey.generate()).publish(false).build()) {
            BufferedReader out = new BufferedReader(new InputStreamReader(server.getInputStream()));
            String line;
            while ((line = out.readLine()) != null && !line.startsWith("relay: ")) {
            }
            EndpointAddr addr = EndpointAddr.of(serverKey.endpointId())
                    .withDirect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port))
                    .withRelay(relay.url);
            QuicClientConnection connection = a.connect(addr, EchoProtocol.ALPN);
            assertEquals("raced", EchoProtocol.echo(connection, "raced"));
            assertFalse(MappedAddresses.isRelayMapped(connection.getServerAddress()), String.valueOf(connection.getServerAddress()));
            assertActiveRelayPath(connection);
            assertEquals("with two paths", EchoProtocol.echo(connection, "with two paths"));
            connection.close();
        }
        finally {
            server.destroy();
            server.waitFor(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void endpointShouldPublishAddressObservedByRelay() throws Exception {
        try (IrohRelayProcess tlsRelay = IrohRelayProcess.withQuicAddressDiscovery();
             Endpoint b = Endpoint.builder(SecretKey.generate())
                     .bind(LOCALHOST)
                     .relays(List.of(tlsRelay.url))
                     .relayQuicPort(tlsRelay.quicPort)
                     .relayTrustManager(tlsRelay.trustManager())
                     .addressLookup(dht())
                     .build()) {
            assertEquals(b.localAddress(), b.observedAddress().orElseThrow());
            // Over loopback the observed address is the local one, so it appears once.
            assertEquals(List.of(b.localAddress()), b.published().orElseThrow().directAddresses());
        }
    }
}
