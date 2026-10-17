package org.peergos.iroh;

import static org.peergos.iroh.RelayProtocol.*;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicClientConnection;

import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** {@link RelayServer} behaviour beyond what {@link JavaRelayInteropTest} covers. */
class RelayServerTest {

    private static final InetSocketAddress LOCALHOST = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final Path PROBE = Path.of(System.getProperty("interop.probe.dir", "../interop-probe/target/release"));

    private RelayServer server;

    @BeforeEach
    void start() throws IOException {
        server = RelayServer.builder().start();
    }

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void httpRoutesShouldAnswer() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        assertEquals(200, get(client, "ping"));
        assertEquals(204, get(client, "generate_204"));
        assertEquals(200, get(client, ""));
        assertEquals(404, get(client, "nothing-here"));
        assertEquals(400, get(client, "relay"));
    }

    private int get(HttpClient client, String path) throws Exception {
        return client.send(HttpRequest.newBuilder(server.url().resolve("/" + path)).build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    @Test
    void accessControlShouldDenyEndpoints() throws Exception {
        SecretKey denied = SecretKey.generate();
        try (RelayServer guarded = RelayServer.builder().accessControl(id -> !id.equals(denied.endpointId())).start()) {
            IOException error = assertThrows(IOException.class, () -> RelayTransport.connect(guarded.url(), denied, TIMEOUT));
            assertTrue(error.getMessage().contains("not authorized"), error.getMessage());
            try (RelayTransport allowed = RelayTransport.connect(guarded.url(), SecretKey.generate(), TIMEOUT)) {
                assertTrue(allowed.isConnected());
            }
        }
    }

    @Test
    void javaEndpointsShouldConnectOverTls() throws Exception {
        Path dir = Files.createTempDirectory("relay-tls");
        Path cert = dir.resolve("cert.pem");
        Path key = dir.resolve("key.pem");
        IrohRelayProcess.selfSignedCertificate(cert, key);
        X509TrustManager trust = IrohRelayProcess.trustManager(cert);
        try (JavaRelay relay = new JavaRelay(RelayCertificate.fromPem(cert, key))) {
            assertEquals("https", relay.url().getScheme());
            SecretKey keyA = SecretKey.generate();
            SecretKey keyB = SecretKey.generate();
            RelayTransport relayA = RelayTransport.connect(relay.url(), keyA, TIMEOUT, trust);
            RelayTransport relayB = RelayTransport.connect(relay.url(), keyB, TIMEOUT, trust);
            try (Endpoint a = Endpoint.bind(keyA, LOCALHOST, Map.of(), List.of(relayA));
                 Endpoint b = Endpoint.bind(keyB, LOCALHOST, Map.of(EchoProtocol.ALPN, new EchoProtocol()), List.of(relayB))) {
                QuicClientConnection connection = a.connect(b.id(), relayA.addressFor(b.id()), EchoProtocol.ALPN);
                assertEquals("over wss", EchoProtocol.echo(connection, "over wss"));
                connection.close();
            }
        }
    }

    /** Rust iroh sends a client auth header signed over TLS keying material, which saves the challenge round trip. */
    @Test
    void rustIrohShouldAuthenticateWithTlsKeyingMaterial() throws Exception {
        Assumptions.assumeTrue(Files.isExecutable(PROBE.resolve("iroh_client")), "interop-probe not built");
        Path dir = Files.createTempDirectory("relay-tls");
        Path cert = dir.resolve("cert.pem");
        Path key = dir.resolve("key.pem");
        IrohRelayProcess.selfSignedCertificate(cert, key);
        try (JavaRelay relay = new JavaRelay(RelayCertificate.fromPem(cert, key))) {
            SecretKey serverKey = SecretKey.generate();
            RelayTransport transport = RelayTransport.connect(relay.url(), serverKey, TIMEOUT, IrohRelayProcess.trustManager(cert));
            try (Endpoint endpoint = Endpoint.bind(serverKey, LOCALHOST, Map.of(EchoProtocol.ALPN, new EchoProtocol()), List.of(transport))) {
                ProcessBuilder builder = new ProcessBuilder(PROBE.resolve("iroh_client").toString(), "-", endpoint.id().toHex(), "3",
                        relay.url().toString())
                        .redirectErrorStream(true);
                builder.environment().put("IROH_RELAY_CA", cert.toString());
                Process client = builder.start();
                boolean exited = client.waitFor(30, TimeUnit.SECONDS);
                String output = new String(client.getInputStream().readAllBytes());
                if (!exited) {
                    client.destroyForcibly();
                    fail("rust client did not finish:\n" + output);
                }
                assertEquals(0, client.exitValue(), output);
                assertTrue(output.contains("echo ok: hello from rust iroh #2"), output);
                assertEquals(1, relay.server().keyMaterialAuthentications());
            }
        }
    }

    @Test
    void datagramsAndBatchesShouldBeForwardedWithTheSource() throws Exception {
        SecretKey a = SecretKey.generate();
        SecretKey b = SecretKey.generate();
        try (RawClient clientA = RawClient.connect(server.url(), a, V2);
             RawClient clientB = RawClient.connect(server.url(), b, V2)) {
            clientB.send(datagram(CLIENT_TO_RELAY_DATAGRAM, a.endpointId(), new byte[]{0}, "hello"));
            assertArrayEquals(datagram(RELAY_TO_CLIENT_DATAGRAM, b.endpointId(), new byte[]{0}, "hello"), clientA.next());

            byte[] batchHeader = {2, 0, 3}; // ECN, segment size 3
            clientB.send(datagram(CLIENT_TO_RELAY_DATAGRAM_BATCH, a.endpointId(), batchHeader, "abcdefgh"));
            assertArrayEquals(datagram(RELAY_TO_CLIENT_DATAGRAM_BATCH, b.endpointId(), batchHeader, "abcdefgh"), clientA.next());
        }
    }

    @Test
    void pingShouldBeAnswered() throws Exception {
        try (RawClient client = RawClient.connect(server.url(), SecretKey.generate(), V2)) {
            byte[] ping = {PING, 1, 2, 3, 4, 5, 6, 7, 8};
            client.send(ping);
            byte[] pong = ping.clone();
            pong[0] = PONG;
            assertArrayEquals(pong, client.next());
        }
    }

    /** As iroh-relay does, an endpoint's departure is announced to the peers it sent to. */
    @Test
    void peersShouldBeToldWhenAnEndpointIsGone() throws Exception {
        SecretKey a = SecretKey.generate();
        SecretKey b = SecretKey.generate();
        try (RawClient clientB = RawClient.connect(server.url(), b, V2)) {
            RawClient clientA = RawClient.connect(server.url(), a, V2);
            clientA.send(datagram(CLIENT_TO_RELAY_DATAGRAM, b.endpointId(), new byte[]{0}, "x"));
            clientB.next();
            clientA.close();
            assertArrayEquals(concat(new byte[]{ENDPOINT_GONE}, a.endpointId().toBytes()), clientB.next());
        }
    }

    @Test
    void newConnectionShouldTakeOverAndHandBackTheEndpointId() throws Exception {
        SecretKey a = SecretKey.generate();
        SecretKey b = SecretKey.generate();
        try (RawClient first = RawClient.connect(server.url(), a, V2);
             RawClient sender = RawClient.connect(server.url(), b, V2)) {
            RawClient second = RawClient.connect(server.url(), a, V2);
            assertArrayEquals(new byte[]{STATUS, STATUS_SAME_ENDPOINT_ID_CONNECTED}, first.next());
            sender.send(datagram(CLIENT_TO_RELAY_DATAGRAM, a.endpointId(), new byte[]{0}, "to second"));
            assertArrayEquals(datagram(RELAY_TO_CLIENT_DATAGRAM, b.endpointId(), new byte[]{0}, "to second"), second.next());

            second.close();
            assertArrayEquals(new byte[]{STATUS, STATUS_HEALTHY}, first.next());
            sender.send(datagram(CLIENT_TO_RELAY_DATAGRAM, a.endpointId(), new byte[]{0}, "to first"));
            assertArrayEquals(datagram(RELAY_TO_CLIENT_DATAGRAM, b.endpointId(), new byte[]{0}, "to first"), first.next());
            assertTrue(server.isConnected(a.endpointId()));
        }
    }

    @Test
    void v1ClientsShouldGetHealthInsteadOfStatus() throws Exception {
        SecretKey a = SecretKey.generate();
        try (RawClient first = RawClient.connect(server.url(), a, V1);
             RawClient second = RawClient.connect(server.url(), a, V1)) {
            assertEquals(V1, first.protocol);
            byte[] health = first.next();
            assertEquals(HEALTH, health[0]);
            assertTrue(new String(health, 1, health.length - 1, StandardCharsets.UTF_8).contains("same endpoint id"));
        }
    }

    @Test
    void badChallengeSignatureShouldBeDenied() throws Exception {
        RawClient client = RawClient.open(server.url(), V2);
        try (client) {
            byte[] challenge = client.next();
            assertEquals(SERVER_CHALLENGE, challenge[0]);
            SecretKey key = SecretKey.generate();
            byte[] signature = sign(key, challengeMessage(Arrays.copyOfRange(challenge, 1, 17)));
            signature[0] ^= 1;
            client.send(concat(new byte[]{CLIENT_AUTH}, key.endpointId().toBytes(), new byte[]{64}, signature));
            byte[] denial = client.next();
            assertEquals(SERVER_DENIES_AUTH, denial[0]);
            assertEquals("signature invalid", new String(denial, 2, denial[1], StandardCharsets.UTF_8));
            assertFalse(server.isConnected(key.endpointId()));
        }
    }

    @Test
    void quicAddressDiscoveryShouldReportTheEndpointsAddress() throws Exception {
        Path dir = Files.createTempDirectory("relay-qad");
        Path cert = dir.resolve("cert.pem");
        Path key = dir.resolve("key.pem");
        IrohRelayProcess.selfSignedCertificate(cert, key);
        RelayCertificate certificate = RelayCertificate.fromPem(cert, key);
        try (RelayServer relay = RelayServer.builder().tls(certificate).quicAddressDiscovery(LOCALHOST).start();
             Endpoint endpoint = Endpoint.bind(SecretKey.generate(), LOCALHOST, Map.of())) {
            InetSocketAddress qad = new InetSocketAddress(InetAddress.getLoopbackAddress(), relay.quicPort().orElseThrow());
            X509TrustManager trust = IrohRelayProcess.trustManager(cert);
            assertEquals(endpoint.localAddress(), QuicAddressDiscovery.observe(endpoint, qad, trust, TIMEOUT));
            assertEquals(1, relay.metrics().qadConnections.sum());

            // A new certificate restarts the QAD server on the same port.
            Path cert2 = dir.resolve("cert2.pem");
            Path key2 = dir.resolve("key2.pem");
            IrohRelayProcess.selfSignedCertificate(cert2, key2);
            certificate.update(RelayCertificate.readPrivateKey(key2), RelayCertificate.readChain(cert2));
            assertEquals(qad.getPort(), relay.quicPort().orElseThrow());
            assertEquals(endpoint.localAddress(), QuicAddressDiscovery.observe(endpoint, qad, IrohRelayProcess.trustManager(cert2), TIMEOUT));
        }
    }

    /** Rust iroh probes QAD on port 7842 of its relay's host, so this needs that port free. */
    @Test
    void rustIrohShouldDiscoverItsAddressFromJavaQad() throws Exception {
        Assumptions.assumeTrue(Files.isExecutable(PROBE.resolve("iroh_client")), "interop-probe not built");
        InetSocketAddress qadAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), QuicAddressDiscovery.DEFAULT_RELAY_QUIC_PORT);
        try (java.net.DatagramSocket probe = new java.net.DatagramSocket(qadAddress)) {
            // free
        }
        catch (java.net.SocketException taken) {
            Assumptions.abort("UDP port 7842 is in use");
        }
        Path dir = Files.createTempDirectory("relay-qad");
        Path cert = dir.resolve("cert.pem");
        Path key = dir.resolve("key.pem");
        IrohRelayProcess.selfSignedCertificate(cert, key);
        try (RelayServer relay = RelayServer.builder().tls(RelayCertificate.fromPem(cert, key)).quicAddressDiscovery(qadAddress).start()) {
            SecretKey serverKey = SecretKey.generate();
            RelayTransport transport = RelayTransport.connect(relay.url(), serverKey, TIMEOUT, IrohRelayProcess.trustManager(cert));
            try (Endpoint endpoint = Endpoint.bind(serverKey, LOCALHOST, Map.of(EchoProtocol.ALPN, new EchoProtocol()), List.of(transport))) {
                ProcessBuilder builder = new ProcessBuilder(PROBE.resolve("iroh_client").toString(), "-", endpoint.id().toHex(), "1",
                        relay.url().toString())
                        .redirectErrorStream(true);
                builder.environment().put("IROH_RELAY_CA", cert.toString());
                builder.environment().put("RUST_LOG", "iroh::net_report=debug");
                Process client = builder.start();
                boolean exited = client.waitFor(30, TimeUnit.SECONDS);
                String output = new String(client.getInputStream().readAllBytes()).replaceAll("\u001b\\[[0-9;]*m", "");
                if (!exited) {
                    client.destroyForcibly();
                    fail("rust client did not finish:\n" + output);
                }
                assertEquals(0, client.exitValue(), output);
                assertTrue(output.matches("(?s).*QadProbeReport \\{ relay: RelayUrl\\(\"" + java.util.regex.Pattern.quote(relay.url().toString())
                        + "\"\\), latency: [^,]+, addr: 127\\.0\\.0\\.1:\\d+ }.*"), output);
                assertTrue(relay.metrics().qadConnections.sum() >= 1);
            }
        }
    }

    @Test
    void clientsOverTheRateLimitShouldBeSlowedAndTold() throws Exception {
        // 20 kB/s with a 2 kB burst: 20 frames of 1 kB take about a second to get through.
        try (RelayServer limited = RelayServer.builder().clientRateLimit(new RelayServer.RateLimit(20_000, 2_000)).start()) {
            SecretKey a = SecretKey.generate();
            SecretKey b = SecretKey.generate();
            try (RawClient sender = RawClient.connect(limited.url(), a, V2);
                 RawClient receiver = RawClient.connect(limited.url(), b, V2)) {
                String payload = "x".repeat(1000 - 34);
                long start = System.nanoTime();
                for (int i = 0; i < 20; i++) {
                    sender.send(datagram(CLIENT_TO_RELAY_DATAGRAM, b.endpointId(), new byte[]{0}, payload));
                }
                for (int i = 0; i < 20; i++) {
                    assertEquals(RELAY_TO_CLIENT_DATAGRAM, receiver.next()[0]);
                }
                long millis = (System.nanoTime() - start) / 1_000_000;
                assertTrue(millis >= 800, "20 kB at 20 kB/s took " + millis + "ms");
                assertArrayEquals(new byte[]{STATUS, STATUS_RATE_LIMITED}, sender.next());
                assertEquals(1, limited.metrics().connsRxRatelimited.sum());
                assertTrue(limited.metrics().bytesRxRatelimited.sum() > 0);
            }
        }
    }

    @Test
    void acceptsShouldBeRateLimited() throws Exception {
        try (RelayServer limited = RelayServer.builder().acceptRateLimit(new RelayServer.RateLimit(10, 1)).start()) {
            HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
            long start = System.nanoTime();
            for (int i = 0; i < 6; i++) {
                // A new connection each time: the server closes after each response.
                assertEquals(200, client.send(HttpRequest.newBuilder(limited.url().resolve("/ping")).build(),
                        HttpResponse.BodyHandlers.discarding()).statusCode());
            }
            long millis = (System.nanoTime() - start) / 1_000_000;
            assertTrue(millis >= 400, "6 connections at 10/s took " + millis + "ms");
        }
    }

    @Test
    void metricsShouldBeServedAsOpenMetrics() throws Exception {
        try (RelayServer relay = RelayServer.builder().metricsBind(LOCALHOST).start()) {
            SecretKey a = SecretKey.generate();
            SecretKey b = SecretKey.generate();
            try (RawClient clientA = RawClient.connect(relay.url(), a, V2);
                 RawClient clientB = RawClient.connect(relay.url(), b, V2)) {
                clientA.send(datagram(CLIENT_TO_RELAY_DATAGRAM, b.endpointId(), new byte[]{0}, "hello"));
                clientB.next();
                clientA.send(datagram(CLIENT_TO_RELAY_DATAGRAM, SecretKey.generate().endpointId(), new byte[]{0}, "nobody"));
                clientA.send(new byte[]{PING, 1, 2, 3, 4, 5, 6, 7, 8});
                clientA.next();
            }
            HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                    URI.create("http://127.0.0.1:" + relay.metricsAddress().orElseThrow().getPort() + "/metrics")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            String text = response.body();
            assertTrue(text.contains("relayserver_send_packets_recv_total 2\n"), text);
            assertTrue(text.contains("relayserver_send_packets_sent_total 1\n"), text);
            assertTrue(text.contains("relayserver_send_packets_dropped_total 1\n"), text);
            assertTrue(text.contains("relayserver_bytes_sent_total 5\n"), text);
            assertTrue(text.contains("relayserver_got_ping_total 1\n"), text);
            assertTrue(text.contains("relayserver_sent_pong_total 1\n"), text);
            assertTrue(text.contains("relayserver_unique_client_keys_total 2\n"), text);
            assertTrue(text.contains("relayserver_bytes_rx_ratelimited_total 0\n"), text);
            assertTrue(text.endsWith("# EOF\n"), text);
        }
    }

    /** The same metric names, help and types as n0's iroh-relay, so its dashboards work. */
    @Test
    void metricsShouldMatchIrohRelays() throws Exception {
        Assumptions.assumeTrue(IrohRelayProcess.available(), "iroh-relay not built");
        Path dir = Files.createTempDirectory("relay-metrics");
        int port;
        int metricsPort;
        try (java.net.ServerSocket s1 = new java.net.ServerSocket(0); java.net.ServerSocket s2 = new java.net.ServerSocket(0)) {
            port = s1.getLocalPort();
            metricsPort = s2.getLocalPort();
        }
        Path config = dir.resolve("relay.toml");
        Files.writeString(config, "http_bind_addr = \"127.0.0.1:" + port + "\"\nenable_metrics = true\nmetrics_bind_addr = \"127.0.0.1:" + metricsPort + "\"\n");
        Process process = new ProcessBuilder(IrohRelayProcess.BINARY.toString(), "--dev", "-c", config.toString())
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        try {
            HttpClient client = HttpClient.newHttpClient();
            String theirs = null;
            for (int i = 0; i < 100 && theirs == null; i++) {
                try {
                    theirs = client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + metricsPort + "/metrics")).build(),
                            HttpResponse.BodyHandlers.ofString()).body();
                }
                catch (IOException notYet) {
                    Thread.sleep(50);
                }
            }
            assertNotNull(theirs, "iroh-relay metrics did not come up");
            assertEquals(theirs.replaceAll("(?m)^(\\S+) \\d+$", "$1 0"), new RelayMetrics().render());
        }
        finally {
            process.destroy();
            process.waitFor(5, TimeUnit.SECONDS);
        }
    }

    private static byte[] datagram(int type, EndpointId id, byte[] header, String contents) {
        return concat(new byte[]{(byte) type}, id.toBytes(), header, contents.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /** A relay client that exchanges raw relay frames. */
    private static final class RawClient implements WebSocket.Listener, AutoCloseable {
        private final BlockingQueue<byte[]> frames = new LinkedBlockingQueue<>();
        private final ByteArrayOutputStream partial = new ByteArrayOutputStream();
        private WebSocket webSocket;
        String protocol;

        static RawClient open(URI relay, String protocol) throws Exception {
            RawClient client = new RawClient();
            client.webSocket = HttpClient.newHttpClient().newWebSocketBuilder()
                    .subprotocols(protocol)
                    .buildAsync(URI.create("ws://" + relay.getRawAuthority() + RELAY_PATH), client)
                    .get(10, TimeUnit.SECONDS);
            client.protocol = client.webSocket.getSubprotocol();
            return client;
        }

        static RawClient connect(URI relay, SecretKey key, String protocol) throws Exception {
            RawClient client = open(relay, protocol);
            byte[] challenge = client.next();
            assertEquals(SERVER_CHALLENGE, challenge[0]);
            byte[] signature = sign(key, challengeMessage(Arrays.copyOfRange(challenge, 1, 17)));
            client.send(concat(new byte[]{CLIENT_AUTH}, key.endpointId().toBytes(), new byte[]{64}, signature));
            assertArrayEquals(new byte[]{SERVER_CONFIRMS_AUTH}, client.next());
            return client;
        }

        void send(byte[] frame) throws Exception {
            webSocket.sendBinary(ByteBuffer.wrap(frame), true).get(5, TimeUnit.SECONDS);
        }

        byte[] next() throws InterruptedException {
            byte[] frame = frames.poll(5, TimeUnit.SECONDS);
            assertNotNull(frame, "no frame from the relay");
            return frame;
        }

        @Override
        public void onOpen(WebSocket webSocket) {
            webSocket.request(1);
        }

        @Override
        public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
            byte[] bytes = new byte[data.remaining()];
            data.get(bytes);
            partial.writeBytes(bytes);
            if (last) {
                frames.add(partial.toByteArray());
                partial.reset();
            }
            webSocket.request(1);
            return null;
        }

        @Override
        public void close() {
            webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "").orTimeout(5, TimeUnit.SECONDS).exceptionally(e -> null).join();
        }
    }
}
