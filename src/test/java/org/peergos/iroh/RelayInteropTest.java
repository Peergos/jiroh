package org.peergos.iroh;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicClientConnection;

import java.io.BufferedReader;
import java.io.IOException;
import tech.kwik.core.send.QuicPath;
import tech.kwik.core.impl.QuicConnectionImpl;
import java.util.concurrent.CompletableFuture;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Relay paths through n0's iroh-relay 1.3 (build with: cargo build --release -p iroh-relay --features server
 * --bin iroh-relay in ../iroh), between Java endpoints and against Rust iroh.
 */
class RelayInteropTest {

    private static final InetSocketAddress LOCALHOST = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final Path PROBE = Path.of(System.getProperty("interop.probe.dir", "../interop-probe/target/release"));

    private IrohRelayProcess relay;

    @BeforeEach
    void startRelay() throws Exception {
        Assumptions.assumeTrue(IrohRelayProcess.available(), "iroh-relay not built");
        relay = new IrohRelayProcess();
    }

    @AfterEach
    void stopRelay() {
        if (relay != null) {
            relay.close();
        }
    }

    @Test
    void relayShouldAuthenticateJavaClient() throws Exception {
        try (RelayTransport transport = connect(SecretKey.generate())) {
            assertEquals("iroh-relay-v2", transport.protocol());
        }
    }

    @Test
    void javaEndpointsShouldConnectViaRelay() throws Exception {
        SecretKey keyA = SecretKey.generate();
        SecretKey keyB = SecretKey.generate();
        RelayTransport relayA = connect(keyA);
        RelayTransport relayB = connect(keyB);
        EchoProtocol echoB = new EchoProtocol();
        try (Endpoint a = Endpoint.bind(keyA, LOCALHOST, Map.of(), List.of(relayA));
             Endpoint b = Endpoint.bind(keyB, LOCALHOST, Map.of(EchoProtocol.ALPN, echoB), List.of(relayB))) {
            QuicClientConnection connection = a.connect(b.id(), relayA.addressFor(b.id()), EchoProtocol.ALPN);
            assertEquals("via iroh-relay", EchoProtocol.echo(connection, "via iroh-relay"));
            assertTrue(MappedAddresses.isRelayMapped(echoB.lastRemoteAddress));
            assertEquals(a.id(), echoB.lastRemote);
            connection.close();
        }
    }

    @Test
    void connectionShouldSurviveRelayRestart() throws Exception {
        connectionShouldSurviveRelayOutage(0);
    }

    @Test
    void connectionShouldSurviveRelayOutageWithFailedReconnects() throws Exception {
        connectionShouldSurviveRelayOutage(2000);
    }

    private void connectionShouldSurviveRelayOutage(long downMillis) throws Exception {
        SecretKey keyA = SecretKey.generate();
        SecretKey keyB = SecretKey.generate();
        RelayTransport relayA = connect(keyA);
        RelayTransport relayB = connect(keyB);
        EchoProtocol echoB = new EchoProtocol();
        try (Endpoint a = Endpoint.bind(keyA, LOCALHOST, Map.of(), List.of(relayA));
             Endpoint b = Endpoint.bind(keyB, LOCALHOST, Map.of(EchoProtocol.ALPN, echoB), List.of(relayB))) {
            QuicClientConnection connection = a.connect(b.id(), relayA.addressFor(b.id()), EchoProtocol.ALPN);
            assertEquals("before", EchoProtocol.echo(connection, "before"));

            relay.restart(downMillis);
            long deadline = System.currentTimeMillis() + 15_000;
            while (!(relayA.connectionCount() >= 2 && relayA.isConnected() && relayB.connectionCount() >= 2 && relayB.isConnected())) {
                assertTrue(System.currentTimeMillis() < deadline, "relay transports did not reconnect");
                Thread.sleep(50);
            }

            // The same QUIC connection: the mapped addresses are unchanged, so QUIC just sees some lost packets.
            assertEquals("after", EchoProtocol.echo(connection, "after"));
            connection.close();
        }
    }

    @Test
    void javaShouldConnectToRustIrohViaRelay() throws Exception {
        Assumptions.assumeTrue(Files.isExecutable(PROBE.resolve("server")), "interop-probe not built");
        SecretKey serverKey = SecretKey.generate();
        Process server = new ProcessBuilder(PROBE.resolve("server").toString(), "127.0.0.1:0",
                HexFormat.of().formatHex(serverKey.toBytes()), relay.url.toString())
                .redirectErrorStream(true)
                .start();
        try {
            BufferedReader out = new BufferedReader(new InputStreamReader(server.getInputStream()));
            waitForLine(out, "relay: ");

            SecretKey clientKey = SecretKey.generate();
            RelayTransport transport = connect(clientKey);
            try (Endpoint client = Endpoint.bind(clientKey, LOCALHOST, Map.of(), List.of(transport))) {
                // Only the relay path: the Rust endpoint's UDP address is never given.
                QuicClientConnection connection = client.connect(serverKey.endpointId(),
                        transport.addressFor(serverKey.endpointId()), EchoProtocol.ALPN);
                for (int i = 0; i < 3; i++) {
                    assertEquals("relayed #" + i, EchoProtocol.echo(connection, "relayed #" + i));
                }
                connection.close();
            }
        }
        finally {
            server.destroy();
            server.waitFor(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void rustIrohShouldConnectToJavaViaRelay() throws Exception {
        Assumptions.assumeTrue(Files.isExecutable(PROBE.resolve("iroh_client")), "interop-probe not built");
        SecretKey serverKey = SecretKey.generate();
        RelayTransport transport = connect(serverKey);
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint server = Endpoint.bind(serverKey, LOCALHOST, Map.of(EchoProtocol.ALPN, echo), List.of(transport))) {
            Process client = new ProcessBuilder(PROBE.resolve("iroh_client").toString(), "-", server.id().toHex(), "3",
                    relay.url.toString())
                    .redirectErrorStream(true)
                    .start();
            boolean exited = client.waitFor(30, TimeUnit.SECONDS);
            String output = new String(client.getInputStream().readAllBytes());
            if (!exited) {
                client.destroyForcibly();
                fail("rust client did not finish:\n" + output);
            }
            assertEquals(0, client.exitValue(), output);
            assertTrue(output.contains("echo ok: hello from rust iroh #2"), output);
            assertTrue(MappedAddresses.isRelayMapped(echo.lastRemoteAddress), String.valueOf(echo.lastRemoteAddress));
        }
    }

    @Test
    void rustIrohShouldOpenAPathBesideTheRelay() throws Exception {
        Assumptions.assumeTrue(Files.isExecutable(PROBE.resolve("iroh_client")), "interop-probe not built");
        SecretKey serverKey = SecretKey.generate();
        RelayTransport transport = connect(serverKey);
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint server = Endpoint.builder(serverKey).bind(LOCALHOST).publish(false).relayQuicPort(null).maxPathId(4)
                .transport(transport).protocol(EchoProtocol.ALPN, echo).build()) {
            InetSocketAddress direct = server.localAddress();
            ProcessBuilder builder = new ProcessBuilder(PROBE.resolve("iroh_client").toString(),
                    direct.getAddress().getHostAddress() + ":" + direct.getPort(), server.id().toHex(), "3", relay.url.toString())
                    .redirectErrorStream(true);
            builder.environment().put("IROH_CLIENT_LINGER_MS", "3000");
            Process client = builder.start();
            boolean exited = client.waitFor(30, TimeUnit.SECONDS);
            String output = new String(client.getInputStream().readAllBytes());
            System.out.println(output);
            if (!exited) {
                client.destroyForcibly();
                fail("rust client did not finish:\n" + output);
            }
            assertEquals(0, client.exitValue(), output);
            assertTrue(output.contains("echo ok: after linger"), output);
            // iroh dialled the direct address as path 0 and opened path 1 over the relay, validating it both ways.
            assertTrue(output.contains("client path event: Opened { id: PathId(1), remote_addr: Relay("), output);
            String path1 = output.substring(output.indexOf("Closed { id: PathId(1)"));
            assertTrue(path1.contains("frame_rx: FrameStats {") && path1.substring(path1.indexOf("frame_rx")).contains("PATH_RESPONSE: 1"), output);
        }
    }

    @Test
    void javaShouldOpenADirectPathToRustIroh() throws Exception {
        Assumptions.assumeTrue(Files.isExecutable(PROBE.resolve("server")), "interop-probe not built");
        SecretKey serverKey = SecretKey.generate();
        Process server = new ProcessBuilder(PROBE.resolve("server").toString(), "127.0.0.1:0",
                HexFormat.of().formatHex(serverKey.toBytes()), relay.url.toString())
                .redirectErrorStream(true)
                .start();
        StringBuffer serverOutput = new StringBuffer();
        CompletableFuture<Integer> boundPort = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try (BufferedReader out = new BufferedReader(new InputStreamReader(server.getInputStream()))) {
                for (String line; (line = out.readLine()) != null; ) {
                    serverOutput.append(line).append('\n');
                    java.util.regex.Matcher bound = java.util.regex.Pattern.compile("bound: \\[127\\.0\\.0\\.1:(\\d+)").matcher(line);
                    if (bound.find()) {
                        boundPort.complete(Integer.parseInt(bound.group(1)));
                    }
                }
            }
            catch (IOException e) {
                // process ended
            }
        });
        try {
            int port = boundPort.get(20, TimeUnit.SECONDS);
            SecretKey clientKey = SecretKey.generate();
            RelayTransport transport = connect(clientKey);
            try (Endpoint client = Endpoint.builder(clientKey).bind(LOCALHOST).publish(false).relayQuicPort(null).maxPathId(4)
                    .transport(transport).build()) {
                QuicClientConnection connection = client.connect(serverKey.endpointId(),
                        transport.addressFor(serverKey.endpointId()), EchoProtocol.ALPN);
                assertEquals("relayed", EchoProtocol.echo(connection, "relayed"));

                QuicConnectionImpl impl = (QuicConnectionImpl) connection;
                long deadline = System.currentTimeMillis() + 10_000;
                while (!impl.getPathManager().hasConnectionIds(1) && System.currentTimeMillis() < deadline) {
                    Thread.sleep(10);
                }
                CompletableFuture<QuicPath> active = new CompletableFuture<>();
                impl.setPathListener(active::complete);
                impl.openPath(new InetSocketAddress(InetAddress.getLoopbackAddress(), port)).orElseThrow();
                assertEquals(1, active.get(10, TimeUnit.SECONDS).getId());
                for (int i = 0; i < 3; i++) {
                    assertEquals("direct #" + i, EchoProtocol.echo(connection, "direct #" + i));
                }
                if (Boolean.getBoolean("interop.linger")) {
                    Thread.sleep(15_000);
                    assertEquals("after linger", EchoProtocol.echo(connection, "after linger"));
                    System.out.println(serverOutput);
                }
                deadline = System.currentTimeMillis() + 5_000;
                while (!serverOutput.toString().contains("Opened { id: PathId(1), remote_addr: Ip(") && System.currentTimeMillis() < deadline) {
                    Thread.sleep(10);
                }
                assertTrue(serverOutput.toString().contains("server path event: Opened { id: PathId(1), remote_addr: Ip("), serverOutput.toString());

                // Leaving the relay path: iroh closes path 0 and carries on over the direct path.
                impl.abandonPath(0, 0);
                assertEquals("direct only", EchoProtocol.echo(connection, "direct only"));
                deadline = System.currentTimeMillis() + 5_000;
                while (!serverOutput.toString().contains("Closed { id: PathId(0)") && System.currentTimeMillis() < deadline) {
                    Thread.sleep(10);
                }
                assertTrue(serverOutput.toString().contains("server path event: Closed { id: PathId(0)"), serverOutput.toString());
                assertEquals("still direct", EchoProtocol.echo(connection, "still direct"));
                connection.close();
            }
        }
        finally {
            server.destroy();
            server.waitFor(5, TimeUnit.SECONDS);
        }
    }

    private RelayTransport connect(SecretKey key) throws Exception {
        return RelayTransport.connect(relay.url, key, TIMEOUT);
    }

    private static void waitForLine(BufferedReader out, String prefix) throws Exception {
        long deadline = System.currentTimeMillis() + 20_000;
        String line;
        while ((line = out.readLine()) != null) {
            if (line.startsWith(prefix)) {
                return;
            }
            if (System.currentTimeMillis() > deadline) {
                break;
            }
        }
        fail("no line starting with '" + prefix + "'");
    }
}
