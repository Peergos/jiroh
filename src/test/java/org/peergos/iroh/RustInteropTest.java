package org.peergos.iroh;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicClientConnection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Interop against Rust iroh 1.3 (the binaries of ../interop-probe; build them with cargo build --release).
 */
class RustInteropTest {

    private static Path probeDir;

    @BeforeAll
    static void findProbe() {
        probeDir = Path.of(System.getProperty("interop.probe.dir", "../interop-probe/target/release"));
        Assumptions.assumeTrue(Files.isExecutable(probeDir.resolve("server")), "interop-probe not built");
    }

    @Test
    void javaClientShouldConnectToRustIrohEndpoint() throws Exception {
        SecretKey serverKey = SecretKey.generate();
        int port = freeUdpPort();
        Process server = new ProcessBuilder(probeDir.resolve("server").toString(), "127.0.0.1:" + port,
                HexFormat.of().formatHex(serverKey.toBytes()))
                .redirectErrorStream(true)
                .start();
        try {
            BufferedReader out = new BufferedReader(new InputStreamReader(server.getInputStream()));
            String idLine = out.readLine();
            assertNotNull(idLine, "server exited early");
            // The Rust endpoint derives the same endpoint id from the secret key as the Java code does.
            assertEquals("endpoint id: " + serverKey.endpointId().toHex(), idLine);
            out.readLine(); // bound sockets

            try (Endpoint client = Endpoint.bind(SecretKey.generate(), new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), Map.of())) {
                QuicClientConnection connection = client.connect(serverKey.endpointId(),
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), port), EchoProtocol.ALPN);
                for (int i = 0; i < 3; i++) {
                    assertEquals("hello from java #" + i, EchoProtocol.echo(connection, "hello from java #" + i));
                }
                assertEquals(serverKey.endpointId(), EndpointId.fromPublicKey(connection.getPeerRawPublicKey()));
                connection.close();
            }
        }
        finally {
            server.destroy();
            server.waitFor(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void rustIrohEndpointShouldConnectToJavaEndpoint() throws Exception {
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint server = Endpoint.bind(SecretKey.generate(), new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                Map.of(EchoProtocol.ALPN, echo))) {
            Process client = new ProcessBuilder(probeDir.resolve("iroh_client").toString(),
                    "127.0.0.1:" + server.localAddress().getPort(), server.id().toHex(), "3")
                    .redirectErrorStream(true)
                    .start();
            boolean exited = client.waitFor(30, TimeUnit.SECONDS);
            String output = new String(client.getInputStream().readAllBytes());
            System.out.println(output);
            if (!exited) {
                client.destroyForcibly();
                fail("rust client did not finish:\n" + output);
            }
            assertEquals(0, client.exitValue(), output);
            assertTrue(output.contains("echo ok: hello from rust iroh #2"), output);
            String clientId = output.lines().filter(l -> l.startsWith("client id: ")).findFirst().orElseThrow().substring(11);
            assertEquals(EndpointId.fromHex(clientId), echo.lastRemote);
        }
    }

    private static int freeUdpPort() throws IOException {
        try (DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }
}
