package org.peergos.iroh.mdns;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.peergos.iroh.Endpoint;
import org.peergos.iroh.EndpointAddr;
import org.peergos.iroh.EndpointId;
import org.peergos.iroh.SecretKey;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicStream;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * mDNS discovery against Rust iroh's iroh-mdns-address-lookup (interop-probe's mdns_peer), and between Java endpoints.
 * Needs a multicast-capable interface: the endpoints find each other through the host's own multicast loopback.
 */
class MdnsInteropTest {

    private static final String ALPN = "iroh-interop/echo/0";
    private static Path probeDir;

    @BeforeAll
    static void findProbe() {
        probeDir = Path.of(System.getProperty("interop.probe.dir", "../interop-probe/target/release"));
    }

    private static void assumeProbe() {
        Assumptions.assumeTrue(Files.isExecutable(probeDir.resolve("mdns_peer")), "interop-probe not built");
    }

    private static Endpoint endpoint(SecretKey key) throws IOException {
        return Endpoint.builder(key)
                .mdns(true)
                .portMapping(false)
                .protocol(ALPN, (remote, address, stream) -> echo(stream))
                .build();
    }

    @Test
    void javaShouldDiscoverAndDialRustEndpointById() throws Exception {
        assumeProbe();
        SecretKey rustKey = SecretKey.generate();
        Process rust = new ProcessBuilder(probeDir.resolve("mdns_peer").toString(), "serve",
                HexFormat.of().formatHex(rustKey.toBytes()))
                .redirectErrorStream(true)
                .start();
        List<String> rustOutput = new CopyOnWriteArrayList<>();
        Thread.ofVirtual().start(() -> new BufferedReader(new InputStreamReader(rust.getInputStream())).lines().forEach(rustOutput::add));
        SecretKey javaKey = SecretKey.generate();
        try (Endpoint java = endpoint(javaKey)) {
            CompletableFuture<EndpointId> expired = new CompletableFuture<>();
            java.mdns().orElseThrow().addListener(event -> {
                if (event instanceof MdnsAddressLookup.Event.Expired e) {
                    expired.complete(e.id());
                }
            });
            QuicClientConnection connection = java.connect(rustKey.endpointId(), ALPN);
            assertEquals("hello rust", echo(connection, "hello rust"));
            EndpointAddr found = java.mdns().orElseThrow().discovered(rustKey.endpointId()).orElseThrow();
            assertFalse(found.directAddresses().isEmpty());
            connection.close();

            waitFor(() -> rustOutput.stream().anyMatch(l -> l.startsWith("discovered " + javaKey.endpointId().toHex())),
                    Duration.ofSeconds(10), "rust did not discover java: " + rustOutput);

            rust.destroy();
            assertEquals(rustKey.endpointId(), expired.get(15, TimeUnit.SECONDS));
            assertTrue(java.mdns().orElseThrow().discovered(rustKey.endpointId()).isEmpty());
        }
        finally {
            rust.destroy();
            rust.waitFor(5, TimeUnit.SECONDS);
            System.out.println(String.join("\n", rustOutput));
        }
    }

    @Test
    void rustShouldDialJavaEndpointById() throws Exception {
        assumeProbe();
        try (Endpoint java = endpoint(SecretKey.generate())) {
            Process rust = new ProcessBuilder(probeDir.resolve("mdns_peer").toString(), "dial", java.id().toHex(), "3")
                    .redirectErrorStream(true)
                    .start();
            boolean exited = rust.waitFor(30, TimeUnit.SECONDS);
            String output = new String(rust.getInputStream().readAllBytes());
            System.out.println(output);
            if (!exited) {
                rust.destroyForcibly();
                fail("rust dialer did not finish:\n" + output);
            }
            assertEquals(0, rust.exitValue(), output);
            assertTrue(output.contains("echo ok: hello from rust iroh #2"), output);
        }
    }

    @Test
    void rustShouldDecodeRelayAndAddressesOnSeveralPorts() throws Exception {
        assumeProbe();
        EndpointId id = SecretKey.generate().endpointId();
        try (MdnsAddressLookup mdns = MdnsAddressLookup.start(id)) {
            mdns.publish(new EndpointAddr(id, List.of(java.net.URI.create("https://relay.example.com/")), List.of(
                    new java.net.InetSocketAddress("192.0.2.1", 1234),
                    new java.net.InetSocketAddress("2001:db8::1", 1234),
                    new java.net.InetSocketAddress("192.0.2.1", 5678))));
            Process rust = new ProcessBuilder(probeDir.resolve("mdns_peer").toString(), "serve")
                    .redirectErrorStream(true)
                    .start();
            List<String> output = new CopyOnWriteArrayList<>();
            Thread.ofVirtual().start(() -> new BufferedReader(new InputStreamReader(rust.getInputStream())).lines().forEach(output::add));
            try {
                waitFor(() -> output.stream().anyMatch(l -> l.startsWith("discovered " + id.toHex())), Duration.ofSeconds(10),
                        "rust did not discover java: " + output);
                String line = output.stream().filter(l -> l.startsWith("discovered " + id.toHex())).findFirst().orElseThrow();
                assertEquals("discovered " + id.toHex() + " addrs [192.0.2.1:1234, 192.0.2.1:5678, [2001:db8::1]:1234]"
                        + " relays [\"https://relay.example.com/\"]", line);
            }
            finally {
                rust.destroy();
                rust.waitFor(5, TimeUnit.SECONDS);
            }
        }
    }

    @Test
    void javaEndpointsShouldFindEachOther() throws Exception {
        try (Endpoint a = endpoint(SecretKey.generate()); Endpoint b = endpoint(SecretKey.generate())) {
            QuicClientConnection connection = a.connect(b.id(), ALPN);
            assertEquals("hello java", echo(connection, "hello java"));
            connection.close();
            waitFor(() -> b.mdns().orElseThrow().discovered(a.id()).isPresent(), Duration.ofSeconds(5), "b did not find a");
        }
    }

    private static void waitFor(java.util.function.BooleanSupplier condition, Duration timeout, String message) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                fail(message);
            }
            Thread.sleep(50);
        }
    }

    private static void echo(QuicStream stream) {
        Thread.ofVirtual().start(() -> {
            try (OutputStream out = stream.getOutputStream()) {
                out.write(stream.getInputStream().readAllBytes());
            }
            catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    private static String echo(QuicClientConnection connection, String message) throws IOException {
        QuicStream stream = connection.createStream(true);
        try (OutputStream out = stream.getOutputStream()) {
            out.write(message.getBytes(StandardCharsets.UTF_8));
        }
        return new String(stream.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
}
