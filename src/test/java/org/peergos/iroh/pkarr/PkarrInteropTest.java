package org.peergos.iroh.pkarr;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.peergos.iroh.EndpointId;
import org.peergos.iroh.SecretKey;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * pkarr on a local mainline DHT (the Rust mainline crate's testnet), against the Rust pkarr crate.
 */
class PkarrInteropTest {

    private static final Path PROBE = Path.of(System.getProperty("interop.probe.dir", "../interop-probe/target/release"));
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private static Process testnet;
    private static List<InetSocketAddress> bootstrap;
    private static String bootstrapArg;

    @BeforeAll
    static void startTestnet() throws Exception {
        Assumptions.assumeTrue(Files.isExecutable(PROBE.resolve("dht_testnet")), "interop-probe not built");
        testnet = new ProcessBuilder(PROBE.resolve("dht_testnet").toString(), "10").redirectErrorStream(true).start();
        String line = new BufferedReader(new InputStreamReader(testnet.getInputStream())).readLine();
        assertNotNull(line);
        List<String> nodes = Arrays.asList(line.substring("bootstrap: ".length()).split(" "));
        bootstrap = MainlineDht.resolve(nodes);
        bootstrapArg = String.join(",", nodes);
    }

    @AfterAll
    static void stopTestnet() throws Exception {
        if (testnet != null) {
            testnet.destroy();
            testnet.waitFor(5, TimeUnit.SECONDS);
        }
    }

    private static MainlineDht dht() throws Exception {
        return MainlineDht.start(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), bootstrap);
    }

    private static EndpointInfo info(SecretKey key) throws Exception {
        return new EndpointInfo(key.endpointId(), List.of(URI.create("http://127.0.0.1:3340/")),
                List.of(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 4433)));
    }

    @Test
    void javaPublishesAndJavaResolves() throws Exception {
        SecretKey key = SecretKey.generate();
        try (MainlineDht publisher = dht(); MainlineDht resolver = dht()) {
            assertTrue(new Pkarr(publisher).publish(key, info(key), TIMEOUT) > 0);
            assertEquals(info(key), new Pkarr(resolver).resolve(key.endpointId(), TIMEOUT).orElseThrow());
        }
    }

    @Test
    void newerPacketReplacesOlder() throws Exception {
        SecretKey key = SecretKey.generate();
        EndpointInfo second = new EndpointInfo(key.endpointId(), List.of(), List.of(new InetSocketAddress(InetAddress.getByName("10.0.0.2"), 1)));
        try (MainlineDht dht = dht()) {
            Pkarr pkarr = new Pkarr(dht);
            assertTrue(pkarr.publish(info(key).toSignedPacket(key, 1000), TIMEOUT) > 0);
            assertTrue(pkarr.publish(second.toSignedPacket(key, 2000), TIMEOUT) > 0);
            SignedPacket resolved = pkarr.resolvePacket(key.endpointId(), TIMEOUT).orElseThrow();
            assertEquals(2000, resolved.timestamp());
            assertEquals(second, EndpointInfo.fromSignedPacket(resolved));
        }
    }

    @Test
    void rustResolvesWhatJavaPublished() throws Exception {
        SecretKey key = SecretKey.generate();
        try (MainlineDht dht = dht()) {
            assertTrue(new Pkarr(dht).publish(key, info(key), TIMEOUT) > 0);
        }
        Process resolve = new ProcessBuilder(PROBE.resolve("pkarr_resolve").toString(), bootstrapArg, key.endpointId().toHex())
                .redirectErrorStream(true).start();
        assertTrue(resolve.waitFor(30, TimeUnit.SECONDS));
        String output = new String(resolve.getInputStream().readAllBytes());
        assertEquals(0, resolve.exitValue(), output);
        String name = "_iroh." + Z32.encode(key.endpointId().toBytes());
        assertTrue(output.contains(name + " TXT relay=http://127.0.0.1:3340/"), output);
        assertTrue(output.contains(name + " TXT addr=127.0.0.1:4433"), output);
    }

    @Test
    void javaResolvesWhatRustPublished() throws Exception {
        SecretKey key = SecretKey.generate();
        Process publish = new ProcessBuilder(PROBE.resolve("pkarr_publish").toString(), bootstrapArg,
                HexFormat.of().formatHex(key.toBytes()), "_iroh", "relay=http://127.0.0.1:3340/", "addr=127.0.0.1:4433")
                .redirectErrorStream(true).start();
        assertTrue(publish.waitFor(30, TimeUnit.SECONDS));
        String output = new String(publish.getInputStream().readAllBytes());
        assertEquals(0, publish.exitValue(), output);
        // Same key encoding as the Rust pkarr crate
        assertTrue(output.startsWith("published " + Z32.encode(key.endpointId().toBytes())), output);
        try (MainlineDht dht = dht()) {
            assertEquals(info(key), new Pkarr(dht).resolve(key.endpointId(), TIMEOUT).orElseThrow());
        }
    }
}
