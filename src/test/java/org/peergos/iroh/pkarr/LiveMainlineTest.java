package org.peergos.iroh.pkarr;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.peergos.iroh.SecretKey;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Against the real mainline DHT; run with -Dmainline.live=true. */
class LiveMainlineTest {

    @Test
    void publishAndResolveOnMainline() throws Exception {
        Assumptions.assumeTrue(Boolean.getBoolean("mainline.live"), "set -Dmainline.live=true");
        List<InetSocketAddress> bootstrap = MainlineDht.resolve(MainlineDht.DEFAULT_BOOTSTRAP);
        SecretKey key = SecretKey.generate();
        EndpointInfo info = new EndpointInfo(key.endpointId(), List.of(URI.create("https://relay.example/")),
                List.of(new InetSocketAddress(InetAddress.getByName("203.0.113.7"), 4433)));
        try (MainlineDht publisher = MainlineDht.start(new InetSocketAddress(0), bootstrap);
             MainlineDht resolver = MainlineDht.start(new InetSocketAddress(0), bootstrap)) {
            long start = System.nanoTime();
            int stored = new Pkarr(publisher).publish(key, info, Duration.ofSeconds(30));
            System.out.println("stored on " + stored + " nodes in " + (System.nanoTime() - start) / 1_000_000 + "ms");
            assertTrue(stored > 0);
            start = System.nanoTime();
            EndpointInfo resolved = new Pkarr(resolver).resolve(key.endpointId(), Duration.ofSeconds(30)).orElseThrow();
            System.out.println("resolved in " + (System.nanoTime() - start) / 1_000_000 + "ms");
            assertEquals(info, resolved);
        }
    }
}
