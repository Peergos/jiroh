package org.peergos.iroh;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class Blake3Test {

    @Test
    void emptyInput() {
        assertEquals("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
                HexFormat.of().formatHex(Blake3.hash(new byte[0])));
    }

    @Test
    void matchesRustBlake3() throws Exception {
        Path bin = Path.of(System.getProperty("interop.probe.dir", "../interop-probe/target/release")).resolve("blake3_vectors");
        Assumptions.assumeTrue(Files.isExecutable(bin), "interop-probe not built");
        Process process = new ProcessBuilder(bin.toString()).start();
        List<String> lines = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).lines().toList();
        process.waitFor(10, TimeUnit.SECONDS);
        assertFalse(lines.isEmpty());
        for (String line : lines) {
            String[] parts = line.split(" ");
            int length = Integer.parseInt(parts[0]);
            byte[] input = new byte[length];
            for (int i = 0; i < length; i++) {
                input[i] = (byte) (i % 251);
            }
            assertEquals(parts[1], HexFormat.of().formatHex(Blake3.hash(input)), "hash of " + length + " bytes");
            assertEquals(parts[2], HexFormat.of().formatHex(Blake3.deriveKey("iroh-relay handshake v1 challenge signature", input)),
                    "derive_key of " + length + " bytes");
        }
    }
}
