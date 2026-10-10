package org.peergos.iroh;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/** n0's iroh-relay binary in --dev mode (plain HTTP) on a free local port. */
final class IrohRelayProcess implements AutoCloseable {

    static final Path BINARY = Path.of(System.getProperty("iroh.relay.bin", "../iroh/target/release/iroh-relay"));

    private Process process;
    private final Path config;
    private int port;
    final URI url;

    IrohRelayProcess() throws IOException, InterruptedException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = socket.getLocalPort();
        }
        config = Files.createTempFile("iroh-relay", ".toml");
        Files.writeString(config, "http_bind_addr = \"127.0.0.1:" + port + "\"\nenable_metrics = false\n");
        url = URI.create("http://127.0.0.1:" + port + "/");
        start();
    }

    /** Stops the relay and starts it again on the same port, dropping all client connections. */
    void restart() throws IOException, InterruptedException {
        restart(0);
    }

    void restart(long downMillis) throws IOException, InterruptedException {
        process.destroy();
        process.waitFor(5, TimeUnit.SECONDS);
        Thread.sleep(downMillis);
        start();
    }

    private void start() throws IOException, InterruptedException {
        process = new ProcessBuilder(BINARY.toString(), "--dev", "-c", config.toString())
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .start();
        long deadline = System.currentTimeMillis() + 10_000;
        while (true) {
            try (Socket ignored = new Socket(InetAddress.getLoopbackAddress(), port)) {
                return;
            }
            catch (IOException notYet) {
                if (System.currentTimeMillis() > deadline || !process.isAlive()) {
                    close();
                    throw new IOException("iroh-relay did not start");
                }
                Thread.sleep(50);
            }
        }
    }

    static boolean available() {
        return Files.isExecutable(BINARY);
    }

    @Override
    public void close() {
        process.destroy();
        try {
            process.waitFor(5, TimeUnit.SECONDS);
            Files.deleteIfExists(config);
        }
        catch (InterruptedException | IOException e) {
            // ignore
        }
    }
}
