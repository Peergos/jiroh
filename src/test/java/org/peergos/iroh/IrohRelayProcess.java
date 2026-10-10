package org.peergos.iroh;

import java.io.IOException;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** n0's iroh-relay binary in --dev mode (plain HTTP) on a free local port. */
final class IrohRelayProcess implements AutoCloseable {

    static final Path BINARY = Path.of(System.getProperty("iroh.relay.bin", "../iroh/target/release/iroh-relay"));

    private Process process;
    private final Path config;
    private final List<String> args;
    private int port;
    final URI url;
    /** The QUIC address discovery port, when started with TLS. */
    final int quicPort;
    /** The relay's self-signed certificate (PEM), when started with TLS. */
    final Path certificate;

    /** Dev mode: plain HTTP, no QUIC address discovery. */
    IrohRelayProcess() throws IOException, InterruptedException {
        port = freeTcpPort();
        config = Files.createTempFile("iroh-relay", ".toml");
        Files.writeString(config, "http_bind_addr = \"127.0.0.1:" + port + "\"\nenable_metrics = false\n");
        url = URI.create("http://127.0.0.1:" + port + "/");
        quicPort = -1;
        certificate = null;
        args = List.of("--dev", "-c", config.toString());
        start();
    }

    /** With TLS (a self-signed certificate for 127.0.0.1) and QUIC address discovery. */
    static IrohRelayProcess withQuicAddressDiscovery() throws IOException, InterruptedException {
        return new IrohRelayProcess(true);
    }

    private IrohRelayProcess(boolean tls) throws IOException, InterruptedException {
        Path dir = Files.createTempDirectory("iroh-relay");
        certificate = dir.resolve("cert.pem");
        Path key = dir.resolve("key.pem");
        Process openssl = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-keyout", key.toString(), "-out", certificate.toString(), "-days", "2",
                "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1")
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        if (openssl.waitFor() != 0) {
            throw new IOException("openssl failed");
        }
        int httpPort = freeTcpPort();
        port = freeTcpPort();
        quicPort = freeUdpPort();
        config = dir.resolve("relay.toml");
        Files.writeString(config, String.join("\n",
                "enable_relay = true",
                "http_bind_addr = \"127.0.0.1:" + httpPort + "\"",
                "enable_quic_addr_discovery = true",
                "enable_metrics = false",
                "[tls]",
                "https_bind_addr = \"127.0.0.1:" + port + "\"",
                "quic_bind_addr = \"127.0.0.1:" + quicPort + "\"",
                "cert_mode = \"Manual\"",
                "manual_cert_path = \"" + certificate + "\"",
                "manual_key_path = \"" + key + "\"", ""));
        url = URI.create("https://127.0.0.1:" + port + "/");
        args = List.of("-c", config.toString());
        start();
    }

    private static int freeTcpPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    private static int freeUdpPort() throws IOException {
        try (DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    /** A trust manager that trusts only the relay's self-signed certificate. */
    X509TrustManager trustManager() throws Exception {
        X509Certificate cert;
        try (var in = Files.newInputStream(certificate)) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("relay", cert);
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
        factory.init(trustStore);
        return (X509TrustManager) factory.getTrustManagers()[0];
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
        List<String> command = new java.util.ArrayList<>(List.of(BINARY.toString()));
        command.addAll(args);
        process = new ProcessBuilder(command)
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
            if (certificate != null) {
                Files.deleteIfExists(certificate);
            }
        }
        catch (InterruptedException | IOException e) {
            // ignore
        }
    }
}
