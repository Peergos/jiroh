package org.peergos.iroh;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

/**
 * Let's Encrypt's Pebble test ACME server (https://github.com/letsencrypt/pebble), on free local ports. It validates
 * http-01 on httpPort and tls-alpn-01 on tlsPort of 127.0.0.1.
 */
final class PebbleProcess implements AutoCloseable {

    static final Path BINARY = Path.of(System.getProperty("pebble.bin", "../pebble/pebble"));

    final URI directory;
    final int httpPort;
    final int tlsPort;
    private final int managementPort;
    private final Path certificate;
    private final Process process;

    PebbleProcess(int httpPort, int tlsPort) throws Exception {
        this.httpPort = httpPort;
        this.tlsPort = tlsPort;
        Path dir = Files.createTempDirectory("pebble");
        certificate = dir.resolve("cert.pem");
        Path key = dir.resolve("key.pem");
        IrohRelayProcess.selfSignedCertificate(certificate, key);
        int port = freePort();
        managementPort = freePort();
        Path config = dir.resolve("pebble.json");
        Files.writeString(config, """
                {"pebble": {
                  "listenAddress": "127.0.0.1:%d",
                  "managementListenAddress": "127.0.0.1:%d",
                  "certificate": "%s",
                  "privateKey": "%s",
                  "httpPort": %d,
                  "tlsPort": %d,
                  "ocspResponderURL": "",
                  "externalAccountBindingRequired": false
                }}
                """.formatted(port, managementPort, certificate, key, httpPort, tlsPort));
        ProcessBuilder builder = new ProcessBuilder(BINARY.toString(), "-config", config.toString())
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD);
        builder.environment().put("PEBBLE_VA_NOSLEEP", "1");
        process = builder.start();
        directory = URI.create("https://127.0.0.1:" + port + "/dir");
        long deadline = System.currentTimeMillis() + 10_000;
        while (true) {
            try (Socket ignored = new Socket(InetAddress.getLoopbackAddress(), port)) {
                return;
            }
            catch (IOException notYet) {
                if (System.currentTimeMillis() > deadline || !process.isAlive()) {
                    close();
                    throw new IOException("pebble did not start");
                }
                Thread.sleep(50);
            }
        }
    }

    static boolean available() {
        return Files.isExecutable(BINARY);
    }

    static int freePort() throws IOException {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    /** Trusts Pebble's own HTTPS certificate, for the ACME client. */
    SSLContext acmeTls() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{IrohRelayProcess.trustManager(certificate)}, null);
        return context;
    }

    /** The root that Pebble's issued certificates chain to (it changes on every start). */
    X509Certificate root() throws Exception {
        HttpClient client = HttpClient.newBuilder().sslContext(acmeTls()).build();
        HttpResponse<byte[]> response = client.send(HttpRequest.newBuilder(URI.create("https://127.0.0.1:" + managementPort + "/roots/0")).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(response.body()));
    }

    @Override
    public void close() {
        process.destroy();
        try {
            process.waitFor(5, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
