package org.peergos.iroh;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.peergos.iroh.acme.AcmeCertificates;
import org.peergos.iroh.acme.AcmeClient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Certificates from Pebble, a test ACME CA, with both challenge types the relay can answer. */
class RelayAcmeTest {

    private static final String DOMAIN = "localhost";
    private static final InetSocketAddress LOCALHOST = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

    private PebbleProcess pebble;

    @BeforeEach
    void startPebble() throws Exception {
        Assumptions.assumeTrue(PebbleProcess.available(), "pebble not installed in ../pebble");
        pebble = new PebbleProcess(PebbleProcess.freePort(), PebbleProcess.freePort());
    }

    @AfterEach
    void stopPebble() {
        if (pebble != null) {
            pebble.close();
        }
    }

    @Test
    void tlsAlpn01ShouldGetACertificateAndServeIt() throws Exception {
        Path dir = Files.createTempDirectory("acme");
        RelayCertificate certificate = RelayCertificate.empty();
        // tls-alpn-01 is validated on the relay's own HTTPS port; there is no plain HTTP listener.
        try (RelayServer relay = RelayServer.builder()
                .bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), pebble.tlsPort))
                .tls(certificate)
                .start();
             AcmeCertificates acme = AcmeCertificates.start(config(dir, List.of(AcmeClient.TLS_ALPN_01, AcmeClient.HTTP_01)),
                     certificate, relay.acmeChallenges())) {
            X509Certificate[] chain = awaitCertificate(certificate);
            assertTrue(chain[0].getSubjectAlternativeNames().stream().anyMatch(name -> DOMAIN.equals(name.get(1))));

            X509TrustManager trust = trustManager(pebble.root());
            URI url = URI.create("https://" + DOMAIN + ":" + pebble.tlsPort + "/");
            assertEquals(200, get(trust, url.resolve("/ping")));

            // Endpoints connect through the relay with the issued certificate.
            SecretKey keyA = SecretKey.generate();
            SecretKey keyB = SecretKey.generate();
            RelayTransport relayA = RelayTransport.connect(url, keyA, Duration.ofSeconds(10), trust);
            RelayTransport relayB = RelayTransport.connect(url, keyB, Duration.ofSeconds(10), trust);
            try (Endpoint a = Endpoint.bind(keyA, LOCALHOST, Map.of(), List.of(relayA));
                 Endpoint b = Endpoint.bind(keyB, LOCALHOST, Map.of(EchoProtocol.ALPN, new EchoProtocol()), List.of(relayB))) {
                var connection = a.connect(b.id(), relayA.addressFor(b.id()), EchoProtocol.ALPN);
                assertEquals("acme", EchoProtocol.echo(connection, "acme"));
                connection.close();
            }
        }

        // A restart uses the cached certificate without asking the CA.
        pebble.close();
        RelayCertificate restarted = RelayCertificate.empty();
        try (AcmeCertificates acme = AcmeCertificates.start(config(dir, List.of(AcmeClient.TLS_ALPN_01)), restarted, unreachable())) {
            assertTrue(restarted.chain().isPresent());
        }
    }

    @Test
    void http01ShouldGetACertificate() throws Exception {
        Path dir = Files.createTempDirectory("acme");
        RelayCertificate certificate = RelayCertificate.empty();
        try (RelayServer relay = RelayServer.builder()
                .tls(certificate)
                .httpBind(new InetSocketAddress(InetAddress.getLoopbackAddress(), pebble.httpPort))
                .start();
             AcmeCertificates acme = AcmeCertificates.start(config(dir, List.of(AcmeClient.HTTP_01)), certificate, relay.acmeChallenges())) {
            awaitCertificate(certificate);
            assertEquals(200, get(trustManager(pebble.root()), URI.create("https://" + DOMAIN + ":" + relay.address().getPort() + "/ping")));
            // The plain HTTP listener does captive portal checks but not the relay.
            HttpClient plain = HttpClient.newHttpClient();
            URI http = URI.create("http://127.0.0.1:" + pebble.httpPort);
            assertEquals(204, plain.send(HttpRequest.newBuilder(http.resolve("/generate_204")).build(), HttpResponse.BodyHandlers.discarding()).statusCode());
            assertEquals(404, plain.send(HttpRequest.newBuilder(http.resolve("/relay")).build(), HttpResponse.BodyHandlers.discarding()).statusCode());
        }
    }

    private AcmeCertificates.Config config(Path dir, List<String> challengeTypes) throws Exception {
        return new AcmeCertificates.Config(pebble.directory, List.of(DOMAIN), List.of("mailto:test@example.com"), dir,
                challengeTypes, pebble.acmeTls());
    }

    private static org.peergos.iroh.acme.ChallengeResponder unreachable() {
        return new org.peergos.iroh.acme.ChallengeResponder() {
            public boolean supportsHttp01() { return false; }
            public void addHttp01(String token, String keyAuthorization) { fail(); }
            public void removeHttp01(String token) {}
            public boolean supportsTlsAlpn01() { return false; }
            public void addTlsAlpn01(String domain, java.security.PrivateKey key, X509Certificate certificate) { fail(); }
            public void removeTlsAlpn01(String domain) {}
        };
    }

    private static X509Certificate[] awaitCertificate(RelayCertificate certificate) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 60_000;
        while (certificate.chain().isEmpty()) {
            assertTrue(System.currentTimeMillis() < deadline, "no certificate from pebble");
            Thread.sleep(100);
        }
        return certificate.chain().get();
    }

    private static X509TrustManager trustManager(X509Certificate root) throws Exception {
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        store.setCertificateEntry("pebble", root);
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
        factory.init(store);
        return (X509TrustManager) factory.getTrustManagers()[0];
    }

    private static int get(X509TrustManager trust, URI uri) throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new javax.net.ssl.TrustManager[]{trust}, null);
        return HttpClient.newBuilder().sslContext(context).build()
                .send(HttpRequest.newBuilder(uri).build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }
}
