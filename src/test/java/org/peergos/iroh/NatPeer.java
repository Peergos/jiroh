package org.peergos.iroh;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.send.QuicPath;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * One endpoint of nat-test.sh, which runs each in its own network namespace behind a NAT.
 * <pre>
 * NatPeer server relay-url relay-cert.pem relay-quic-port
 * NatPeer client relay-url relay-cert.pem relay-quic-port server-id
 * </pre>
 * The client knows only the server's relay, so a direct path can only come from NAT traversal; it then abandons the
 * relay path and echoes over the direct one.
 */
public final class NatPeer {

    public static void main(String[] args) throws Exception {
        URI relay = URI.create(args[1]);
        Endpoint.Builder builder = Endpoint.builder(SecretKey.generate())
                .bind(new InetSocketAddress(0))
                .publish(false)
                .relays(List.of(relay))
                .relayTrustManager(trustManager(Path.of(args[2])))
                .relayQuicPort(Integer.parseInt(args[3]));
        if (args[0].equals("server")) {
            Endpoint endpoint = builder.protocol(EchoProtocol.ALPN, new EchoProtocol()).build();
            System.out.println("observed: " + endpoint.observedAddress().orElse(null));
            System.out.println("direct addresses: " + endpoint.addr().directAddresses());
            System.out.println("endpoint id: " + endpoint.id().toHex());
            Thread.sleep(Long.MAX_VALUE);
        }
        try (Endpoint endpoint = builder.build()) {
            System.out.println("observed: " + endpoint.observedAddress().orElse(null));
            System.out.println("direct addresses: " + endpoint.addr().directAddresses());
            EndpointId server = EndpointId.fromHex(args[4]);
            QuicClientConnection connection = endpoint.connect(new EndpointAddr(server, List.of(relay), List.of()), EchoProtocol.ALPN);
            QuicConnectionImpl impl = (QuicConnectionImpl) connection;
            CompletableFuture<QuicPath> direct = new CompletableFuture<>();
            impl.setPathListener(path -> {
                if (!MappedAddresses.isRelayMapped(path.getPeerAddress())) {
                    direct.complete(path);
                }
            });
            System.out.println(EchoProtocol.echo(connection, "relayed"));
            long start = System.nanoTime();
            QuicPath path = direct.get(20, TimeUnit.SECONDS);
            System.out.println("server candidates: " + impl.getRemoteNatTraversalAddresses());
            System.out.println("direct path " + path.getId() + " to " + path.getPeerAddress() + " after "
                    + Duration.ofNanos(System.nanoTime() - start).toMillis() + " ms");
            impl.abandonPath(0, 0);
            for (int i = 0; i < 3; i++) {
                System.out.println(EchoProtocol.echo(connection, "direct #" + i));
            }
            System.out.println("paths: " + impl.getPaths());
            connection.close();
        }
        System.exit(0);
    }

    private static X509TrustManager trustManager(Path pem) throws Exception {
        X509Certificate cert;
        try (var in = Files.newInputStream(pem)) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("relay", cert);
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
        factory.init(trustStore);
        return (X509TrustManager) factory.getTrustManagers()[0];
    }
}
