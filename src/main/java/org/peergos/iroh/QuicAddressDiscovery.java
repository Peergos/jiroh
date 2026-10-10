package org.peergos.iroh;

import tech.kwik.core.QuicClientConnection;

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * QUIC Address Discovery against an iroh relay (iroh-relay/src/quic.rs): a QUIC connection from the endpoint's
 * socket to the relay's QAD port, whose OBSERVED_ADDRESS report is this endpoint's address as seen from outside.
 * This is what iroh uses instead of STUN.
 */
public final class QuicAddressDiscovery {

    public static final String ALPN = "/iroh-qad/0";
    public static final int DEFAULT_RELAY_QUIC_PORT = 7842;
    private static final long CLOSE_CODE = 1;
    private static final String CLOSE_REASON = "finished";

    private QuicAddressDiscovery() {}

    /**
     * @param relay         the relay's QAD address; its certificate must be valid for this IP
     * @param trustManager  trust manager for the relay's certificate, or null for the default trust store
     */
    public static InetSocketAddress observe(Endpoint endpoint, InetSocketAddress relay, X509TrustManager trustManager,
                                            Duration timeout) throws IOException {
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder()
                .host(relay.getAddress().getHostAddress())
                .port(relay.getPort())
                .applicationProtocol(ALPN)
                .addressDiscovery(false, true)
                .sharedEndpoint(endpoint.sharedEndpoint())
                .connectTimeout(timeout)
                .maxIdleTimeout(Duration.ofSeconds(35));
        if (trustManager != null) {
            builder.customTrustManager(trustManager);
        }
        QuicClientConnection connection = builder.build();
        CompletableFuture<InetSocketAddress> observed = new CompletableFuture<>();
        connection.setObservedAddressListener(observed::complete);
        try {
            connection.connect();
            return observed.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
        catch (ExecutionException | TimeoutException e) {
            throw new IOException("no observed address from relay " + relay, e);
        }
        finally {
            connection.close(CLOSE_CODE, CLOSE_REASON);
        }
    }
}
