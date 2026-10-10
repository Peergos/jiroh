package org.peergos.iroh;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Map;

/**
 * A minimal iroh endpoint: QUIC with iroh's TLS (mutually authenticated Ed25519 raw public keys, no SNI) over direct
 * UDP. No relay, no address lookup, no multipath or NAT traversal yet; a Rust iroh v1 endpoint accepts such a
 * single-path peer.
 *
 * TODO: kwik gives every outgoing connection its own UDP socket; iroh needs all connections on the one listening
 * socket (hole punching requires sending from it) plus relay "paths".
 */
public final class Endpoint implements AutoCloseable {

    private static final Duration MAX_IDLE_TIMEOUT = Duration.ofSeconds(30);

    private final SecretKey secretKey;
    private final DatagramSocket socket;
    private final ServerConnector server;

    private Endpoint(SecretKey secretKey, DatagramSocket socket, ServerConnector server) {
        this.secretKey = secretKey;
        this.socket = socket;
        this.server = server;
    }

    public static Endpoint bind(SecretKey secretKey, InetSocketAddress bindAddress, Map<String, ProtocolHandler> protocols)
            throws IOException {
        DatagramSocket socket = new DatagramSocket(bindAddress);
        ServerConnector server;
        try {
            server = ServerConnector.builder()
                    .withSocket(socket)
                    .withLogger(new NullLogger())
                    .withRawPublicKey(secretKey.keyPair())
                    // iroh authenticates every client, and accepts any key: authorisation is up to the protocol.
                    .requireClientRawPublicKey(key -> true)
                    .withConfiguration(ServerConnectionConfig.builder()
                            .maxIdleTimeoutInSeconds((int) MAX_IDLE_TIMEOUT.toSeconds())
                            .maxOpenPeerInitiatedBidirectionalStreams(100)
                            .maxOpenPeerInitiatedUnidirectionalStreams(100)
                            .build())
                    .build();
        }
        catch (CertificateException e) {
            socket.close();
            throw new IllegalStateException(e);
        }
        protocols.forEach((alpn, handler) -> server.registerApplicationProtocol(alpn, new Factory(handler)));
        server.start();
        return new Endpoint(secretKey, socket, server);
    }

    public EndpointId id() {
        return secretKey.endpointId();
    }

    public InetSocketAddress localAddress() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }

    /**
     * Connects to the given endpoint at a known direct address. The handshake fails unless the remote proves it
     * holds the key of {@code remote}.
     */
    public QuicClientConnection connect(EndpointId remote, InetSocketAddress address, String alpn) throws IOException {
        QuicClientConnection connection = QuicClientConnection.newBuilder()
                .host(address.getAddress().getHostAddress())
                .port(address.getPort())
                .applicationProtocol(alpn)
                .serverRawPublicKey(remote::matches)
                .clientRawPublicKey(secretKey.keyPair())
                .maxIdleTimeout(MAX_IDLE_TIMEOUT)
                .build();
        connection.connect();
        return connection;
    }

    @Override
    public void close() {
        server.close();
        socket.close();
    }

    private record Factory(ProtocolHandler handler) implements ApplicationProtocolConnectionFactory {
        @Override
        public ApplicationProtocolConnection createConnection(String protocol, QuicConnection connection) {
            EndpointId remote = EndpointId.fromPublicKey(connection.getPeerRawPublicKey());
            return new ApplicationProtocolConnection() {
                @Override
                public void acceptPeerInitiatedStream(QuicStream stream) {
                    handler.acceptStream(remote, stream);
                }
            };
        }

        @Override
        public int maxConcurrentPeerInitiatedBidirectionalStreams() {
            return 100;
        }
    }
}
