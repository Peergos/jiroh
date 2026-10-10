package org.peergos.iroh;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnection;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;
import tech.kwik.core.socket.SharedEndpoint;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * A minimal iroh endpoint: QUIC with iroh's TLS (mutually authenticated Ed25519 raw public keys, no SNI) over direct
 * UDP. No relay, no address lookup, no multipath or NAT traversal yet; a Rust iroh v1 endpoint accepts such a
 * single-path peer.
 *
 * All connections, incoming and outgoing, share the endpoint's one UDP socket, as hole punching requires.
 */
public final class Endpoint implements AutoCloseable {

    private static final Duration MAX_IDLE_TIMEOUT = Duration.ofSeconds(30);

    private final SecretKey secretKey;
    private final IrohSocket socket;
    private final ServerConnector server;

    private Endpoint(SecretKey secretKey, IrohSocket socket, ServerConnector server) {
        this.secretKey = secretKey;
        this.socket = socket;
        this.server = server;
    }

    public static Endpoint bind(SecretKey secretKey, InetSocketAddress bindAddress, Map<String, ProtocolHandler> protocols)
            throws IOException {
        return bind(secretKey, bindAddress, protocols, List.of());
    }

    public static Endpoint bind(SecretKey secretKey, InetSocketAddress bindAddress, Map<String, ProtocolHandler> protocols,
                                List<PacketTransport> transports) throws IOException {
        IrohSocket socket = new IrohSocket(bindAddress);
        transports.forEach(socket::addTransport);
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

    SharedEndpoint sharedEndpoint() {
        return server.getSharedEndpoint();
    }

    public InetSocketAddress localAddress() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }

    /**
     * Connects to the given endpoint at a known address: a direct UDP address, or a mapped address of one of the
     * endpoint's transports. The handshake fails unless the remote proves it
     * holds the key of {@code remote}.
     */
    public QuicClientConnection connect(EndpointId remote, InetSocketAddress address, String alpn) throws IOException {
        QuicClientConnection connection = QuicClientConnection.newBuilder()
                // A literal, so no DNS lookup happens.
                .host(address.getAddress().getHostAddress())
                .port(address.getPort())
                .applicationProtocol(alpn)
                .serverRawPublicKey(remote::matches)
                .clientRawPublicKey(secretKey.keyPair())
                .maxIdleTimeout(MAX_IDLE_TIMEOUT)
                .sharedEndpoint(server.getSharedEndpoint())
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
            InetSocketAddress remoteAddress = ((ServerConnection) connection).getInitialRemoteAddress();
            return new ApplicationProtocolConnection() {
                @Override
                public void acceptPeerInitiatedStream(QuicStream stream) {
                    handler.acceptStream(remote, remoteAddress, stream);
                }
            };
        }

        @Override
        public int maxConcurrentPeerInitiatedBidirectionalStreams() {
            return 100;
        }
    }
}
