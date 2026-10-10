package org.peergos.iroh;

import org.peergos.iroh.pkarr.EndpointInfo;
import org.peergos.iroh.pkarr.MainlineDht;
import org.peergos.iroh.pkarr.Pkarr;
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

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An iroh endpoint: QUIC with iroh's TLS (mutually authenticated Ed25519 raw public keys, no SNI) over one UDP
 * socket plus relay paths. It picks a home relay, learns its public address with QUIC address discovery, publishes
 * where it can be reached as a pkarr record on the mainline DHT, and dials other endpoints by id.
 *
 * Without QUIC multipath and NAT traversal, a connection stays on the path it was established on, so connecting
 * races the direct addresses against the relay and keeps the first handshake that completes.
 */
public final class Endpoint implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(Endpoint.class.getName());
    private static final Duration MAX_IDLE_TIMEOUT = Duration.ofSeconds(30);
    // Direct paths get a head start, so the relay is only used when they do not work.
    private static final Duration RELAY_DELAY = Duration.ofMillis(250);
    public static final Duration REPUBLISH_INTERVAL = Duration.ofMinutes(5);
    public static final long DEFAULT_STREAM_RECEIVE_WINDOW = 2 * 1024 * 1024;

    private final SecretKey secretKey;
    private final IrohSocket socket;
    private final ServerConnector server;
    private final Duration timeout;
    private final X509TrustManager relayTrustManager;
    private final Integer relayQuicPort;
    private final long streamReceiveWindow;
    private final Pkarr pkarr;
    private final Map<URI, RelayTransport> relays = new ConcurrentHashMap<>();
    private record ConnectionKey(EndpointId remote, String alpn) {}
    private final Map<ConnectionKey, CompletableFuture<QuicClientConnection>> connections = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler;
    private volatile URI homeRelay;
    private volatile InetSocketAddress observedAddress;
    private volatile EndpointInfo published;

    private Endpoint(Builder builder, IrohSocket socket, ServerConnector server) {
        this.secretKey = builder.secretKey;
        this.socket = socket;
        this.server = server;
        this.timeout = builder.timeout;
        this.relayTrustManager = builder.relayTrustManager;
        this.relayQuicPort = builder.relayQuicPort;
        this.streamReceiveWindow = builder.streamReceiveWindow;
        this.pkarr = builder.dht == null? null: new Pkarr(builder.dht);
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "iroh-endpoint-" + secretKey.endpointId().toHex().substring(0, 8));
            t.setDaemon(true);
            return t;
        });
    }

    public static Builder builder(SecretKey secretKey) {
        return new Builder(secretKey);
    }

    public static final class Builder {
        private final SecretKey secretKey;
        private InetSocketAddress bindAddress = new InetSocketAddress(0);
        private final Map<String, ProtocolHandler> protocols = new LinkedHashMap<>();
        private final List<PacketTransport> transports = new ArrayList<>();
        private final List<URI> relayUrls = new ArrayList<>();
        private X509TrustManager relayTrustManager;
        private MainlineDht dht;
        private boolean publish = true;
        private Duration timeout = Duration.ofSeconds(10);
        private Integer relayQuicPort = QuicAddressDiscovery.DEFAULT_RELAY_QUIC_PORT;
        private long streamReceiveWindow = DEFAULT_STREAM_RECEIVE_WINDOW;

        private Builder(SecretKey secretKey) {
            this.secretKey = secretKey;
        }

        public Builder bind(InetSocketAddress bindAddress) {
            this.bindAddress = bindAddress;
            return this;
        }

        public Builder protocol(String alpn, ProtocolHandler handler) {
            protocols.put(alpn, handler);
            return this;
        }

        public Builder transport(PacketTransport transport) {
            transports.add(transport);
            return this;
        }

        /** Candidate home relays; the first that accepts the connection becomes the home relay. */
        public Builder relays(List<URI> relayUrls) {
            this.relayUrls.addAll(relayUrls);
            return this;
        }

        /** Trust manager for the relays' TLS certificates, when not the default trust store. */
        public Builder relayTrustManager(X509TrustManager trustManager) {
            this.relayTrustManager = trustManager;
            return this;
        }

        /** Mainline DHT client for pkarr: resolving other endpoints, and publishing this one unless disabled. */
        public Builder addressLookup(MainlineDht dht) {
            this.dht = dht;
            return this;
        }

        /** The home relay's QUIC address discovery port; null to not discover the public address. */
        public Builder relayQuicPort(Integer port) {
            this.relayQuicPort = port;
            return this;
        }

        public Builder publish(boolean publish) {
            this.publish = publish;
            return this;
        }

        /** Flow control credit per stream; the connection gets ten times this. */
        public Builder streamReceiveWindow(long bytes) {
            this.streamReceiveWindow = bytes;
            return this;
        }

        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public Endpoint build() throws IOException {
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
                                .maxBidirectionalStreamBufferSize(streamReceiveWindow)
                                .maxUnidirectionalStreamBufferSize(streamReceiveWindow)
                                .maxConnectionBufferSize(10 * streamReceiveWindow)
                                .build())
                        .build();
            }
            catch (CertificateException e) {
                socket.close();
                throw new IllegalStateException(e);
            }
            protocols.forEach((alpn, handler) -> server.registerApplicationProtocol(alpn, new Factory(handler)));
            server.start();
            Endpoint endpoint = new Endpoint(this, socket, server);
            try {
                endpoint.start(relayUrls, publish);
            }
            catch (RuntimeException e) {
                endpoint.close();
                throw e;
            }
            return endpoint;
        }
    }

    public static Endpoint bind(SecretKey secretKey, InetSocketAddress bindAddress, Map<String, ProtocolHandler> protocols)
            throws IOException {
        return bind(secretKey, bindAddress, protocols, List.of());
    }

    public static Endpoint bind(SecretKey secretKey, InetSocketAddress bindAddress, Map<String, ProtocolHandler> protocols,
                                List<PacketTransport> transports) throws IOException {
        Builder builder = builder(secretKey).bind(bindAddress);
        protocols.forEach(builder::protocol);
        transports.forEach(builder::transport);
        return builder.build();
    }

    private void start(List<URI> relayUrls, boolean publish) {
        if (!relayUrls.isEmpty()) {
            homeRelay = connectHomeRelay(relayUrls);
            if (homeRelay != null && relayQuicPort != null) {
                observedAddress = discoverAddress(homeRelay).orElse(null);
            }
        }
        if (pkarr != null && publish) {
            publishNow();
            scheduler.scheduleWithFixedDelay(this::publishNow, REPUBLISH_INTERVAL.toMillis(), REPUBLISH_INTERVAL.toMillis(), TimeUnit.MILLISECONDS);
        }
    }

    /** Connects to all candidate relays at once and keeps the first to authenticate, as a latency estimate. */
    private URI connectHomeRelay(List<URI> relayUrls) {
        CompletableFuture<URI> first = new CompletableFuture<>();
        AtomicInteger failures = new AtomicInteger();
        for (URI url : relayUrls) {
            Thread.ofVirtual().start(() -> {
                try {
                    relay(url);
                    first.complete(url);
                }
                catch (IOException e) {
                    LOG.log(Level.INFO, "relay " + url + " unavailable", e);
                    if (failures.incrementAndGet() == relayUrls.size()) {
                        first.complete(null);
                    }
                }
            });
        }
        try {
            return first.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
        catch (ExecutionException | TimeoutException e) {
            return null;
        }
    }

    /** The relay transport for the given relay, connecting to it when needed. */
    private RelayTransport relay(URI url) throws IOException {
        RelayTransport existing = relays.get(url);
        if (existing != null) {
            return existing;
        }
        synchronized (relays) {
            existing = relays.get(url);
            if (existing != null) {
                return existing;
            }
            RelayTransport transport = RelayTransport.connect(url, secretKey, timeout, relayTrustManager);
            socket.addTransport(transport);
            relays.put(url, transport);
            return transport;
        }
    }

    private Optional<InetSocketAddress> discoverAddress(URI relay) {
        try {
            InetAddress host = InetAddress.getByName(relay.getHost());
            InetSocketAddress qad = new InetSocketAddress(host, relayQuicPort);
            return Optional.of(QuicAddressDiscovery.observe(this, qad, relayTrustManager, Duration.ofSeconds(2)));
        }
        catch (IOException e) {
            LOG.fine("no QUIC address discovery from " + relay + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    private void publishNow() {
        try {
            EndpointAddr addr = addr();
            EndpointInfo info = new EndpointInfo(addr.id(), addr.relayUrls(), addr.directAddresses());
            int stored = pkarr.publish(secretKey, info, timeout);
            published = info;
            LOG.fine("published " + info + " on " + stored + " DHT nodes");
        }
        catch (RuntimeException e) {
            LOG.log(Level.WARNING, "publishing endpoint info failed", e);
        }
    }

    public EndpointId id() {
        return secretKey.endpointId();
    }

    public InetSocketAddress localAddress() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }

    public Optional<URI> homeRelay() {
        return Optional.ofNullable(homeRelay);
    }

    /** This endpoint's address as observed by its home relay (QUIC address discovery), if known. */
    public Optional<InetSocketAddress> observedAddress() {
        return Optional.ofNullable(observedAddress);
    }

    /** This endpoint's own address: its home relay, the publicly observed address and its local addresses. */
    public EndpointAddr addr() {
        Set<InetSocketAddress> direct = new LinkedHashSet<>();
        if (observedAddress != null) {
            direct.add(observedAddress);
        }
        direct.addAll(localAddresses());
        return new EndpointAddr(id(), homeRelay == null? List.of(): List.of(homeRelay), new ArrayList<>(direct));
    }

    private List<InetSocketAddress> localAddresses() {
        InetSocketAddress bound = localAddress();
        if (!bound.getAddress().isAnyLocalAddress()) {
            return List.of(bound);
        }
        List<InetSocketAddress> addresses = new ArrayList<>();
        try {
            for (NetworkInterface nif : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!nif.isUp() || nif.isLoopback() || nif.isVirtual()) {
                    continue;
                }
                for (InetAddress address : Collections.list(nif.getInetAddresses())) {
                    if (address instanceof Inet6Address v6 && (v6.isLinkLocalAddress() || v6.getScopeId() != 0)) {
                        continue;
                    }
                    addresses.add(new InetSocketAddress(address, bound.getPort()));
                }
            }
        }
        catch (SocketException e) {
            LOG.fine("cannot list network interfaces: " + e.getMessage());
        }
        return addresses;
    }

    SharedEndpoint sharedEndpoint() {
        return server.getSharedEndpoint();
    }

    /**
     * An open connection to the given endpoint for the given ALPN, reusing an existing one; concurrent callers
     * share a single dial. Connections are dropped from the cache when they terminate.
     */
    public QuicClientConnection connection(EndpointAddr remote, String alpn) throws IOException {
        return cached(new ConnectionKey(remote.id(), alpn), () -> connect(remote, alpn));
    }

    /** Like {@link #connection(EndpointAddr, String)}, finding the endpoint's addresses with pkarr. */
    public QuicClientConnection connection(EndpointId remote, String alpn) throws IOException {
        return cached(new ConnectionKey(remote, alpn), () -> connect(remote, alpn));
    }

    private interface Dialer {
        QuicClientConnection dial() throws IOException;
    }

    private QuicClientConnection cached(ConnectionKey key, Dialer dialer) throws IOException {
        CompletableFuture<QuicClientConnection> fresh = new CompletableFuture<>();
        CompletableFuture<QuicClientConnection> existing = connections.putIfAbsent(key, fresh);
        if (existing != null) {
            try {
                return existing.join();
            }
            catch (java.util.concurrent.CompletionException e) {
                throw e.getCause() instanceof IOException io? io: new IOException(e.getCause());
            }
        }
        try {
            QuicClientConnection connection = dialer.dial();
            connection.setConnectionListener(event -> connections.remove(key, fresh));
            fresh.complete(connection);
            return connection;
        }
        catch (IOException | RuntimeException e) {
            connections.remove(key, fresh);
            fresh.completeExceptionally(e);
            throw e;
        }
    }

    /**
     * Connects to the given endpoint, finding its addresses with pkarr on the mainline DHT.
     */
    public QuicClientConnection connect(EndpointId remote, String alpn) throws IOException {
        if (pkarr == null) {
            throw new IOException("no address lookup configured");
        }
        EndpointInfo info = pkarr.resolve(remote, timeout)
                .orElseThrow(() -> new IOException("no address found for " + remote));
        return connect(new EndpointAddr(remote, info.relayUrls(), info.directAddresses()), alpn);
    }

    /**
     * Connects to the given endpoint over the first of its paths to complete a handshake: each direct address is
     * tried at once, its relays shortly after. The handshake fails unless the remote proves it holds the key of
     * {@code remote.id()}.
     */
    public QuicClientConnection connect(EndpointAddr remote, String alpn) throws IOException {
        List<CompletableFuture<QuicClientConnection>> attempts = new ArrayList<>();
        CompletableFuture<QuicClientConnection> winner = new CompletableFuture<>();
        AtomicInteger remaining = new AtomicInteger(remote.directAddresses().size() + remote.relayUrls().size());
        if (remaining.get() == 0) {
            throw new IOException("no addresses for " + remote.id());
        }
        List<IOException> failures = Collections.synchronizedList(new ArrayList<>());
        for (InetSocketAddress address : remote.directAddresses()) {
            attempts.add(attempt(remote.id(), () -> address, alpn, Duration.ZERO, winner, remaining, failures));
        }
        for (URI relayUrl : remote.relayUrls()) {
            Duration delay = remote.directAddresses().isEmpty()? Duration.ZERO: RELAY_DELAY;
            attempts.add(attempt(remote.id(), () -> relay(relayUrl).addressFor(remote.id()), alpn, delay, winner, remaining, failures));
        }
        try {
            QuicClientConnection connection = winner.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            // Close the handshakes that lost the race.
            attempts.forEach(a -> a.thenAccept(c -> {
                if (c != connection) {
                    c.close();
                }
            }));
            return connection;
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
        catch (ExecutionException e) {
            IOException failure = new IOException("could not connect to " + remote.id(), e.getCause());
            failures.forEach(failure::addSuppressed);
            throw failure;
        }
        catch (TimeoutException e) {
            attempts.forEach(a -> a.thenAccept(QuicConnection::close));
            throw new IOException("timed out connecting to " + remote.id());
        }
    }

    private interface AddressSupplier {
        InetSocketAddress get() throws IOException;
    }

    private CompletableFuture<QuicClientConnection> attempt(EndpointId remote, AddressSupplier address, String alpn, Duration delay,
                                                            CompletableFuture<QuicClientConnection> winner, AtomicInteger remaining,
                                                            List<IOException> failures) {
        CompletableFuture<QuicClientConnection> result = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try {
                if (!delay.isZero()) {
                    Thread.sleep(delay.toMillis());
                }
                if (winner.isDone()) {
                    result.cancel(false);
                    return;
                }
                QuicClientConnection connection = connectVia(remote, address.get(), alpn);
                result.complete(connection);
                if (!winner.complete(connection)) {
                    connection.close();
                }
            }
            catch (IOException e) {
                failures.add(e);
                result.completeExceptionally(e);
                if (remaining.decrementAndGet() == 0) {
                    winner.completeExceptionally(e);
                }
                return;
            }
            catch (InterruptedException e) {
                result.cancel(false);
                return;
            }
            remaining.decrementAndGet();
        });
        return result;
    }

    /**
     * Connects to the given endpoint at a known address: a direct UDP address, or a mapped address of one of the
     * endpoint's transports.
     */
    public QuicClientConnection connect(EndpointId remote, InetSocketAddress address, String alpn) throws IOException {
        return connectVia(remote, address, alpn);
    }

    private QuicClientConnection connectVia(EndpointId remote, InetSocketAddress address, String alpn) throws IOException {
        QuicClientConnection connection = QuicClientConnection.newBuilder()
                // A literal, so no DNS lookup happens.
                .host(address.getAddress().getHostAddress())
                .port(address.getPort())
                .applicationProtocol(alpn)
                .serverRawPublicKey(remote::matches)
                .clientRawPublicKey(secretKey.keyPair())
                .maxIdleTimeout(MAX_IDLE_TIMEOUT)
                .connectTimeout(timeout)
                .defaultStreamReceiveBufferSize(streamReceiveWindow)
                .sharedEndpoint(server.getSharedEndpoint())
                .build();
        connection.connect();
        return connection;
    }

    /** The endpoint info most recently published, if any. */
    public Optional<EndpointInfo> published() {
        return Optional.ofNullable(published);
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
        connections.values().forEach(f -> f.thenAccept(QuicConnection::close));
        relays.values().forEach(RelayTransport::close);
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
