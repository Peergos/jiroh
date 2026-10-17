package org.peergos.iroh;

import static org.peergos.iroh.RelayProtocol.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A client of an iroh relay (iroh-relay protocol v2, falling back to v1), carrying QUIC datagrams to and from
 * other endpoints connected to the same relay. Each remote endpoint is addressed by a relay mapped address.
 *
 * Protocol: {@link RelayProtocol}.
 */
public final class RelayTransport implements PacketTransport, AutoCloseable {

    private static final Logger LOG = Logger.getLogger(RelayTransport.class.getName());

    private static final int MAX_PENDING_SENDS = 1024;
    private static final Duration MIN_BACKOFF = Duration.ofMillis(250);
    private static final Duration MAX_BACKOFF = Duration.ofSeconds(30);
    private static final ScheduledExecutorService TIMER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "iroh-relay-timer");
        t.setDaemon(true);
        return t;
    });

    private final URI relayUrl;
    private final SecretKey secretKey;
    private final Duration timeout;
    private final X509TrustManager trustManager;
    private final Map<EndpointId, InetSocketAddress> addresses = new ConcurrentHashMap<>();
    private final Map<InetSocketAddress, EndpointId> endpoints = new ConcurrentHashMap<>();
    private final ScheduledFuture<?> pinger;
    private final AtomicInteger connectionCount = new AtomicInteger();
    private volatile Connection current;
    private volatile PacketSink sink;
    private volatile boolean closed;
    private Duration backoff = MIN_BACKOFF;

    private RelayTransport(URI relayUrl, SecretKey secretKey, Duration timeout, X509TrustManager trustManager) {
        this.relayUrl = relayUrl;
        this.secretKey = secretKey;
        this.timeout = timeout;
        this.trustManager = trustManager;
        this.pinger = TIMER.scheduleWithFixedDelay(this::ping, PING_INTERVAL.toMillis(), PING_INTERVAL.toMillis(), TimeUnit.MILLISECONDS);
    }

    /**
     * Connects to the relay and authenticates as the endpoint of the given key. When the connection is lost
     * later, the transport reconnects with backoff; mapped addresses stay valid across reconnects.
     * @param relayUrl  the relay URL as iroh uses it, e.g. https://relay.example/ (http only for local testing)
     */
    public static RelayTransport connect(URI relayUrl, SecretKey secretKey, Duration timeout) throws IOException {
        return connect(relayUrl, secretKey, timeout, null);
    }

    /**
     * @param trustManager  trust manager for the relay's certificate, or null for the default trust store
     */
    public static RelayTransport connect(URI relayUrl, SecretKey secretKey, Duration timeout, X509TrustManager trustManager) throws IOException {
        RelayTransport transport = new RelayTransport(relayUrl, secretKey, timeout, trustManager);
        try {
            transport.current = transport.openConnection();
        }
        catch (IOException e) {
            transport.close();
            throw e;
        }
        return transport;
    }

    public URI relayUrl() {
        return relayUrl;
    }

    /** The negotiated relay protocol version of the current connection, e.g. "iroh-relay-v2". */
    public String protocol() {
        Connection connection = current;
        return connection == null? null: connection.protocol;
    }

    public boolean isConnected() {
        Connection connection = current;
        return connection != null && connection.isAuthenticated();
    }

    /** How many times a relay connection has been established (1 until the first reconnect). */
    public int connectionCount() {
        return connectionCount.get();
    }

    /** The mapped address under which the given endpoint is reachable via this relay. */
    public InetSocketAddress addressFor(EndpointId remote) {
        return addresses.computeIfAbsent(remote, id -> {
            InetSocketAddress mapped = MappedAddresses.newRelayMapped();
            endpoints.put(mapped, id);
            return mapped;
        });
    }

    private Connection openConnection() throws IOException {
        Connection connection = new Connection();
        URI wsUri = URI.create(("https".equals(relayUrl.getScheme())? "wss": "ws") + "://" + relayUrl.getRawAuthority() + RELAY_PATH);
        HttpClient.Builder clientBuilder = HttpClient.newBuilder().connectTimeout(timeout);
        if (trustManager != null) {
            try {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, new TrustManager[]{trustManager}, null);
                clientBuilder.sslContext(context);
            }
            catch (NoSuchAlgorithmException | KeyManagementException e) {
                throw new IOException(e);
            }
        }
        HttpClient client = clientBuilder.build();
        try {
            WebSocket webSocket = client.newWebSocketBuilder()
                    .subprotocols(PROTOCOLS[0], PROTOCOLS[1])
                    .connectTimeout(timeout)
                    .buildAsync(wsUri, connection)
                    .get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            connection.protocol = webSocket.getSubprotocol();
            connection.authenticated.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            connection.abort();
            throw new IOException(e);
        }
        catch (ExecutionException e) {
            connection.abort();
            throw new IOException("relay connection failed: " + e.getCause().getMessage(), e.getCause());
        }
        catch (TimeoutException e) {
            connection.abort();
            throw new IOException("relay connection timed out", e);
        }
        connectionCount.incrementAndGet();
        return connection;
    }

    private void connectionLost(Connection connection, Duration delay) {
        synchronized (this) {
            if (closed || connection != current || connection.lost) {
                return;
            }
            connection.lost = true;
        }
        connection.abort();
        LOG.fine("relay connection to " + relayUrl + " lost, reconnecting in " + delay.toMillis() + "ms");
        TIMER.schedule(this::reconnect, delay.toMillis(), TimeUnit.MILLISECONDS);
    }

    private void reconnect() {
        if (closed) {
            return;
        }
        Connection connection;
        try {
            connection = openConnection();
        }
        catch (IOException e) {
            Duration delay;
            synchronized (this) {
                delay = backoff;
                backoff = backoff.multipliedBy(2).compareTo(MAX_BACKOFF) > 0? MAX_BACKOFF: backoff.multipliedBy(2);
            }
            LOG.fine("relay reconnect to " + relayUrl + " failed (" + e.getMessage() + "), retrying in " + delay.toMillis() + "ms");
            TIMER.schedule(this::reconnect, delay.toMillis(), TimeUnit.MILLISECONDS);
            return;
        }
        synchronized (this) {
            if (closed) {
                connection.abort();
                return;
            }
            current = connection;
            backoff = MIN_BACKOFF;
        }
        LOG.info("reconnected to relay " + relayUrl);
    }

    /**
     * Pings the relay; a connection that did not answer the previous ping is considered dead.
     */
    private void ping() {
        Connection connection = current;
        if (closed || connection == null || !connection.isAuthenticated()) {
            return;
        }
        if (connection.outstandingPing != null) {
            connectionLost(connection, Duration.ZERO);
            return;
        }
        byte[] payload = new byte[8];
        ThreadLocalRandom.current().nextBytes(payload);
        connection.outstandingPing = payload;
        ByteBuffer ping = ByteBuffer.allocate(9);
        ping.put((byte) PING).put(payload).flip();
        connection.sendFrame(ping);
    }

    @Override
    public boolean handles(InetSocketAddress destination) {
        return endpoints.containsKey(destination);
    }

    @Override
    public void send(InetSocketAddress destination, byte[] data, int offset, int length) throws IOException {
        EndpointId to = endpoints.get(destination);
        if (to == null) {
            throw new IOException("unknown relay mapped address " + destination);
        }
        if (closed) {
            throw new IOException("relay transport closed");
        }
        Connection connection = current;
        if (connection == null || !connection.isAuthenticated()) {
            // Like a UDP path that is down: the datagram is lost and QUIC retransmits.
            return;
        }
        ByteBuffer frame = ByteBuffer.allocate(1 + 32 + 1 + length);
        frame.put((byte) CLIENT_TO_RELAY_DATAGRAM).put(to.toBytes()).put((byte) 0).put(data, offset, length).flip();
        connection.sendFrame(frame);
    }

    @Override
    public void start(PacketSink sink) {
        this.sink = sink;
    }

    @Override
    public void close() {
        synchronized (this) {
            closed = true;
        }
        pinger.cancel(false);
        Connection connection = current;
        if (connection != null) {
            connection.close();
        }
    }

    /** One WebSocket session with the relay. */
    private final class Connection implements WebSocket.Listener {
        private final CompletableFuture<Void> authenticated = new CompletableFuture<>();
        private final AtomicInteger pendingSends = new AtomicInteger();
        private final ByteArrayOutputStream partial = new ByteArrayOutputStream();
        private CompletableFuture<?> sendChain = CompletableFuture.completedFuture(null);
        private volatile WebSocket webSocket;
        private volatile String protocol;
        private volatile byte[] outstandingPing;
        private volatile boolean lost;

        boolean isAuthenticated() {
            return authenticated.isDone() && !authenticated.isCompletedExceptionally() && !lost;
        }

        /**
         * Java's WebSocket allows one outstanding send, so sends are chained. Like UDP, datagrams are dropped
         * rather than queued without bound when the relay connection cannot keep up.
         */
        void sendFrame(ByteBuffer frame) {
            if (pendingSends.incrementAndGet() > MAX_PENDING_SENDS) {
                pendingSends.decrementAndGet();
                return;
            }
            synchronized (this) {
                sendChain = sendChain
                        .thenCompose(ignored -> webSocket.sendBinary(frame, true))
                        .whenComplete((ws, error) -> {
                            pendingSends.decrementAndGet();
                            if (error != null && !closed) {
                                LOG.log(Level.FINE, "relay send failed", error);
                            }
                        })
                        .exceptionally(error -> null);
            }
        }

        void close() {
            WebSocket ws = webSocket;
            if (ws != null) {
                ws.sendClose(WebSocket.NORMAL_CLOSURE, "").exceptionally(e -> null);
            }
            abort();
        }

        void abort() {
            WebSocket ws = webSocket;
            if (ws != null) {
                ws.abort();
            }
            authenticated.completeExceptionally(new IOException("closed"));
        }

        private void handleFrame(ByteBuffer frame) {
            int type = (int) readVarint(frame);
            if (!authenticated.isDone()) {
                handleHandshakeFrame(type, frame);
                return;
            }
            switch (type) {
                case RELAY_TO_CLIENT_DATAGRAM, RELAY_TO_CLIENT_DATAGRAM_BATCH -> {
                    EndpointId from = readEndpointId(frame);
                    frame.get(); // ECN
                    int segmentSize = type == RELAY_TO_CLIENT_DATAGRAM_BATCH? frame.getShort() & 0xffff: 0;
                    PacketSink sink = RelayTransport.this.sink;
                    if (sink == null) {
                        return;
                    }
                    InetSocketAddress source = addressFor(from);
                    byte[] contents = new byte[frame.remaining()];
                    frame.get(contents);
                    if (segmentSize == 0) {
                        sink.deliver(source, contents, 0, contents.length);
                    }
                    else {
                        for (int offset = 0; offset < contents.length; offset += segmentSize) {
                            sink.deliver(source, contents, offset, Math.min(segmentSize, contents.length - offset));
                        }
                    }
                }
                case PING -> {
                    byte[] payload = new byte[8];
                    frame.get(payload);
                    ByteBuffer pong = ByteBuffer.allocate(9);
                    pong.put((byte) PONG).put(payload).flip();
                    sendFrame(pong);
                }
                case PONG -> {
                    byte[] payload = new byte[8];
                    frame.get(payload);
                    if (Arrays.equals(payload, outstandingPing)) {
                        outstandingPing = null;
                    }
                }
                case ENDPOINT_GONE -> LOG.fine("relay: endpoint gone " + readEndpointId(frame));
                case STATUS -> LOG.info("relay status " + (frame.get() & 0xff) + " from " + relayUrl);
                case HEALTH -> LOG.info("relay health: " + StandardCharsets.UTF_8.decode(frame));
                case RESTARTING -> {
                    // RelayToClientMsg::Restarting { reconnect_in: u32 millis, try_for: u32 millis }
                    long reconnectIn = frame.getInt() & 0xffffffffL;
                    LOG.info("relay " + relayUrl + " restarting, reconnecting in " + reconnectIn + "ms");
                    connectionLost(this, Duration.ofMillis(Math.min(reconnectIn, MAX_BACKOFF.toMillis())));
                }
                default -> LOG.fine("relay: ignoring frame type " + type);
            }
        }

        private void handleHandshakeFrame(int type, ByteBuffer frame) {
            switch (type) {
                case SERVER_CHALLENGE -> {
                    // postcard ServerChallenge { challenge: [u8; 16] }: the 16 bytes as they are
                    byte[] challenge = new byte[16];
                    frame.get(challenge);
                    byte[] signature = sign(secretKey, challengeMessage(challenge));
                    // postcard ClientAuth { public_key: [u8; 32], signature: serde_bytes [u8; 64] }
                    ByteBuffer auth = ByteBuffer.allocate(1 + 32 + 1 + 64);
                    auth.put((byte) CLIENT_AUTH).put(secretKey.endpointId().toBytes()).put((byte) 64).put(signature).flip();
                    sendFrame(auth);
                }
                case SERVER_CONFIRMS_AUTH -> authenticated.complete(null);
                case SERVER_DENIES_AUTH -> {
                    int length = (int) readPostcardVarint(frame);
                    byte[] reason = new byte[Math.min(length, frame.remaining())];
                    frame.get(reason);
                    authenticated.completeExceptionally(new IOException("relay denied authentication: " + new String(reason, StandardCharsets.UTF_8)));
                }
                default -> authenticated.completeExceptionally(new IOException("unexpected handshake frame " + type));
            }
        }

        @Override
        public void onOpen(WebSocket webSocket) {
            // The relay's challenge can arrive before buildAsync completes, so take the socket from here.
            this.webSocket = webSocket;
            webSocket.request(1);
        }

        @Override
        public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
            try {
                if (partial.size() == 0 && last) {
                    handleFrame(data);
                }
                else {
                    if (partial.size() + data.remaining() > MAX_FRAME_SIZE) {
                        throw new IllegalStateException("relay frame too large");
                    }
                    byte[] bytes = new byte[data.remaining()];
                    data.get(bytes);
                    partial.writeBytes(bytes);
                    if (last) {
                        handleFrame(ByteBuffer.wrap(partial.toByteArray()));
                        partial.reset();
                    }
                }
            }
            catch (RuntimeException e) {
                LOG.log(Level.WARNING, "invalid relay frame from " + relayUrl, e);
                partial.reset();
            }
            webSocket.request(1);
            return null;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            authenticated.completeExceptionally(new IOException("relay closed connection: " + statusCode + " " + reason));
            connectionLost(this, MIN_BACKOFF);
            return null;
        }

        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            authenticated.completeExceptionally(error);
            connectionLost(this, MIN_BACKOFF);
        }
    }
}
