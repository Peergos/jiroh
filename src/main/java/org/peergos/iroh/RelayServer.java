package org.peergos.iroh;

import static org.peergos.iroh.RelayProtocol.*;

import com.sun.net.httpserver.HttpServer;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLSocket;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An iroh relay server, wire compatible with n0's iroh-relay 1.3 (iroh-relay/src/server): endpoints connect over a
 * WebSocket on /relay, authenticate with their endpoint key, and send each other datagrams by endpoint id.
 *
 * TLS uses an ordinary X.509 certificate ({@link RelayCertificate}, which can be replaced while running), as iroh
 * clients verify relays against web PKI roots. Without TLS the server speaks plain HTTP, like iroh-relay --dev. With
 * TLS it can also run QUIC address discovery.
 */
public final class RelayServer implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(RelayServer.class.getName());

    private static final Duration HANDSHAKE_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration PONG_TIMEOUT = Duration.ofSeconds(5);
    private static final int SEND_QUEUE_DEPTH = 512;
    private static final Outgoing STOP = new Outgoing(ServerWebSocket.CLOSE, new byte[0]);

    private final ServerSocket serverSocket;
    private final RelayCertificate certificate;
    private final QadServer qad;
    private final HttpServer metricsServer;
    private final RelayMetrics metrics;
    private final Predicate<EndpointId> accessControl;
    private final RateLimit clientRx;
    private final TokenBucket acceptLimit;
    private final SecureRandom random = new SecureRandom();
    private final ScheduledThreadPoolExecutor timer;
    private final Map<EndpointId, Registration> clients = new ConcurrentHashMap<>();
    private final Map<EndpointId, Set<EndpointId>> sentTo = new ConcurrentHashMap<>();
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
    private final AtomicInteger keyMaterialAuthentications = new AtomicInteger();
    private volatile boolean closed;

    private RelayServer(Builder config, ServerSocket serverSocket, QadServer qad, HttpServer metricsServer) {
        this.serverSocket = serverSocket;
        this.certificate = config.certificate;
        this.qad = qad;
        this.metricsServer = metricsServer;
        this.metrics = config.metrics;
        this.accessControl = config.accessControl;
        this.clientRx = config.clientRx;
        this.acceptLimit = config.acceptLimit == null? null: new TokenBucket(config.acceptLimit.perSecond(), config.acceptLimit.burst());
        this.timer = new ScheduledThreadPoolExecutor(1, r -> {
            Thread thread = new Thread(r, "iroh-relay-server-timer");
            thread.setDaemon(true);
            return thread;
        });
        timer.setRemoveOnCancelPolicy(true);
        Thread.ofPlatform().daemon().name("iroh-relay-server-accept").start(this::acceptLoop);
    }

    /** A token bucket rate: a sustained rate per second, and how much may be used at once. */
    public record RateLimit(double perSecond, double burst) {
        public RateLimit {
            if (perSecond <= 0 || burst <= 0) {
                throw new IllegalArgumentException("rate limits must be positive");
            }
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private InetSocketAddress bind = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        private RelayCertificate certificate;
        private InetSocketAddress quicBind;
        private InetSocketAddress metricsBind;
        private RelayMetrics metrics = new RelayMetrics();
        private Predicate<EndpointId> accessControl = id -> true;
        private RateLimit clientRx;
        private RateLimit acceptLimit;

        private Builder() {}

        /** The relay listener: HTTPS with {@link #tls}, else plain HTTP. */
        public Builder bind(InetSocketAddress bind) {
            this.bind = bind;
            return this;
        }

        /** Serve HTTPS with this certificate. Without one, plain HTTP. */
        public Builder tls(RelayCertificate certificate) {
            this.certificate = certificate;
            return this;
        }

        /** Run QUIC address discovery on this UDP address (iroh's default port is 7842). Needs TLS. */
        public Builder quicAddressDiscovery(InetSocketAddress quicBind) {
            this.quicBind = quicBind;
            return this;
        }

        /** Serve the metrics as OpenMetrics text on http://metricsBind/metrics. */
        public Builder metricsBind(InetSocketAddress metricsBind) {
            this.metricsBind = metricsBind;
            return this;
        }

        public Builder metrics(RelayMetrics metrics) {
            this.metrics = metrics;
            return this;
        }

        /** Which endpoints may connect; others are sent ServerDeniesAuth. */
        public Builder accessControl(Predicate<EndpointId> accessControl) {
            this.accessControl = accessControl;
            return this;
        }

        /**
         * Limits how fast each client connection is read, in bytes of relay frames, as iroh-relay's
         * limits.client_rx. A client over the limit is slowed down, not disconnected, and told once with
         * Status RateLimited (v2 clients).
         */
        public Builder clientRateLimit(RateLimit clientRx) {
            this.clientRx = clientRx;
            return this;
        }

        /** Limits how fast connections are accepted on the relay listener (iroh-relay's accept_conn_limit). */
        public Builder acceptRateLimit(RateLimit acceptLimit) {
            this.acceptLimit = acceptLimit;
            return this;
        }

        public RelayServer start() throws IOException {
            if (quicBind != null && certificate == null) {
                throw new IllegalStateException("QUIC address discovery needs TLS");
            }
            List<AutoCloseable> opened = new ArrayList<>();
            try {
                ServerSocket socket;
                if (certificate == null) {
                    socket = new ServerSocket();
                }
                else {
                    try {
                        socket = certificate.sslContext().getServerSocketFactory().createServerSocket();
                    }
                    catch (GeneralSecurityException e) {
                        throw new IOException(e);
                    }
                }
                opened.add(socket);
                socket.setReuseAddress(true);
                socket.bind(bind, 1024);
                QadServer qad = null;
                if (quicBind != null) {
                    qad = new QadServer(quicBind, certificate, metrics);
                    opened.add(qad);
                }
                HttpServer metricsServer = null;
                if (metricsBind != null) {
                    metricsServer = HttpServer.create(metricsBind, 16);
                    RelayMetrics metrics = this.metrics;
                    metricsServer.createContext("/metrics", exchange -> {
                        byte[] body = metrics.render().getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8");
                        exchange.sendResponseHeaders(200, body.length);
                        exchange.getResponseBody().write(body);
                        exchange.close();
                    });
                    metricsServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
                    metricsServer.start();
                    HttpServer started = metricsServer;
                    opened.add(() -> started.stop(0));
                }
                return new RelayServer(this, socket, qad, metricsServer);
            }
            catch (IOException | RuntimeException e) {
                for (AutoCloseable closeable : opened) {
                    try {
                        closeable.close();
                    }
                    catch (Exception ignored) {
                        // closing what was opened
                    }
                }
                throw e;
            }
        }
    }

    public InetSocketAddress address() {
        return (InetSocketAddress) serverSocket.getLocalSocketAddress();
    }

    /** The relay URL clients use, e.g. https://127.0.0.1:443/ */
    public URI url() {
        InetSocketAddress address = address();
        String host = address.getAddress().isAnyLocalAddress()? InetAddress.getLoopbackAddress().getHostAddress(): address.getAddress().getHostAddress();
        if (host.contains(":")) {
            host = "[" + host + "]";
        }
        return URI.create((certificate != null? "https": "http") + "://" + host + ":" + address.getPort() + "/");
    }

    /** The QUIC address discovery port, when it runs. */
    public OptionalInt quicPort() {
        return qad == null? OptionalInt.empty(): OptionalInt.of(qad.port());
    }

    /** The metrics listener's address, when there is one. */
    public Optional<InetSocketAddress> metricsAddress() {
        return Optional.ofNullable(metricsServer).map(HttpServer::getAddress);
    }

    public RelayMetrics metrics() {
        return metrics;
    }

    /** How many distinct endpoints are connected. */
    public int clientCount() {
        return clients.size();
    }

    public boolean isConnected(EndpointId id) {
        return clients.containsKey(id);
    }

    /** How many clients authenticated with TLS keying material rather than a challenge. */
    int keyMaterialAuthentications() {
        return keyMaterialAuthentications.get();
    }

    @Override
    public void close() {
        closed = true;
        try {
            serverSocket.close();
        }
        catch (IOException e) {
            // ignore
        }
        if (qad != null) {
            qad.close();
        }
        if (metricsServer != null) {
            metricsServer.stop(0);
        }
        for (Socket socket : sockets) {
            closeQuietly(socket);
        }
        timer.shutdownNow();
    }

    private void acceptLoop() {
        while (!closed) {
            Socket socket;
            try {
                if (acceptLimit != null) {
                    long wait = acceptLimit.consume(1);
                    if (wait > 0) {
                        Thread.sleep(Duration.ofNanos(wait));
                    }
                }
                socket = serverSocket.accept();
            }
            catch (InterruptedException e) {
                return;
            }
            catch (IOException e) {
                if (!closed) {
                    LOG.log(Level.WARNING, "relay accept failed", e);
                }
                continue;
            }
            sockets.add(socket);
            if (closed) {
                closeQuietly(socket);
                continue;
            }
            Thread.ofVirtual().name("iroh-relay-conn").start(() -> serve(socket));
        }
    }

    private void serve(Socket socket) {
        metrics.httpConnections.increment();
        boolean errored = false;
        try (socket) {
            socket.setSoTimeout((int) HANDSHAKE_TIMEOUT.toMillis());
            socket.setTcpNoDelay(true);
            InputStream in = new BufferedInputStream(socket.getInputStream());
            OutputStream out = new BufferedOutputStream(socket.getOutputStream(), 64 * 1024);
            ServerWebSocket.Request request = ServerWebSocket.readRequest(in);
            if (request == null) {
                return;
            }
            if (!request.method().equals("GET")) {
                ServerWebSocket.writeResponse(out, 405, "Method Not Allowed", Map.of("Connection", "close"), new byte[0]);
                return;
            }
            switch (request.path()) {
                case RELAY_PATH -> upgrade(socket, in, out, request);
                case PROBE_PATH -> ServerWebSocket.writeResponse(out, 200, "OK",
                        Map.of("Access-Control-Allow-Origin", "*", "Connection", "close"), new byte[0]);
                case "/generate_204" -> ServerWebSocket.writeResponse(out, 204, "No Content", Map.of("Connection", "close"), null);
                case "/robots.txt" -> ServerWebSocket.writeResponse(out, 200, "OK", Map.of("Connection", "close"),
                        "User-agent: *\nDisallow: /\n".getBytes(StandardCharsets.UTF_8));
                case "/", "/index.html" -> ServerWebSocket.writeResponse(out, 200, "OK",
                        Map.of("Content-Type", "text/plain; charset=utf-8", "Connection", "close"),
                        "iroh relay (jiroh)\n".getBytes(StandardCharsets.UTF_8));
                default -> ServerWebSocket.writeResponse(out, 404, "Not Found", Map.of("Connection", "close"), new byte[0]);
            }
        }
        catch (IOException | RuntimeException e) {
            errored = !(e instanceof SocketException || e instanceof EOFException);
            if (!closed) {
                LOG.log(Level.FINE, "relay connection from " + socket.getRemoteSocketAddress() + " ended", e);
            }
        }
        finally {
            sockets.remove(socket);
            metrics.httpConnectionsClosed.increment();
            if (errored) {
                metrics.httpConnectionsErrored.increment();
            }
        }
    }

    private void upgrade(Socket socket, InputStream in, OutputStream out, ServerWebSocket.Request request) throws IOException {
        String upgrade = request.header("upgrade");
        String key = request.header("sec-websocket-key");
        if (upgrade == null || !upgrade.toLowerCase(Locale.ROOT).contains("websocket") || key == null) {
            badRequest(out, Map.of(), "expected a websocket upgrade");
            return;
        }
        if (!"13".equals(request.header("sec-websocket-version"))) {
            badRequest(out, Map.of("Sec-WebSocket-Version", "13"), "unsupported websocket version");
            return;
        }
        String protocol = null;
        String offered = request.header("sec-websocket-protocol");
        if (offered != null) {
            Set<String> protocols = new HashSet<>();
            for (String p : offered.split(",")) {
                protocols.add(p.trim());
            }
            for (String supported : PROTOCOLS) {
                if (protocols.contains(supported)) {
                    protocol = supported;
                    break;
                }
            }
        }
        if (protocol == null) {
            badRequest(out, Map.of(), "unsupported relay version: we support " + String.join(", ", PROTOCOLS) + " but you only provide " + offered);
            return;
        }
        ServerWebSocket.writeResponse(out, 101, "Switching Protocols", Map.of(
                "Upgrade", "websocket",
                "Connection", "Upgrade",
                "Sec-WebSocket-Accept", ServerWebSocket.acceptKey(key),
                "Sec-WebSocket-Protocol", protocol), null);

        ServerWebSocket ws = new ServerWebSocket(in, out);
        EndpointId id = authenticate(socket, ws, request.header(CLIENT_AUTH_HEADER));
        if (id == null) {
            return;
        }
        if (!accessControl.test(id)) {
            deny(ws, "not authorized");
            return;
        }
        writeFrame(ws, new byte[]{SERVER_CONFIRMS_AUTH});
        socket.setSoTimeout(0);
        metrics.accepts.increment();
        metrics.clientConnected(id);
        try {
            new Client(id, protocol.equals(V2), socket, ws).run();
        }
        finally {
            metrics.disconnects.increment();
        }
    }

    private static void badRequest(OutputStream out, Map<String, String> headers, String message) throws IOException {
        Map<String, String> all = new java.util.LinkedHashMap<>(headers);
        all.put("Connection", "close");
        ServerWebSocket.writeResponse(out, 400, "Bad Request", all, message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Returns the client's endpoint id, or null after denying it. A client auth header signed over TLS keying
     * material saves a round trip; without one, or when it does not verify, the client answers a challenge.
     */
    private EndpointId authenticate(Socket socket, ServerWebSocket ws, String authHeader) throws IOException {
        if (authHeader != null && socket instanceof SSLSocket ssl) {
            EndpointId id = verifyKeyMaterialAuth(ssl, authHeader);
            if (id != null) {
                keyMaterialAuthentications.incrementAndGet();
                return id;
            }
        }
        byte[] challenge = new byte[16];
        random.nextBytes(challenge);
        // postcard ServerChallenge { challenge: [u8; 16] }
        byte[] frame = new byte[1 + 16];
        frame[0] = SERVER_CHALLENGE;
        System.arraycopy(challenge, 0, frame, 1, 16);
        writeFrame(ws, frame);

        ByteBuffer auth = ByteBuffer.wrap(readHandshakeFrame(ws));
        try {
            if (readVarint(auth) != CLIENT_AUTH) {
                throw new ProtocolException("expected ClientAuth");
            }
            // postcard ClientAuth { public_key: [u8; 32], signature: serde_bytes [u8; 64] }
            EndpointId id = readEndpointId(auth);
            if (readPostcardVarint(auth) != 64) {
                throw new ProtocolException("bad ClientAuth signature length");
            }
            byte[] signature = new byte[64];
            auth.get(signature);
            if (!verify(id, challengeMessage(challenge), signature)) {
                deny(ws, "signature invalid");
                return null;
            }
            return id;
        }
        catch (BufferUnderflowException | IllegalArgumentException e) {
            throw new ProtocolException("malformed ClientAuth");
        }
    }

    /** handshake.rs KeyMaterialClientAuth, sent base64url (no padding) in the x-iroh-relay-client-auth-v1 header. */
    private static EndpointId verifyKeyMaterialAuth(SSLSocket socket, String header) {
        try {
            ByteBuffer auth = ByteBuffer.wrap(Base64.getUrlDecoder().decode(header.trim()));
            EndpointId id = readEndpointId(auth);
            if (readPostcardVarint(auth) != 64) {
                return null;
            }
            byte[] signature = new byte[64];
            auth.get(signature);
            byte[] suffix = new byte[16];
            auth.get(suffix);
            byte[] keyMaterial = ((ExtendedSSLSession) socket.getSession())
                    .exportKeyingMaterialData(DOMAIN_SEP_TLS_EXPORT_LABEL, id.toBytes(), 32);
            if (keyMaterial == null || !MessageDigest.isEqual(suffix, Arrays.copyOfRange(keyMaterial, 16, 32))) {
                return null;
            }
            return verify(id, Arrays.copyOf(keyMaterial, 16), signature)? id: null;
        }
        catch (IOException | RuntimeException e) {
            LOG.log(Level.FINE, "client auth header did not verify, falling back to a challenge", e);
            return null;
        }
    }

    private static byte[] readHandshakeFrame(ServerWebSocket ws) throws IOException {
        while (true) {
            ServerWebSocket.Message message = ws.read(MAX_FRAME_SIZE);
            if (message == null || message.opcode() == ServerWebSocket.CLOSE) {
                throw new ProtocolException("connection closed during handshake");
            }
            switch (message.opcode()) {
                case ServerWebSocket.BINARY -> {
                    return message.data();
                }
                case ServerWebSocket.PING -> {
                    ws.write(ServerWebSocket.PONG, message.data(), 0, message.data().length);
                    ws.flush();
                }
                case ServerWebSocket.PONG -> {}
                default -> throw new ProtocolException("unexpected websocket message " + message.opcode());
            }
        }
    }

    private static void deny(ServerWebSocket ws, String reason) throws IOException {
        // postcard ServerDeniesAuth { reason: String }
        byte[] text = reason.getBytes(StandardCharsets.UTF_8);
        ByteBuffer frame = ByteBuffer.allocate(1 + postcardVarintLength(text.length) + text.length);
        frame.put((byte) SERVER_DENIES_AUTH);
        writePostcardVarint(frame, text.length);
        frame.put(text);
        writeFrame(ws, frame.array());
    }

    private static void writeFrame(ServerWebSocket ws, byte[] frame) throws IOException {
        ws.write(ServerWebSocket.BINARY, frame, 0, frame.length);
        ws.flush();
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        }
        catch (IOException e) {
            // ignore
        }
    }

    // ---- client registry, iroh-relay/src/server/clients.rs ----

    /** The connections of one endpoint id: the newest receives, older ones wait in case it goes away. */
    private static final class Registration {
        volatile Client active;
        final ArrayDeque<Client> inactive = new ArrayDeque<>();

        Registration(Client active) {
            this.active = active;
        }
    }

    private void register(Client client) {
        Client[] replaced = new Client[1];
        clients.compute(client.id, (id, registration) -> {
            if (registration == null) {
                return new Registration(client);
            }
            replaced[0] = registration.active;
            registration.inactive.push(registration.active);
            metrics.clientsInactiveAdded.increment();
            registration.active = client;
            return registration;
        });
        if (replaced[0] != null) {
            LOG.fine("relay: another connection for " + client.id + ", deactivating the old one");
            replaced[0].sendStatus(STATUS_SAME_ENDPOINT_ID_CONNECTED);
        }
    }

    private void unregister(Client client) {
        Client[] promoted = new Client[1];
        boolean[] gone = new boolean[1];
        clients.computeIfPresent(client.id, (id, registration) -> {
            if (registration.active != client) {
                if (registration.inactive.remove(client)) {
                    metrics.clientsInactiveRemoved.increment();
                }
                return registration;
            }
            Client next = registration.inactive.poll();
            if (next == null) {
                gone[0] = true;
                return null;
            }
            metrics.clientsInactiveRemoved.increment();
            registration.active = next;
            promoted[0] = next;
            return registration;
        });
        if (promoted[0] != null) {
            promoted[0].sendStatus(STATUS_HEALTHY);
        }
        if (gone[0]) {
            Set<EndpointId> peers = sentTo.remove(client.id);
            if (peers != null) {
                byte[] frame = new byte[1 + 32];
                frame[0] = ENDPOINT_GONE;
                System.arraycopy(client.idBytes, 0, frame, 1, 32);
                for (EndpointId peer : peers) {
                    Registration registration = clients.get(peer);
                    if (registration != null) {
                        registration.active.offer(new Outgoing(ServerWebSocket.BINARY, frame));
                    }
                }
            }
        }
    }

    private record Outgoing(int opcode, byte[] data) {}

    /** One authenticated WebSocket connection. Reads on the connection's thread; writes on its own thread. */
    private final class Client {
        final EndpointId id;
        final byte[] idBytes;
        final boolean v2;
        final Socket socket;
        final ServerWebSocket ws;
        final BlockingQueue<Outgoing> queue = new ArrayBlockingQueue<>(SEND_QUEUE_DEPTH);
        /** Destinations already recorded in sentTo; only the reader touches it. */
        final Set<EndpointId> recorded = new HashSet<>();
        volatile byte[] outstandingPing;
        final TokenBucket rxLimit = clientRx == null? null: new TokenBucket(clientRx.perSecond(), clientRx.burst());
        boolean rateLimited;
        Thread writer;

        Client(EndpointId id, boolean v2, Socket socket, ServerWebSocket ws) {
            this.id = id;
            this.idBytes = id.toBytes();
            this.v2 = v2;
            this.socket = socket;
            this.ws = ws;
        }

        void run() throws IOException {
            writer = Thread.ofVirtual().name("iroh-relay-writer").start(this::writeLoop);
            long interval = PING_INTERVAL.toMillis();
            ScheduledFuture<?> pinger = timer.scheduleWithFixedDelay(this::ping,
                    interval + ThreadLocalRandom.current().nextLong(interval / 10), interval, TimeUnit.MILLISECONDS);
            register(this);
            boolean closedByClient = false;
            try {
                closedByClient = readLoop();
            }
            finally {
                pinger.cancel(false);
                unregister(this);
                if (closedByClient) {
                    try {
                        writer.join(1000);
                    }
                    catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                closeQuietly(socket);
                writer.interrupt();
            }
        }

        boolean offer(Outgoing frame) {
            return queue.offer(frame);
        }

        /** Returns whether the client closed the WebSocket. */
        private boolean readLoop() throws IOException {
            while (true) {
                ServerWebSocket.Message message = ws.read(MAX_FRAME_SIZE);
                if (message == null) {
                    return false;
                }
                if (rxLimit != null) {
                    limitRate(message.data().length);
                }
                switch (message.opcode()) {
                    case ServerWebSocket.BINARY -> handleFrame(message.data());
                    case ServerWebSocket.PING -> offer(new Outgoing(ServerWebSocket.PONG, message.data()));
                    case ServerWebSocket.PONG -> {}
                    case ServerWebSocket.CLOSE -> {
                        queue.clear();
                        offer(STOP);
                        return true;
                    }
                    default -> throw new ProtocolException("unexpected websocket message " + message.opcode());
                }
            }
        }

        private void limitRate(int bytes) throws InterruptedIOException {
            long wait = rxLimit.consume(bytes);
            if (wait == 0) {
                return;
            }
            metrics.bytesRxRatelimited.add(bytes);
            if (!rateLimited) {
                rateLimited = true;
                metrics.connsRxRatelimited.increment();
                if (v2) {
                    offer(new Outgoing(ServerWebSocket.BINARY, new byte[]{STATUS, STATUS_RATE_LIMITED}));
                }
            }
            try {
                Thread.sleep(Duration.ofNanos(wait));
            }
            catch (InterruptedException e) {
                throw new InterruptedIOException();
            }
        }

        private void handleFrame(byte[] frame) throws ProtocolException {
            ByteBuffer buffer = ByteBuffer.wrap(frame);
            int type;
            try {
                type = (int) readVarint(buffer);
            }
            catch (BufferUnderflowException e) {
                throw new ProtocolException("empty relay frame");
            }
            if (buffer.remaining() > MAX_PACKET_SIZE) {
                throw new ProtocolException("relay frame too large: " + buffer.remaining());
            }
            switch (type) {
                case CLIENT_TO_RELAY_DATAGRAM, CLIENT_TO_RELAY_DATAGRAM_BATCH -> {
                    boolean batch = type == CLIENT_TO_RELAY_DATAGRAM_BATCH;
                    if (buffer.position() != 1 || buffer.remaining() < 32 + (batch? 3: 1)) {
                        throw new ProtocolException("malformed datagram frame");
                    }
                    EndpointId destination = EndpointId.fromBytes(Arrays.copyOfRange(frame, 1, 33));
                    metrics.sendPacketsRecv.increment();
                    metrics.bytesRecv.add(frame.length - 34 - (batch? 2: 0));
                    // The same layout with the source in place of the destination: [type][endpoint id][ecn][segment size][contents]
                    frame[0] = (byte) (batch? RELAY_TO_CLIENT_DATAGRAM_BATCH: RELAY_TO_CLIENT_DATAGRAM);
                    System.arraycopy(idBytes, 0, frame, 1, 32);
                    forward(destination, frame);
                }
                case PING -> {
                    if (buffer.remaining() != 8) {
                        throw new ProtocolException("malformed ping");
                    }
                    metrics.gotPing.increment();
                    byte[] pong = new byte[9];
                    pong[0] = PONG;
                    buffer.get(pong, 1, 8);
                    offer(new Outgoing(ServerWebSocket.BINARY, pong));
                }
                case PONG -> {
                    byte[] payload = new byte[8];
                    if (buffer.remaining() == 8) {
                        buffer.get(payload);
                        if (Arrays.equals(payload, outstandingPing)) {
                            outstandingPing = null;
                        }
                    }
                }
                default -> {
                    metrics.unknownFrames.increment();
                    LOG.fine("relay: ignoring frame type " + type + " from " + id);
                }
            }
        }

        private void forward(EndpointId destination, byte[] frame) {
            Registration registration = clients.get(destination);
            if (registration == null) {
                metrics.sendPacketsDropped.increment();
                return;
            }
            if (registration.active.offer(new Outgoing(ServerWebSocket.BINARY, frame)) && recorded.add(destination)) {
                sentTo.computeIfAbsent(id, k -> ConcurrentHashMap.newKeySet()).add(destination);
            }
        }

        void sendStatus(int status) {
            if (v2) {
                offer(new Outgoing(ServerWebSocket.BINARY, new byte[]{STATUS, (byte) status}));
                return;
            }
            String problem = status == STATUS_SAME_ENDPOINT_ID_CONNECTED
                    ? "Another endpoint connected with the same endpoint id. No more messages will be received."
                    : "The connection is healthy and has recovered from previous problems";
            byte[] text = problem.getBytes(StandardCharsets.UTF_8);
            byte[] frame = new byte[1 + text.length];
            frame[0] = HEALTH;
            System.arraycopy(text, 0, frame, 1, text.length);
            offer(new Outgoing(ServerWebSocket.BINARY, frame));
        }

        /** A client that has not answered within PONG_TIMEOUT is dropped. */
        private void ping() {
            byte[] payload = new byte[8];
            ThreadLocalRandom.current().nextBytes(payload);
            outstandingPing = payload;
            byte[] frame = new byte[9];
            frame[0] = PING;
            System.arraycopy(payload, 0, frame, 1, 8);
            offer(new Outgoing(ServerWebSocket.BINARY, frame));
            timer.schedule(() -> {
                if (outstandingPing == payload) {
                    LOG.fine("relay: " + id + " did not answer a ping, disconnecting");
                    closeQuietly(socket);
                }
            }, PONG_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        }

        private void countSent(byte[] frame) {
            switch (frame[0]) {
                case RELAY_TO_CLIENT_DATAGRAM -> {
                    metrics.sendPacketsSent.increment();
                    metrics.bytesSent.add(frame.length - 34);
                }
                case RELAY_TO_CLIENT_DATAGRAM_BATCH -> {
                    metrics.sendPacketsSent.increment();
                    metrics.bytesSent.add(frame.length - 36);
                }
                case PONG -> metrics.sentPong.increment();
                default -> {}
            }
        }

        private void writeLoop() {
            try {
                while (true) {
                    Outgoing next = queue.take();
                    do {
                        if (next == STOP) {
                            ws.write(ServerWebSocket.CLOSE, next.data(), 0, 0);
                            ws.flush();
                            return;
                        }
                        ws.write(next.opcode(), next.data(), 0, next.data().length);
                        if (next.opcode() == ServerWebSocket.BINARY) {
                            countSent(next.data());
                        }
                    } while ((next = queue.poll()) != null);
                    ws.flush();
                }
            }
            catch (InterruptedException e) {
                // connection closed
            }
            catch (IOException e) {
                if (!(e instanceof SocketException) && !closed) {
                    LOG.log(Level.FINE, "relay write to " + id + " failed", e);
                }
                closeQuietly(socket);
            }
        }
    }

    private static final String USAGE = String.join("\n",
            "usage: RelayServer [options]",
            "  --bind host:port          relay listener (443 with TLS, else 127.0.0.1:3340 plain HTTP)",
            "  --cert chain.pem --key key.pem   a certificate and PKCS#8 key",
            "  --quic-bind host:port | --no-quic    QUIC address discovery (default :7842 with TLS)",
            "  --metrics-bind host:port  serve OpenMetrics on /metrics",
            "  --client-rx bytes/s[:burst]   per-client receive rate limit (burst defaults to a tenth of a second)",
            "  --accept-limit conns/s[:burst]  rate limit on accepting connections");

    /** Runs a relay; see USAGE. Without a certificate it serves plain HTTP, for local testing only. */
    public static void main(String[] args) throws Exception {
        String bind = null;
        String quicBind = null;
        String metricsBind = null;
        boolean quic = true;
        Path cert = null;
        Path key = null;
        RateLimit clientRx = null;
        RateLimit acceptLimit = null;
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--bind" -> bind = args[++i];
                    case "--cert" -> cert = Path.of(args[++i]);
                    case "--key" -> key = Path.of(args[++i]);
                    case "--quic-bind" -> quicBind = args[++i];
                    case "--no-quic" -> quic = false;
                    case "--metrics-bind" -> metricsBind = args[++i];
                    case "--client-rx" -> clientRx = rateLimit(args[++i], 0.1);
                    case "--accept-limit" -> acceptLimit = rateLimit(args[++i], 1);
                    default -> throw new IllegalArgumentException("unknown option " + args[i]);
                }
            }
            if ((cert == null) != (key == null)) {
                throw new IllegalArgumentException("--cert and --key go together");
            }
        }
        catch (RuntimeException e) {
            System.err.println(e.getMessage() + "\n" + USAGE);
            System.exit(2);
            return;
        }
        boolean tls = cert != null;
        InetSocketAddress relayAddress = parseAddress(bind != null? bind: tls? "0.0.0.0:443": "127.0.0.1:3340");
        Builder builder = builder().bind(relayAddress).clientRateLimit(clientRx).acceptRateLimit(acceptLimit);
        if (tls) {
            builder.tls(RelayCertificate.fromPem(cert, key));
            String host = relayAddress.getAddress().getHostAddress();
            if (quic) {
                builder.quicAddressDiscovery(parseAddress(quicBind != null? quicBind: host + ":" + QuicAddressDiscovery.DEFAULT_RELAY_QUIC_PORT));
            }
        }
        if (metricsBind != null) {
            builder.metricsBind(parseAddress(metricsBind));
        }
        RelayServer server = builder.start();
        LOG.info("iroh relay listening on " + server.url());
        Thread.currentThread().join();
    }

    private static RateLimit rateLimit(String value, double defaultBurstSeconds) {
        String[] parts = value.split(":");
        double rate = Double.parseDouble(parts[0]);
        double burst = parts.length > 1? Double.parseDouble(parts[1]): Math.max(1, rate * defaultBurstSeconds);
        return new RateLimit(rate, burst);
    }

    private static InetSocketAddress parseAddress(String hostPort) throws IOException {
        int colon = hostPort.lastIndexOf(':');
        String host = hostPort.substring(0, colon).replaceAll("^\\[|]$", "");
        return new InetSocketAddress(InetAddress.getByName(host.isEmpty()? "0.0.0.0": host), Integer.parseInt(hostPort.substring(colon + 1)));
    }
}
