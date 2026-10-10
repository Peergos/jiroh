package org.peergos.iroh;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A client of an iroh relay (iroh-relay protocol v2, falling back to v1), carrying QUIC datagrams to and from
 * other endpoints connected to the same relay. Each remote endpoint is addressed by a relay mapped address.
 *
 * Protocol: iroh-relay/src/protos/{handshake,relay}.rs. Frames are binary WebSocket messages starting with a
 * QUIC varint frame type.
 */
public final class RelayTransport implements PacketTransport, AutoCloseable {

    private static final Logger LOG = Logger.getLogger(RelayTransport.class.getName());

    static final String RELAY_PATH = "/relay";
    static final String[] PROTOCOLS = {"iroh-relay-v2", "iroh-relay-v1"};
    private static final String DOMAIN_SEP_CHALLENGE = "iroh-relay handshake v1 challenge signature";
    private static final int MAX_FRAME_SIZE = 1024 * 1024;
    private static final int MAX_PENDING_SENDS = 1024;

    // FrameType, iroh-relay/src/protos/common.rs
    static final int SERVER_CHALLENGE = 0;
    static final int CLIENT_AUTH = 1;
    static final int SERVER_CONFIRMS_AUTH = 2;
    static final int SERVER_DENIES_AUTH = 3;
    static final int CLIENT_TO_RELAY_DATAGRAM = 4;
    static final int CLIENT_TO_RELAY_DATAGRAM_BATCH = 5;
    static final int RELAY_TO_CLIENT_DATAGRAM = 6;
    static final int RELAY_TO_CLIENT_DATAGRAM_BATCH = 7;
    static final int ENDPOINT_GONE = 8;
    static final int PING = 9;
    static final int PONG = 10;
    static final int HEALTH = 11;
    static final int RESTARTING = 12;
    static final int STATUS = 13;

    private final URI relayUrl;
    private final SecretKey secretKey;
    private final Map<EndpointId, InetSocketAddress> addresses = new ConcurrentHashMap<>();
    private final Map<InetSocketAddress, EndpointId> endpoints = new ConcurrentHashMap<>();
    private final CompletableFuture<Void> authenticated = new CompletableFuture<>();
    private final AtomicInteger pendingSends = new AtomicInteger();
    private final Object sendLock = new Object();
    private CompletableFuture<?> sendChain = CompletableFuture.completedFuture(null);
    private volatile WebSocket webSocket;
    private volatile PacketSink sink;
    private volatile String protocol;
    private volatile boolean closed;

    private RelayTransport(URI relayUrl, SecretKey secretKey) {
        this.relayUrl = relayUrl;
        this.secretKey = secretKey;
    }

    /**
     * Connects to the relay and authenticates as the endpoint of the given key.
     * @param relayUrl  the relay URL as iroh uses it, e.g. https://relay.example/ (http only for local testing)
     */
    public static RelayTransport connect(URI relayUrl, SecretKey secretKey, Duration timeout) throws IOException {
        RelayTransport transport = new RelayTransport(relayUrl, secretKey);
        transport.open(timeout);
        return transport;
    }

    public URI relayUrl() {
        return relayUrl;
    }

    /** The negotiated relay protocol version, e.g. "iroh-relay-v2". */
    public String protocol() {
        return protocol;
    }

    /** The mapped address under which the given endpoint is reachable via this relay. */
    public InetSocketAddress addressFor(EndpointId remote) {
        return addresses.computeIfAbsent(remote, id -> {
            InetSocketAddress mapped = MappedAddresses.newRelayMapped();
            endpoints.put(mapped, id);
            return mapped;
        });
    }

    private void open(Duration timeout) throws IOException {
        URI wsUri = URI.create(("https".equals(relayUrl.getScheme())? "wss": "ws") + "://" + relayUrl.getRawAuthority() + RELAY_PATH);
        HttpClient client = HttpClient.newBuilder().connectTimeout(timeout).build();
        try {
            client.newWebSocketBuilder()
                    .subprotocols(PROTOCOLS[0], PROTOCOLS[1])
                    .connectTimeout(timeout)
                    .buildAsync(wsUri, new Listener())
                    .get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            protocol = webSocket.getSubprotocol();
            authenticated.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
        catch (ExecutionException e) {
            close();
            throw new IOException("relay connection failed: " + e.getCause().getMessage(), e.getCause());
        }
        catch (TimeoutException e) {
            close();
            throw new IOException("relay connection timed out", e);
        }
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
                PacketSink sink = this.sink;
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
            case PONG -> { }
            case ENDPOINT_GONE -> LOG.fine("relay: endpoint gone " + readEndpointId(frame));
            case STATUS -> LOG.info("relay status " + (frame.get() & 0xff) + " from " + relayUrl);
            case HEALTH -> LOG.info("relay health: " + StandardCharsets.UTF_8.decode(frame));
            case RESTARTING -> LOG.info("relay restarting: " + relayUrl);
            default -> LOG.fine("relay: ignoring frame type " + type);
        }
    }

    private void handleHandshakeFrame(int type, ByteBuffer frame) {
        switch (type) {
            case SERVER_CHALLENGE -> {
                // postcard ServerChallenge { challenge: [u8; 16] }: the 16 bytes as they are
                byte[] challenge = new byte[16];
                frame.get(challenge);
                byte[] signature = sign(Blake3.deriveKey(DOMAIN_SEP_CHALLENGE, challenge));
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
            throw new IOException("relay connection closed");
        }
        ByteBuffer frame = ByteBuffer.allocate(1 + 32 + 1 + length);
        frame.put((byte) CLIENT_TO_RELAY_DATAGRAM).put(to.toBytes()).put((byte) 0).put(data, offset, length).flip();
        sendFrame(frame);
    }

    /**
     * Java's WebSocket allows one outstanding send, so sends are chained. Like UDP, datagrams are dropped rather
     * than queued without bound when the relay connection cannot keep up.
     */
    private void sendFrame(ByteBuffer frame) {
        if (pendingSends.incrementAndGet() > MAX_PENDING_SENDS) {
            pendingSends.decrementAndGet();
            return;
        }
        synchronized (sendLock) {
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

    @Override
    public void start(PacketSink sink) {
        this.sink = sink;
    }

    @Override
    public void close() {
        closed = true;
        WebSocket ws = webSocket;
        if (ws != null) {
            ws.sendClose(WebSocket.NORMAL_CLOSURE, "").exceptionally(e -> null);
            ws.abort();
        }
        authenticated.completeExceptionally(new IOException("closed"));
    }

    private byte[] sign(byte[] message) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(secretKey.keyPair().getPrivate());
            signature.update(message);
            return signature.sign();
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    private static EndpointId readEndpointId(ByteBuffer frame) {
        byte[] id = new byte[32];
        frame.get(id);
        return EndpointId.fromBytes(id);
    }

    /** QUIC variable-length integer (RFC 9000 section 16). */
    static long readVarint(ByteBuffer buffer) {
        int first = buffer.get() & 0xff;
        int length = 1 << (first >> 6);
        long value = first & 0x3f;
        for (int i = 1; i < length; i++) {
            value = (value << 8) | (buffer.get() & 0xff);
        }
        return value;
    }

    /** postcard's LEB128 varint. */
    private static long readPostcardVarint(ByteBuffer buffer) {
        long value = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            int b = buffer.get() & 0xff;
            value |= (long) (b & 0x7f) << shift;
            if ((b & 0x80) == 0) {
                break;
            }
        }
        return value;
    }

    private class Listener implements WebSocket.Listener {
        private final ByteArrayOutputStream partial = new ByteArrayOutputStream();

        @Override
        public void onOpen(WebSocket webSocket) {
            // The relay's challenge can arrive before buildAsync completes, so take the socket from here.
            RelayTransport.this.webSocket = webSocket;
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
            closed = true;
            authenticated.completeExceptionally(new IOException("relay closed connection: " + statusCode + " " + reason));
            return null;
        }

        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            closed = true;
            authenticated.completeExceptionally(error);
        }
    }
}
