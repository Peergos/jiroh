package org.peergos.iroh.pkarr;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A read-only client of the BitTorrent mainline DHT (BEP5) for mutable items (BEP44), as pkarr uses it. It does not
 * keep a routing table or answer queries (BEP43 "ro"); each lookup walks from the bootstrap nodes and a small cache
 * of nodes that answered recently towards the target.
 */
public final class MainlineDht implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(MainlineDht.class.getName());

    public static final List<String> DEFAULT_BOOTSTRAP = List.of(
            "router.bittorrent.com:6881", "dht.transmissionbt.com:6881", "dht.libtorrent.org:25401", "relay.pkarr.org:6881");

    private static final int K = 8;
    private static final int ALPHA = 8;
    private static final Duration REQUEST_TIMEOUT = Duration.ofMillis(1500);
    // A node that has not answered by then no longer holds up the lookup (but a late answer is still used).
    private static final long SLOW_NANOS = Duration.ofMillis(400).toNanos();
    private static final int MAX_CACHED_NODES = 256;

    /** A BEP44 mutable item without salt, as pkarr publishes it. */
    public record MutableItem(byte[] k, long seq, byte[] sig, byte[] v) {}

    record Node(byte[] id, InetSocketAddress address) {}

    private record Response(InetSocketAddress from, Map<String, Object> body) {}

    private final DatagramChannel channel;
    private final List<InetSocketAddress> bootstrap;
    private final byte[] nodeId = new byte[20];
    private final Map<Integer, CompletableFuture<Response>> pending = new ConcurrentHashMap<>();
    private final AtomicInteger nextTransaction = new AtomicInteger(new SecureRandom().nextInt());
    private final Map<InetSocketAddress, Node> cache = java.util.Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<InetSocketAddress, Node> eldest) {
            return size() > MAX_CACHED_NODES;
        }
    });
    private final Thread receiver;
    private volatile boolean closed;

    private MainlineDht(DatagramChannel channel, List<InetSocketAddress> bootstrap) {
        this.channel = channel;
        this.bootstrap = bootstrap;
        new SecureRandom().nextBytes(nodeId);
        receiver = Thread.ofVirtual().name("mainline-dht").start(this::receive);
    }

    public static MainlineDht start(InetSocketAddress bindAddress, List<InetSocketAddress> bootstrap) throws IOException {
        DatagramChannel channel = DatagramChannel.open();
        channel.bind(bindAddress);
        return new MainlineDht(channel, List.copyOf(bootstrap));
    }

    /** Resolves "host:port" strings; unresolvable ones are skipped. */
    public static List<InetSocketAddress> resolve(List<String> hostPorts) {
        List<InetSocketAddress> addresses = new ArrayList<>();
        for (String hostPort : hostPorts) {
            int colon = hostPort.lastIndexOf(':');
            InetSocketAddress address = new InetSocketAddress(hostPort.substring(0, colon), Integer.parseInt(hostPort.substring(colon + 1)));
            if (!address.isUnresolved()) {
                addresses.add(address);
            }
        }
        return addresses;
    }

    public InetSocketAddress localAddress() throws IOException {
        return (InetSocketAddress) channel.getLocalAddress();
    }

    /**
     * Gets the mutable item with the highest sequence number stored under the given Ed25519 public key.
     */
    public Optional<MutableItem> get(byte[] publicKey, Duration timeout) {
        Lookup lookup = lookup(sha1(publicKey), timeout, true);
        return lookup.items.stream()
                .filter(item -> Arrays.equals(item.k, publicKey))
                .max(Comparator.comparingLong(MutableItem::seq));
    }

    /**
     * Stores a mutable item on the nodes closest to its key that the lookup reached.
     * @return  the number of nodes that confirmed the put
     */
    public int put(MutableItem item, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        Lookup lookup = lookup(sha1(item.k), timeout, false);
        List<Node> closest = lookup.closestWithTokens();
        // Store on the K closest; if too few of them confirm, also on the next closest.
        int stored = putAll(item, lookup, closest.subList(0, Math.min(K, closest.size())), deadline);
        if (stored < K / 2 && closest.size() > K) {
            stored += putAll(item, lookup, closest.subList(K, Math.min(2 * K, closest.size())), deadline);
        }
        return stored;
    }

    private int putAll(MutableItem item, Lookup lookup, List<Node> nodes, long deadline) {
        List<CompletableFuture<Response>> puts = new ArrayList<>();
        for (Node node : nodes) {
            Map<String, Object> args = new HashMap<>();
            args.put("id", nodeId);
            args.put("token", lookup.tokens.get(node.address()));
            // Not in BEP44, but the Rust mainline crate requires it; other nodes ignore it.
            args.put("target", lookup.target);
            args.put("k", item.k);
            args.put("seq", item.seq);
            args.put("sig", item.sig);
            args.put("v", item.v);
            puts.add(query(node.address(), "put", args));
        }
        int stored = 0;
        for (CompletableFuture<Response> put : puts) {
            try {
                long remaining = Math.max(1, deadline - System.nanoTime());
                Response response = put.get(remaining, TimeUnit.NANOSECONDS);
                if (response != null && "r".equals(Bencode.string(response.body, "y"))) {
                    stored++;
                }
                else if (response != null) {
                    LOG.fine("put rejected by " + response.from + ": " + response.body.get("e"));
                }
            }
            catch (Exception e) {
                // timed out or failed
            }
        }
        return stored;
    }

    private final class Lookup {
        final byte[] target;
        final Map<InetSocketAddress, byte[]> tokens = new HashMap<>();
        final List<MutableItem> items = new ArrayList<>();
        final Map<InetSocketAddress, Node> responded = new HashMap<>();

        Lookup(byte[] target) {
            this.target = target;
        }

        List<Node> closestWithTokens() {
            return responded.values().stream()
                    .filter(n -> tokens.containsKey(n.address()))
                    .sorted(Comparator.comparing(n -> distance(n.id(), target), Arrays::compareUnsigned))
                    .toList();
        }
    }

    /**
     * @param wantValue  whether to keep waiting for slow nodes near the target until a value is found
     */
    private Lookup lookup(byte[] target, Duration timeout, boolean wantValue) {
        long deadline = System.nanoTime() + timeout.toNanos();
        Lookup lookup = new Lookup(target);
        // Candidates of unknown id (bootstrap nodes) sort first, so they are queried right away.
        Comparator<Node> byDistance = Comparator.comparing(
                n -> n.id() == null? new byte[20]: distance(n.id(), target), Arrays::compareUnsigned);
        Map<InetSocketAddress, Node> candidates = new HashMap<>();
        bootstrap.forEach(a -> candidates.put(a, new Node(null, a)));
        synchronized (cache) {
            cache.values().stream().sorted(byDistance).limit(K * 2).forEach(n -> candidates.put(n.address(), n));
        }
        Set<InetSocketAddress> queried = new HashSet<>();
        Map<InetSocketAddress, Node> inFlight = new HashMap<>();
        Map<InetSocketAddress, Long> sentAt = new HashMap<>();
        int refills = 0;
        // Nodes asked with find_node because their id was unknown; once it is known they may be asked to get.
        Set<InetSocketAddress> findNodeQueried = new HashSet<>();
        LinkedBlockingQueue<Response> responses = new LinkedBlockingQueue<>();

        while (System.nanoTime() < deadline) {
            // The lookup has converged once the K closest nodes that answered are closer than every node that has
            // not been asked yet or has not answered yet; slow nodes further away are not waited for.
            List<Node> closestResponders = lookup.responded.values().stream().sorted(byDistance).limit(K).toList();
            Node kth = closestResponders.size() == K? closestResponders.get(K - 1): null;
            List<Node> worthAsking = candidates.values().stream()
                    .filter(n -> !queried.contains(n.address()))
                    .filter(n -> kth == null || (n.id() != null && byDistance.compare(n, kth) < 0))
                    .sorted(byDistance)
                    .toList();
            long now = System.nanoTime();
            List<Node> active = inFlight.values().stream()
                    .filter(n -> now - sentAt.get(n.address()) < SLOW_NANOS)
                    .toList();
            boolean waitForSlow = wantValue && lookup.items.isEmpty();
            boolean closerInFlight = (waitForSlow? inFlight.values(): active).stream()
                    .anyMatch(n -> kth == null || (n.id() != null && byDistance.compare(n, kth) < 0));
            if (worthAsking.isEmpty() && inFlight.isEmpty() && kth == null && refills < 3) {
                // Ran out of nodes before reaching the target (a cold start whose first nodes were all
                // unreachable): ask the bootstrap nodes for more, around random ids.
                refills++;
                for (InetSocketAddress address : bootstrap) {
                    Map<String, Object> args = new HashMap<>();
                    args.put("id", nodeId);
                    byte[] random = new byte[20];
                    ThreadLocalRandom.current().nextBytes(random);
                    args.put("target", random);
                    inFlight.put(address, new Node(null, address));
                    sentAt.put(address, now);
                    findNodeQueried.add(address);
                    query(address, "find_node", args).whenComplete((response, error) ->
                            responses.add(response != null? response: new Response(address, null)));
                }
                continue;
            }
            if (worthAsking.isEmpty() && !closerInFlight && (kth != null || inFlight.isEmpty())) {
                break;
            }
            int activeCount = active.size();
            for (Node node : worthAsking) {
                if (activeCount >= ALPHA) {
                    break;
                }
                activeCount++;
                queried.add(node.address());
                inFlight.put(node.address(), node);
                sentAt.put(node.address(), now);
                Map<String, Object> args = new HashMap<>();
                args.put("id", nodeId);
                args.put("target", target);
                // Bootstrap routers (whose id is unknown) often implement only BEP5, so they get find_node.
                if (node.id() == null) {
                    findNodeQueried.add(node.address());
                }
                query(node.address(), node.id() == null? "find_node": "get", args).whenComplete((response, error) ->
                        responses.add(response != null? response: new Response(node.address(), null)));
            }
            Response response;
            try {
                long remaining = Math.min(deadline - System.nanoTime(), SLOW_NANOS / 4);
                response = responses.poll(Math.max(1, remaining), TimeUnit.NANOSECONDS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            if (response == null) {
                continue;
            }
            inFlight.remove(response.from);
            sentAt.remove(response.from);
            if (response.body == null) {
                candidates.remove(response.from);
                cache.remove(response.from);
                continue;
            }
            handleGetResponse(lookup, response, candidates);
            if (findNodeQueried.remove(response.from)) {
                // It answered find_node, which gives no token or value: ask it again with get if it is close.
                lookup.responded.remove(response.from);
                queried.remove(response.from);
            }
        }
        return lookup;
    }

    private void handleGetResponse(Lookup lookup, Response response, Map<InetSocketAddress, Node> candidates) {
        Map<String, Object> r = Bencode.dict(response.body, "r");
        if (r == null) {
            candidates.remove(response.from);
            return;
        }
        byte[] id = Bencode.bytes(r, "id");
        if (id == null || id.length != 20) {
            return;
        }
        Node node = new Node(id, response.from);
        candidates.put(response.from, node);
        lookup.responded.put(response.from, node);
        cache.put(response.from, node);
        byte[] token = Bencode.bytes(r, "token");
        if (token != null) {
            lookup.tokens.put(response.from, token);
        }
        byte[] nodes = Bencode.bytes(r, "nodes");
        if (nodes != null) {
            for (int offset = 0; offset + 26 <= nodes.length; offset += 26) {
                byte[] nodeId = Arrays.copyOfRange(nodes, offset, offset + 20);
                InetSocketAddress address = compactAddress(nodes, offset + 20);
                if (address != null && !candidates.containsKey(address)) {
                    candidates.put(address, new Node(nodeId, address));
                }
            }
        }
        byte[] k = Bencode.bytes(r, "k");
        byte[] sig = Bencode.bytes(r, "sig");
        Long seq = Bencode.number(r, "seq");
        byte[] v = Bencode.bytes(r, "v");
        if (k != null && sig != null && seq != null && v != null && k.length == 32 && Arrays.equals(sha1(k), lookup.target)) {
            try {
                // Verifies the signature; an invalid item from a misbehaving node is dropped.
                SignedPacket.fromParts(org.peergos.iroh.EndpointId.fromBytes(k), seq, sig, v);
                lookup.items.add(new MutableItem(k, seq, sig, v));
            }
            catch (IllegalArgumentException e) {
                LOG.fine("invalid mutable item from " + response.from);
            }
        }
    }

    private static InetSocketAddress compactAddress(byte[] data, int offset) {
        try {
            InetAddress ip = InetAddress.getByAddress(Arrays.copyOfRange(data, offset, offset + 4));
            int port = ((data[offset + 4] & 0xff) << 8) | (data[offset + 5] & 0xff);
            if (port == 0 || ip.isAnyLocalAddress() || ip.isMulticastAddress()) {
                return null;
            }
            return new InetSocketAddress(ip, port);
        }
        catch (java.net.UnknownHostException e) {
            return null;
        }
    }

    private CompletableFuture<Response> query(InetSocketAddress to, String method, Map<String, Object> args) {
        // Four bytes: the Rust mainline crate (used by pkarr) drops messages with any other length.
        int transaction = nextTransaction.getAndIncrement();
        byte[] t = ByteBuffer.allocate(4).putInt(transaction).array();
        Map<String, Object> message = new HashMap<>();
        message.put("t", t);
        message.put("y", "q");
        message.put("q", method);
        message.put("a", args);
        message.put("ro", 1L);
        CompletableFuture<Response> future = new CompletableFuture<>();
        pending.put(transaction, future);
        future.orTimeout(REQUEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
                .whenComplete((r, e) -> pending.remove(transaction, future));
        try {
            if (to.getAddress() instanceof Inet4Address || !(channel.getLocalAddress() instanceof InetSocketAddress local
                    && local.getAddress() instanceof Inet4Address)) {
                channel.send(ByteBuffer.wrap(Bencode.encode(message)), to);
            }
            else {
                future.completeExceptionally(new IOException("cannot send to " + to));
            }
        }
        catch (IOException e) {
            future.completeExceptionally(e);
        }
        return future;
    }

    private void receive() {
        ByteBuffer buffer = ByteBuffer.allocate(2048);
        while (!closed) {
            try {
                buffer.clear();
                InetSocketAddress from = (InetSocketAddress) channel.receive(buffer);
                buffer.flip();
                byte[] data = new byte[buffer.remaining()];
                buffer.get(data);
                Object decoded = Bencode.decode(data);
                if (!(decoded instanceof Map<?, ?> message)) {
                    continue;
                }
                byte[] t = Bencode.bytes(message, "t");
                String y = Bencode.string(message, "y");
                if (t == null || t.length != 4 || !("r".equals(y) || "e".equals(y))) {
                    continue; // queries are ignored: this node is read-only
                }
                int transaction = ByteBuffer.wrap(t).getInt();
                CompletableFuture<Response> future = pending.get(transaction);
                if (future != null) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> body = (Map<String, Object>) message;
                    future.complete(new Response(from, body));
                }
            }
            catch (ClosedChannelException e) {
                return;
            }
            catch (IOException | RuntimeException e) {
                if (!closed) {
                    LOG.log(Level.FINE, "invalid DHT message", e);
                }
            }
        }
    }

    static byte[] distance(byte[] a, byte[] b) {
        byte[] d = new byte[20];
        for (int i = 0; i < 20; i++) {
            d[i] = (byte) (a[i] ^ b[i]);
        }
        return d;
    }

    static byte[] sha1(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-1").digest(data);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        closed = true;
        try {
            channel.close();
        }
        catch (IOException e) {
            // ignore
        }
    }
}
