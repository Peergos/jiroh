package org.peergos.iroh.mdns;

import org.peergos.iroh.EndpointAddr;
import org.peergos.iroh.EndpointId;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ProtocolFamily;
import java.net.SocketException;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Finds endpoints on the local network with mDNS, compatible with iroh's {@code iroh-mdns-address-lookup} and the
 * swarm-discovery crate it is built on.
 *
 * Each endpoint answers PTR queries for {@code _irohv1._udp.local} with an SRV record
 * {@code <id>._irohv1._udp.local -> <id>-<port>.local} per port, A/AAAA records for its addresses, and a TXT record
 * with its home relay; the id is the endpoint id in lowercase unpadded base32. As in swarm-discovery, queries and
 * responses are paced by the swarm size so that the traffic stays bounded however many endpoints there are
 * (τ = 0.7s, φ = 2.5Hz, its settings for interactive use), and an endpoint expires when it has not been heard from
 * for three of its expected response intervals.
 */
public final class MdnsAddressLookup implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(MdnsAddressLookup.class.getName());

    public static final String SERVICE_NAME = "irohv1";
    static final String RELAY_ATTRIBUTE = "relay";
    static final int PORT = 5353;
    static final InetSocketAddress GROUP_V4 = new InetSocketAddress(literal("224.0.0.251"), PORT);
    static final InetSocketAddress GROUP_V6 = new InetSocketAddress(literal("ff02::fb"), PORT);
    private static final Duration CADENCE = Duration.ofMillis(700);
    private static final float RESPONSE_RATE = 2.5f;
    private static final long RESPONSE_DELAY_NANOS = Duration.ofMillis(100).toNanos();
    private static final int MAX_TXT_ATTRIBUTE = 254;

    public sealed interface Event {
        /** An endpoint was found, or its addresses changed. */
        record Discovered(EndpointAddr addr) implements Event {}
        /** An endpoint has not been heard from for a while. */
        record Expired(EndpointId id) implements Event {}
    }

    private enum Family { V4, V6, ANY }

    private sealed interface Input {}
    private record QueryReceived(Family family) implements Input {}
    private record ResponseReceived(Map<String, Peer> peers) implements Input {}

    private record Peer(List<InetSocketAddress> addrs, Map<String, String> txt, long lastSeen) {
        boolean sameAs(Peer other) {
            return other != null && addrs.equals(other.addrs) && txt.equals(other.txt);
        }
    }

    private final EndpointId self;
    private final String selfLabel;
    private final String serviceName;
    private final boolean advertise;
    private final Sockets v4;
    private final Sockets v6;
    private final BlockingQueue<Input> inputs = new LinkedBlockingQueue<>();
    // The swarm as swarm-discovery sees it, keyed by instance label and including this endpoint.
    private final Map<String, Peer> swarm = new TreeMap<>();
    private final Map<EndpointId, EndpointAddr> discovered = new ConcurrentHashMap<>();
    private final Map<EndpointId, Set<CompletableFuture<EndpointAddr>>> waiters = new ConcurrentHashMap<>();
    private final List<Consumer<Event>> listeners = new CopyOnWriteArrayList<>();
    private final Thread actor;
    private final List<Thread> receivers = new ArrayList<>();
    private volatile byte[] response;
    private volatile boolean closed;

    private MdnsAddressLookup(EndpointId self, String serviceName, boolean advertise, Sockets v4, Sockets v6) {
        this.self = self;
        this.selfLabel = base32(self.toBytes());
        this.serviceName = "_" + serviceName + "._udp.local";
        this.advertise = advertise;
        this.v4 = v4;
        this.v6 = v6;
        this.actor = new Thread(this::run, "iroh-mdns-" + self.toHex().substring(0, 8));
        actor.setDaemon(true);
    }

    /** Starts looking up and, once {@link #publish} is called, advertising the given endpoint under {@code irohv1}. */
    public static MdnsAddressLookup start(EndpointId self) throws IOException {
        return start(self, SERVICE_NAME, true);
    }

    public static MdnsAddressLookup start(EndpointId self, String serviceName, boolean advertise) throws IOException {
        Sockets v4 = Sockets.open(StandardProtocolFamily.INET);
        Sockets v6 = Sockets.open(StandardProtocolFamily.INET6);
        if (v4 == null && v6 == null) {
            throw new IOException("cannot bind mDNS port " + PORT + " for IPv4 or IPv6");
        }
        MdnsAddressLookup mdns = new MdnsAddressLookup(self, serviceName, advertise, v4, v6);
        for (Sockets sockets : new Sockets[] {v4, v6}) {
            if (sockets != null) {
                Thread receiver = Thread.ofVirtual().name("iroh-mdns-receive").unstarted(() -> mdns.receive(sockets));
                mdns.receivers.add(receiver);
                receiver.start();
            }
        }
        mdns.actor.start();
        return mdns;
    }

    /** Advertises the given addresses and the first relay; an endpoint with no direct addresses is not advertised. */
    public void publish(EndpointAddr addr) {
        if (!advertise) {
            return;
        }
        if (!addr.id().equals(self)) {
            throw new IllegalArgumentException("not this endpoint's address");
        }
        Map<String, String> txt = new TreeMap<>();
        if (!addr.relayUrls().isEmpty()) {
            String relay = addr.relayUrls().getFirst().toString();
            // As iroh: a relay URL too long for a TXT attribute is dropped.
            if (RELAY_ATTRIBUTE.length() + 1 + relay.length() <= MAX_TXT_ATTRIBUTE + 1) {
                txt.put(RELAY_ATTRIBUTE, relay);
            }
        }
        response = addr.directAddresses().isEmpty()? null: encodeResponse(sorted(addr.directAddresses()), txt);
    }

    /** The endpoint's addresses if it is currently known on the local network. */
    public Optional<EndpointAddr> discovered(EndpointId id) {
        return Optional.ofNullable(discovered.get(id));
    }

    /** All endpoints currently known on the local network. */
    public Map<EndpointId, EndpointAddr> discovered() {
        return Map.copyOf(discovered);
    }

    /** The endpoint's addresses, waiting up to the timeout for it to be discovered. */
    public Optional<EndpointAddr> resolve(EndpointId id, Duration timeout) {
        CompletableFuture<EndpointAddr> found = new CompletableFuture<>();
        waiters.computeIfAbsent(id, k -> ConcurrentHashMap.newKeySet()).add(found);
        try {
            EndpointAddr known = discovered.get(id);
            if (known != null) {
                return Optional.of(known);
            }
            return Optional.of(found.get(timeout.toMillis(), TimeUnit.MILLISECONDS));
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
        catch (ExecutionException | TimeoutException e) {
            return Optional.empty();
        }
        finally {
            waiters.computeIfPresent(id, (k, set) -> {
                set.remove(found);
                return set.isEmpty()? null: set;
            });
        }
    }

    /** Calls the listener, on the discovery thread, for every endpoint discovered, changed or expired. */
    public void addListener(Consumer<Event> listener) {
        listeners.add(listener);
    }

    public void removeListener(Consumer<Event> listener) {
        listeners.remove(listener);
    }

    @Override
    public void close() {
        closed = true;
        actor.interrupt();
        receivers.forEach(Thread::interrupt);
        if (v4 != null) {
            v4.close();
        }
        if (v6 != null) {
            v6.close();
        }
    }

    /** swarm-discovery's sender: alternate between waiting to query and waiting to respond. */
    private void run() {
        long tau = CADENCE.toNanos();
        int cutoff = (int) Math.ceil(CADENCE.toMillis() / 1000.0 * RESPONSE_RATE);
        long gcInterval = tau * 12345 / 9999;
        long nextGc = System.nanoTime() + gcInterval;
        long extraDelay = 0;
        boolean hasResponded = false;
        byte[] query = MdnsMessage.query(serviceName);
        try {
            while (!closed) {
                // Query mode: send a query when the timeout fires first, or respond to another endpoint's query.
                long deadline = System.nanoTime() + tau + random(tau * swarmSize() / 10);
                Family mode = null;
                while (mode == null) {
                    Input input = poll(Math.min(deadline, nextGc));
                    nextGc = maybeCollect(nextGc, gcInterval);
                    switch (input) {
                        case QueryReceived q -> mode = q.family;
                        case ResponseReceived r -> update(r.peers);
                        case null -> {
                            if (System.nanoTime() - deadline >= 0) {
                                send(query, Family.ANY);
                                mode = Family.ANY;
                            }
                        }
                    }
                }

                // Respond mode: respond unless enough other endpoints respond first. If this endpoint responded last
                // time and the swarm is large, it waits longer, for fairness.
                int size = swarmSize();
                extraDelay = hasResponded
                        ? RESPONSE_DELAY_NANOS * Math.min(10, size / cutoff)
                        : Math.max(0, extraDelay - RESPONSE_DELAY_NANOS);
                deadline = System.nanoTime() + random(RESPONSE_DELAY_NANOS * size / cutoff) + extraDelay;
                hasResponded = false;
                int responses = 0;
                while (true) {
                    Input input = poll(Math.min(deadline, nextGc));
                    nextGc = maybeCollect(nextGc, gcInterval);
                    if (input instanceof ResponseReceived r) {
                        responses += r.peers.size();
                        update(r.peers);
                        if (responses >= cutoff) {
                            break;
                        }
                    }
                    else if (input == null && System.nanoTime() - deadline >= 0) {
                        byte[] current = response;
                        if (current != null) {
                            send(current, mode);
                            hasResponded = true;
                        }
                        break;
                    }
                }
            }
        }
        catch (InterruptedException e) {
            // closed
        }
    }

    private Input poll(long deadline) throws InterruptedException {
        long wait = deadline - System.nanoTime();
        return wait <= 0? inputs.poll(): inputs.poll(wait, TimeUnit.NANOSECONDS);
    }

    private int swarmSize() {
        return swarm.isEmpty()? 1: swarm.size();
    }

    private static long random(long bound) {
        return bound <= 0? 0: ThreadLocalRandom.current().nextLong(bound);
    }

    private long maybeCollect(long nextGc, long gcInterval) {
        long now = System.nanoTime();
        if (now - nextGc < 0) {
            return nextGc;
        }
        if (!swarm.isEmpty()) {
            float tau = CADENCE.toMillis() / 1000f;
            // Each cadence brings min(swarm size, ceil(τφ)) responses; allow three per-endpoint intervals of jitter.
            float expectedFrequency = Math.min((float) Math.ceil(tau * RESPONSE_RATE), swarm.size()) / tau;
            float perPeer = expectedFrequency / swarm.size();
            long grace = (long) (3.0 / perPeer * 1e9);
            var it = swarm.entrySet().iterator();
            while (it.hasNext()) {
                var entry = it.next();
                if (now - entry.getValue().lastSeen >= grace) {
                    it.remove();
                    expired(entry.getKey());
                }
            }
        }
        return now + gcInterval;
    }

    private void update(Map<String, Peer> peers) {
        for (var entry : peers.entrySet()) {
            Peer previous = swarm.put(entry.getKey(), entry.getValue());
            if (entry.getValue().sameAs(previous)) {
                continue;
            }
            EndpointId id = parseId(entry.getKey());
            if (id == null || id.equals(self)) {
                continue;
            }
            EndpointAddr addr = toAddr(id, entry.getValue());
            discovered.put(id, addr);
            LOG.fine("mDNS discovered " + addr);
            Set<CompletableFuture<EndpointAddr>> waiting = waiters.get(id);
            if (waiting != null) {
                waiting.forEach(f -> f.complete(addr));
            }
            notifyListeners(new Event.Discovered(addr));
        }
    }

    private void expired(String label) {
        EndpointId id = parseId(label);
        if (id == null || id.equals(self)) {
            return;
        }
        discovered.remove(id);
        LOG.fine("mDNS expired " + id);
        notifyListeners(new Event.Expired(id));
    }

    private void notifyListeners(Event event) {
        for (Consumer<Event> listener : listeners) {
            try {
                listener.accept(event);
            }
            catch (RuntimeException e) {
                LOG.log(Level.WARNING, "mDNS listener failed", e);
            }
        }
    }

    private static EndpointAddr toAddr(EndpointId id, Peer peer) {
        List<URI> relays = new ArrayList<>();
        String relay = peer.txt.get(RELAY_ATTRIBUTE);
        if (relay != null) {
            try {
                URI url = new URI(relay);
                if (url.getScheme() != null && url.getHost() != null) {
                    relays.add(url);
                }
            }
            catch (java.net.URISyntaxException e) {
                LOG.fine("bad relay url in mDNS TXT: " + relay);
            }
        }
        return new EndpointAddr(id, relays, peer.addrs);
    }

    private void receive(Sockets sockets) {
        ByteBuffer buffer = ByteBuffer.allocate(9000);
        while (!closed) {
            try {
                buffer.clear();
                InetSocketAddress source = (InetSocketAddress) sockets.channel.receive(buffer);
                // A dual-stack IPv6 socket can also see IPv4 multicast; the IPv4 socket handles that.
                if (sockets.family == StandardProtocolFamily.INET6 && source.getAddress() instanceof Inet4Address) {
                    continue;
                }
                Input input = handle(Arrays.copyOf(buffer.array(), buffer.position()),
                        sockets.family == StandardProtocolFamily.INET? Family.V4: Family.V6);
                if (input != null) {
                    inputs.add(input);
                }
            }
            catch (ClosedChannelException e) {
                return;
            }
            catch (IOException e) {
                if (!closed) {
                    LOG.log(Level.FINE, "mDNS receive failed", e);
                }
            }
        }
    }

    /** swarm-discovery's receiver: a query for the service, or the endpoints in a response (possibly none). */
    private Input handle(byte[] packet, Family family) {
        MdnsMessage.Message message;
        try {
            message = MdnsMessage.decode(packet);
        }
        catch (RuntimeException e) {
            LOG.finest("bad mDNS packet: " + e);
            return null;
        }
        for (MdnsMessage.Question q : message.questions()) {
            if ((q.dnsClass() & 0x7fff) == MdnsMessage.CLASS_IN && q.type() == MdnsMessage.TYPE_PTR
                    && q.name().equalsIgnoreCase(serviceName)) {
                return new QueryReceived(family);
            }
        }
        return new ResponseReceived(parsePeers(message, serviceName, System.nanoTime()));
    }

    private static Map<String, Peer> parsePeers(MdnsMessage.Message message, String serviceName, long now) {
        // SRV target name -> (port, instance)
        Map<String, List<Map.Entry<Integer, String>>> targets = new TreeMap<>();
        Map<String, Map<String, String>> txts = new TreeMap<>();
        for (MdnsMessage.Record record : message.answers()) {
            if ((record.dnsClass() & 0x7fff) != MdnsMessage.CLASS_IN) {
                continue;
            }
            int dot = record.name().indexOf('.');
            if (dot <= 0 || !record.name().substring(dot + 1).equalsIgnoreCase(serviceName)) {
                continue;
            }
            String instance = record.name().substring(0, dot);
            switch (record.data()) {
                case MdnsMessage.Srv srv -> targets.computeIfAbsent(srv.target().toLowerCase(), k -> new ArrayList<>())
                        .add(Map.entry(srv.port(), instance));
                case MdnsMessage.Txt txt -> {
                    Map<String, String> attributes = txts.computeIfAbsent(instance, k -> new TreeMap<>());
                    for (String s : txt.strings()) {
                        if (s.isEmpty()) {
                            continue;
                        }
                        int eq = s.indexOf('=');
                        // A key without a value is a flag; it is kept as an empty value.
                        attributes.putIfAbsent(eq < 0? s: s.substring(0, eq), eq < 0? "": s.substring(eq + 1));
                    }
                }
                default -> { }
            }
        }
        Map<String, List<InetSocketAddress>> addrs = new TreeMap<>();
        for (MdnsMessage.Record record : message.additionals()) {
            if ((record.dnsClass() & 0x7fff) != MdnsMessage.CLASS_IN
                    || !(record.data() instanceof MdnsMessage.Address address)) {
                continue;
            }
            int dot = record.name().indexOf('.');
            if (dot <= 0 || !record.name().substring(dot + 1).equalsIgnoreCase("local")) {
                continue;
            }
            for (var target : targets.getOrDefault(record.name().toLowerCase(), List.of())) {
                addrs.computeIfAbsent(target.getValue(), k -> new ArrayList<>())
                        .add(new InetSocketAddress(address.address(), target.getKey()));
            }
        }
        Map<String, Peer> peers = new TreeMap<>();
        addrs.forEach((instance, list) -> peers.put(instance,
                new Peer(sorted(list), Map.copyOf(txts.getOrDefault(instance, Map.of())), now)));
        return peers;
    }

    private byte[] encodeResponse(List<InetSocketAddress> addrs, Map<String, String> txt) {
        String instance = selfLabel + "." + serviceName;
        List<MdnsMessage.Record> answers = new ArrayList<>();
        List<MdnsMessage.Record> additionals = new ArrayList<>();
        Map<Integer, List<InetAddress>> byPort = new TreeMap<>();
        for (InetSocketAddress addr : addrs) {
            byPort.computeIfAbsent(addr.getPort(), k -> new ArrayList<>()).add(addr.getAddress());
        }
        // swarm-discovery's records have TTL 0: liveness comes from the steady flow of responses.
        byPort.forEach((port, ips) -> {
            String target = selfLabel + "-" + port + ".local";
            answers.add(new MdnsMessage.Record(instance, MdnsMessage.CLASS_IN, 0, new MdnsMessage.Srv(port, target)));
            for (InetAddress ip : ips) {
                additionals.add(new MdnsMessage.Record(target, MdnsMessage.CLASS_IN, 0, new MdnsMessage.Address(withoutScope(ip))));
            }
        });
        if (!txt.isEmpty()) {
            List<String> strings = new ArrayList<>();
            txt.forEach((k, v) -> strings.add(k + "=" + v));
            answers.add(new MdnsMessage.Record(instance, MdnsMessage.CLASS_IN, 0, new MdnsMessage.Txt(strings)));
        }
        return MdnsMessage.response(answers, additionals);
    }

    private void send(byte[] packet, Family family) {
        Sockets sockets = switch (family) {
            case V4 -> v4;
            case V6 -> v6;
            case ANY -> v4 != null? v4: v6;
        };
        if (sockets != null) {
            sockets.send(packet);
        }
    }

    /** Rust's IpAddr then port order: IPv4 before IPv6, then by bytes. */
    private static List<InetSocketAddress> sorted(List<InetSocketAddress> addrs) {
        List<InetSocketAddress> copy = new ArrayList<>(new java.util.LinkedHashSet<>(addrs));
        copy.sort(Comparator.<InetSocketAddress>comparingInt(a -> a.getAddress().getAddress().length)
                .thenComparing(a -> a.getAddress().getAddress(), Arrays::compareUnsigned)
                .thenComparingInt(InetSocketAddress::getPort));
        return List.copyOf(copy);
    }

    private static InetAddress withoutScope(InetAddress ip) {
        try {
            return ip instanceof Inet6Address? InetAddress.getByAddress(ip.getAddress()): ip;
        }
        catch (java.net.UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final String BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

    /** RFC 4648 base32, lowercase without padding: how iroh names an endpoint in mDNS. */
    static String base32(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte b : bytes) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                out.append(BASE32.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(BASE32.charAt((buffer << (5 - bits)) & 31));
        }
        return out.toString();
    }

    /** An endpoint id in base32 or hex, as iroh's PublicKey::from_str accepts; null if neither. */
    static EndpointId parseId(String label) {
        try {
            if (label.length() == 64) {
                return EndpointId.fromHex(label);
            }
            if (label.length() != 52) {
                return null;
            }
            byte[] out = new byte[32];
            int buffer = 0, bits = 0, n = 0;
            for (char c : label.toLowerCase().toCharArray()) {
                int v = BASE32.indexOf(c);
                if (v < 0) {
                    return null;
                }
                buffer = (buffer << 5) | v;
                bits += 5;
                if (bits >= 8) {
                    out[n++] = (byte) (buffer >> (bits - 8));
                    bits -= 8;
                }
            }
            return EndpointId.fromBytes(out);
        }
        catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static InetAddress literal(String ip) {
        try {
            return InetAddress.getByName(ip);
        }
        catch (java.net.UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The mDNS socket of one IP family, bound to port 5353 beside any other mDNS responder, in the group on every
     * multicast interface. Packets are sent out of each of those interfaces, so endpoints on any of the host's networks
     * are found.
     */
    private static final class Sockets {
        final ProtocolFamily family;
        final DatagramChannel channel;
        final InetSocketAddress group;
        final List<NetworkInterface> interfaces;

        private Sockets(ProtocolFamily family, DatagramChannel channel, InetSocketAddress group, List<NetworkInterface> interfaces) {
            this.family = family;
            this.channel = channel;
            this.group = group;
            this.interfaces = interfaces;
        }

        static Sockets open(ProtocolFamily family) {
            boolean v4 = family == StandardProtocolFamily.INET;
            InetSocketAddress group = v4? GROUP_V4: GROUP_V6;
            DatagramChannel channel = null;
            try {
                channel = DatagramChannel.open(family);
                channel.setOption(StandardSocketOptions.SO_REUSEADDR, true);
                if (channel.supportedOptions().contains(StandardSocketOptions.SO_REUSEPORT)) {
                    channel.setOption(StandardSocketOptions.SO_REUSEPORT, true);
                }
                channel.bind(new InetSocketAddress(v4? literal("0.0.0.0"): literal("::"), PORT));
                channel.setOption(StandardSocketOptions.IP_MULTICAST_LOOP, true);
                if (v4) {
                    channel.setOption(StandardSocketOptions.IP_MULTICAST_TTL, 16);
                }
                List<NetworkInterface> joined = new ArrayList<>();
                for (NetworkInterface nif : candidates(v4)) {
                    try {
                        channel.join(group.getAddress(), nif);
                        joined.add(nif);
                    }
                    catch (IOException | UnsupportedOperationException e) {
                        LOG.fine("cannot join mDNS group on " + nif.getName() + ": " + e.getMessage());
                    }
                }
                if (joined.isEmpty()) {
                    throw new IOException("no interface joined the mDNS group");
                }
                return new Sockets(family, channel, group, List.copyOf(joined));
            }
            catch (IOException | UnsupportedOperationException e) {
                LOG.fine("no mDNS for " + family + ": " + e.getMessage());
                if (channel != null) {
                    try {
                        channel.close();
                    }
                    catch (IOException ignored) {
                    }
                }
                return null;
            }
        }

        /** Up multicast interfaces with an address of the family; loopback only when there is nothing else. */
        private static List<NetworkInterface> candidates(boolean v4) throws SocketException {
            List<NetworkInterface> found = new ArrayList<>();
            List<NetworkInterface> loopback = new ArrayList<>();
            for (NetworkInterface nif : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!nif.isUp() || nif.isVirtual()) {
                    continue;
                }
                boolean hasFamily = Collections.list(nif.getInetAddresses()).stream()
                        .anyMatch(a -> v4? a instanceof Inet4Address: a instanceof Inet6Address);
                if (!hasFamily) {
                    continue;
                }
                if (nif.isLoopback()) {
                    loopback.add(nif);
                }
                else if (nif.supportsMulticast()) {
                    found.add(nif);
                }
            }
            return found.isEmpty()? loopback: found;
        }

        void send(byte[] packet) {
            for (NetworkInterface nif : interfaces) {
                try {
                    channel.setOption(StandardSocketOptions.IP_MULTICAST_IF, nif);
                    channel.send(ByteBuffer.wrap(packet), group);
                }
                catch (IOException e) {
                    LOG.fine("mDNS send on " + nif.getName() + " failed: " + e.getMessage());
                }
            }
        }

        void close() {
            try {
                channel.close();
            }
            catch (IOException ignored) {
            }
        }
    }
}
