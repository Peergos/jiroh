package org.peergos.iroh;

import tech.kwik.core.impl.QuicConnectionImpl;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Drives iroh's QUIC NAT traversal on an endpoint's connections, as iroh's remote state does: every connection gets
 * the endpoint's direct addresses as candidates (a server advertises them, a client sends them in REACH_OUT), and a
 * client starts a round when connected, when the server's candidates change, and every few seconds until it has a
 * direct path. kwik opens a path to each candidate that answers.
 */
final class NatTraversal {

    private static final Logger LOG = Logger.getLogger(NatTraversal.class.getName());
    // iroh's MAX_QNT_ADDRESSES
    static final int MAX_ADDRESSES = 32;
    // iroh's HOLEPUNCH_ATTEMPTS_INTERVAL: a round is repeated with the same candidates only after this long.
    private static final Duration ATTEMPT_INTERVAL = Duration.ofSeconds(5);
    private static final Duration NO_ADDRESSES_RETRY = Duration.ofMillis(100);

    private final Supplier<List<InetSocketAddress>> candidates;
    private final ScheduledExecutorService scheduler;
    private final Set<QuicConnectionImpl> servers = ConcurrentHashMap.newKeySet();
    private final Set<Client> clients = ConcurrentHashMap.newKeySet();

    NatTraversal(Supplier<List<InetSocketAddress>> candidates, ScheduledExecutorService scheduler) {
        this.candidates = candidates;
        this.scheduler = scheduler;
    }

    void serverConnection(QuicConnectionImpl connection) {
        if (!connection.isNatTraversalEnabled()) {
            return;
        }
        servers.add(connection);
        connection.setConnectionListener(event -> servers.remove(connection));
        sync(connection);
    }

    void clientConnection(QuicConnectionImpl connection) {
        if (!connection.isNatTraversalEnabled()) {
            return;
        }
        Client client = new Client(connection);
        clients.add(client);
        connection.setNatTraversalListener(event -> client.trigger());
        client.trigger();
    }

    /** The endpoint's direct addresses changed, e.g. a public address was learned or mapped. */
    void candidatesChanged() {
        servers.forEach(this::sync);
        clients.forEach(Client::trigger);
    }

    private List<InetSocketAddress> directCandidates() {
        return candidates.get().stream().filter(a -> !MappedAddresses.isRelayMapped(a)).toList();
    }

    private Set<InetSocketAddress> sync(QuicConnectionImpl connection) {
        Set<InetSocketAddress> wanted = new HashSet<>();
        try {
            for (InetSocketAddress address : directCandidates()) {
                wanted.add(tech.kwik.core.path.NatTraversal.canonical(address));
            }
            for (InetSocketAddress current : connection.getLocalNatTraversalAddresses()) {
                if (!wanted.contains(current)) {
                    connection.removeNatTraversalAddress(current);
                }
            }
            for (InetSocketAddress address : wanted) {
                connection.addNatTraversalAddress(address);
            }
        }
        catch (tech.kwik.core.path.NatTraversal.TooManyAddressesException e) {
            LOG.fine("more NAT traversal candidates than the peer accepts");
        }
        catch (RuntimeException e) {
            LOG.log(Level.FINE, "NAT traversal candidates not updated", e);
        }
        return wanted;
    }

    private final class Client {
        private final QuicConnectionImpl connection;
        private Set<InetSocketAddress> lastCandidates = Set.of();
        private long lastRound;
        private boolean scheduled;

        Client(QuicConnectionImpl connection) {
            this.connection = connection;
        }

        void trigger() {
            scheduler.execute(this::attempt);
        }

        private synchronized void attempt() {
            if (!(connection instanceof tech.kwik.core.QuicClientConnection client && client.isConnected())) {
                clients.remove(this);
                return;
            }
            Set<InetSocketAddress> local = sync(connection);
            Set<InetSocketAddress> all = new HashSet<>(local);
            all.addAll(connection.getRemoteNatTraversalAddresses());
            long now = System.nanoTime();
            boolean changed = !all.equals(lastCandidates);
            boolean due = now - lastRound >= ATTEMPT_INTERVAL.toNanos();
            if (!hasDirectPath() && (changed || due)) {
                try {
                    List<InetSocketAddress> probed = connection.initiateNatTraversalRound();
                    lastCandidates = all;
                    lastRound = now;
                    LOG.fine("NAT traversal round: probing " + probed + ", reaching out from " + local);
                }
                catch (tech.kwik.core.path.NatTraversal.NotEnoughAddressesException e) {
                    scheduler.schedule(this::attempt, NO_ADDRESSES_RETRY.toMillis(), TimeUnit.MILLISECONDS);
                    return;
                }
                catch (IllegalStateException e) {
                    LOG.fine("no NAT traversal round: " + e.getMessage());
                }
            }
            if (!scheduled) {
                scheduled = true;
                scheduler.schedule(this::periodic, ATTEMPT_INTERVAL.toMillis(), TimeUnit.MILLISECONDS);
            }
        }

        private void periodic() {
            synchronized (this) {
                scheduled = false;
            }
            attempt();
        }

        private boolean hasDirectPath() {
            return connection.hasActivePath(address -> !MappedAddresses.isRelayMapped(address));
        }
    }
}
