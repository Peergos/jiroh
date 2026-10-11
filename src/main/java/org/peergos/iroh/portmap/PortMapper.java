package org.peergos.iroh.portmap;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Maps a local UDP port on the gateway, as iroh's portmapper does: with PCP, NAT-PMP or UPnP IGD, preferring them in
 * that order among those the gateway answers, renewing the mapping at half its lifetime and releasing it on close.
 * The external address is reported to the listener whenever it changes.
 */
public final class PortMapper implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(PortMapper.class.getName());
    private static final Duration PCP_TIMEOUT = Duration.ofMillis(500);
    private static final Duration NAT_PMP_TIMEOUT = Duration.ofMillis(500);
    private static final Duration UPNP_TIMEOUT = Duration.ofSeconds(1);
    // A protocol the gateway answered is trusted for this long without probing again.
    private static final Duration AVAILABILITY_TRUST = Duration.ofMinutes(10);
    // A protocol the gateway did not answer is tried again after this long.
    private static final Duration UNAVAILABILITY_TRUST = Duration.ofSeconds(5);

    /** Where to find the gateway's port mapping services; {@link #system()} for the default route's gateway. */
    public record Gateway(Inet4Address gateway, Inet4Address local, int pcpPort, InetSocketAddress ssdp) {}

    public record Probe(boolean pcp, boolean natPmp, boolean upnp) {}

    private final int localPort;
    private final Supplier<Optional<Gateway>> gateways;
    private final Consumer<Optional<InetSocketAddress>> listener;
    private final ScheduledExecutorService executor;
    private Mapping mapping;
    private Gateway mappingGateway;
    private ScheduledFuture<?> renewal;
    private long pcpSeen, natPmpSeen, upnpSeen, lastProbe;
    private Upnp.Gateway upnpGateway;
    private boolean closed;

    public PortMapper(int localPort, Consumer<Optional<InetSocketAddress>> listener) {
        this(localPort, PortMapper::system, listener);
    }

    public PortMapper(int localPort, Supplier<Optional<Gateway>> gateways, Consumer<Optional<InetSocketAddress>> listener) {
        this.localPort = localPort;
        this.gateways = gateways;
        this.listener = listener;
        this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "portmapper");
            t.setDaemon(true);
            return t;
        });
    }

    public static Optional<Gateway> system() {
        return DefaultGateway.find().map(g -> new Gateway(g.gateway(), g.local(), Pcp.SERVER_PORT, Upnp.SSDP));
    }

    /** Tries to get a mapping, unless there is one; asynchronous, like iroh's procure_mapping. */
    public void procure() {
        executor.execute(this::procureNow);
    }

    public synchronized Optional<InetSocketAddress> external() {
        return Optional.ofNullable(mapping).map(Mapping::external);
    }

    /** Which protocols the gateway answers. */
    public Probe probe() {
        try {
            return executor.submit(() -> {
                Optional<Gateway> gateway = gateways.get();
                if (gateway.isEmpty()) {
                    return new Probe(false, false, false);
                }
                probeNow(gateway.get());
                return available();
            }).get();
        }
        catch (Exception e) {
            return new Probe(false, false, false);
        }
    }

    private Probe available() {
        long now = System.nanoTime();
        return new Probe(fresh(pcpSeen, now), fresh(natPmpSeen, now), fresh(upnpSeen, now) && upnpGateway != null);
    }

    private static boolean fresh(long seen, long now) {
        return seen != 0 && now - seen < AVAILABILITY_TRUST.toNanos();
    }

    private void probeNow(Gateway gateway) {
        long now = System.nanoTime();
        lastProbe = now;
        Probe known = available();
        if (!known.pcp() && Pcp.probe(gateway.local(), gateway.gateway(), gateway.pcpPort(), PCP_TIMEOUT)) {
            pcpSeen = now;
        }
        if (!known.natPmp() && NatPmp.probe(gateway.local(), gateway.gateway(), gateway.pcpPort(), NAT_PMP_TIMEOUT)) {
            natPmpSeen = now;
        }
        if (!known.upnp()) {
            try {
                upnpGateway = Upnp.search(gateway.local(), gateway.ssdp(), UPNP_TIMEOUT);
                upnpSeen = now;
            }
            catch (IOException e) {
                LOG.fine("no UPnP gateway: " + e.getMessage());
            }
        }
        LOG.fine("port mapping " + available());
    }

    private void procureNow() {
        synchronized (this) {
            if (closed || mapping != null) {
                return;
            }
        }
        Optional<Gateway> gateway = gateways.get();
        if (gateway.isEmpty()) {
            LOG.fine("no gateway for port mapping");
            return;
        }
        obtain(gateway.get(), null);
    }

    /** Gets a mapping from the best available protocol, trying for the given external address first when renewing. */
    private void obtain(Gateway gateway, InetSocketAddress preferred) {
        Probe available = available();
        boolean recentlyProbed = System.nanoTime() - lastProbe < UNAVAILABILITY_TRUST.toNanos();
        if (!recentlyProbed && !(available.pcp() || available.natPmp() || available.upnp())) {
            probeNow(gateway);
            available = available();
        }
        Mapping result = null;
        try {
            if (available.pcp()) {
                result = Pcp.map(gateway.local(), localPort, gateway.gateway(), gateway.pcpPort(), preferred, PCP_TIMEOUT);
            }
            else if (available.natPmp()) {
                result = NatPmp.map(gateway.local(), localPort, gateway.gateway(), gateway.pcpPort(), preferred, NAT_PMP_TIMEOUT);
            }
            else if (available.upnp()) {
                result = Upnp.map(gateway.local(), localPort, upnpGateway, preferred == null? null: preferred.getPort(), UPNP_TIMEOUT);
            }
        }
        catch (IOException | RuntimeException e) {
            LOG.log(Level.FINE, "port mapping failed", e);
        }
        update(gateway, result);
    }

    private void update(Gateway gateway, Mapping result) {
        Optional<InetSocketAddress> before, after;
        synchronized (this) {
            if (closed) {
                release(result);
                return;
            }
            before = Optional.ofNullable(mapping).map(Mapping::external);
            mapping = result;
            mappingGateway = gateway;
            if (renewal != null) {
                renewal.cancel(false);
                renewal = null;
            }
            if (result != null) {
                long half = Math.max(1, result.lifetime().toSeconds() / 2);
                InetSocketAddress external = result.external();
                renewal = executor.schedule(() -> renew(external), half, TimeUnit.SECONDS);
                LOG.info("port mapped with " + result.protocol() + ": " + external + " -> local port " + localPort);
            }
            after = Optional.ofNullable(mapping).map(Mapping::external);
        }
        if (!before.equals(after)) {
            listener.accept(after);
        }
    }

    private void renew(InetSocketAddress external) {
        Gateway gateway;
        synchronized (this) {
            gateway = mappingGateway;
            if (closed || gateway == null) {
                return;
            }
        }
        obtain(gateway, external);
    }

    private static void release(Mapping mapping) {
        if (mapping == null) {
            return;
        }
        try {
            mapping.release().release();
        }
        catch (IOException e) {
            LOG.fine("releasing port mapping failed: " + e.getMessage());
        }
    }

    @Override
    public void close() {
        Mapping current;
        synchronized (this) {
            closed = true;
            current = mapping;
            mapping = null;
            if (renewal != null) {
                renewal.cancel(false);
            }
        }
        executor.execute(() -> release(current));
        executor.shutdown();
        try {
            executor.awaitTermination(2, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
