package org.peergos.iroh;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

/**
 * The relay server's counters, named and described as iroh-relay's (iroh-relay/src/server/metrics.rs), so the
 * same dashboards work. {@link #render()} gives the OpenMetrics text iroh-relay serves on /metrics.
 */
public final class RelayMetrics {

    public final LongAdder bytesSent = new LongAdder();
    public final LongAdder bytesRecv = new LongAdder();
    public final LongAdder sendPacketsSent = new LongAdder();
    public final LongAdder sendPacketsRecv = new LongAdder();
    public final LongAdder sendPacketsDropped = new LongAdder();
    public final LongAdder otherPacketsSent = new LongAdder();
    public final LongAdder otherPacketsRecv = new LongAdder();
    public final LongAdder otherPacketsDropped = new LongAdder();
    public final LongAdder gotPing = new LongAdder();
    public final LongAdder sentPong = new LongAdder();
    public final LongAdder unknownFrames = new LongAdder();
    public final LongAdder bytesRxRatelimited = new LongAdder();
    public final LongAdder connsRxRatelimited = new LongAdder();
    public final LongAdder accepts = new LongAdder();
    public final LongAdder disconnects = new LongAdder();
    public final LongAdder uniqueClientKeys = new LongAdder();
    public final LongAdder clientsInactiveAdded = new LongAdder();
    public final LongAdder clientsInactiveRemoved = new LongAdder();
    public final LongAdder qadIncoming = new LongAdder();
    public final LongAdder qadIncomingError = new LongAdder();
    public final LongAdder qadConnections = new LongAdder();
    public final LongAdder qadConnectionsClosed = new LongAdder();
    public final LongAdder qadConnectionsErrored = new LongAdder();
    public final LongAdder httpConnections = new LongAdder();
    public final LongAdder httpConnectionsClosed = new LongAdder();
    public final LongAdder httpConnectionsErrored = new LongAdder();

    private final Map<String, Metric> metrics = new LinkedHashMap<>();
    private volatile LocalDate day = LocalDate.now(ZoneOffset.UTC);
    private volatile Set<EndpointId> keysToday = ConcurrentHashMap.newKeySet();

    private record Metric(String help, LongAdder value) {}

    public RelayMetrics() {
        add("bytes_sent", "Number of bytes sent.", bytesSent);
        add("bytes_recv", "Number of bytes received.", bytesRecv);
        add("send_packets_sent", "Number of 'send' packets relayed.", sendPacketsSent);
        add("send_packets_recv", "Number of 'send' packets received.", sendPacketsRecv);
        add("send_packets_dropped", "Number of 'send' packets dropped.", sendPacketsDropped);
        add("other_packets_sent", "Number of packets sent that were not 'send' packets.", otherPacketsSent);
        add("other_packets_recv", "Number of packets received that were not 'send' packets.", otherPacketsRecv);
        add("other_packets_dropped", "Number of times, non-send packet was dropped.", otherPacketsDropped);
        add("got_ping", "Number of times the server has received a Ping from a client.", gotPing);
        add("sent_pong", "Number of times the server has sent a Pong to a client.", sentPong);
        add("unknown_frames", "Number of unknown frames sent to this server.", unknownFrames);
        add("bytes_rx_ratelimited_total", "Number of bytes received from client connection which have been rate-limited.", bytesRxRatelimited);
        add("conns_rx_ratelimited_total", "Number of client connections which have had any frames rate-limited.", connsRxRatelimited);
        add("accepts", "Number of times this server has accepted a connection.", accepts);
        add("disconnects", "Number of clients that have then disconnected.", disconnects);
        add("unique_client_keys", "Number of unique client keys per day.", uniqueClientKeys);
        add("clients_inactive_added", "Number of times a client was moved into the inactive state.", clientsInactiveAdded);
        add("clients_inactive_removed", "Number of times a client was removed from the inactive state.", clientsInactiveRemoved);
        add("qad_incoming", "Number of incoming QAD connections.", qadIncoming);
        add("qad_incoming_error", "Number of QAD QUIC connections that aborted before completing the handshake.", qadIncomingError);
        add("qad_connections", "Number of accepted QAD QUIC connections.", qadConnections);
        add("qad_connections_closed", "Number of QAD QUIC connections that disconnected after being accepted.", qadConnectionsClosed);
        add("qad_connections_errored", "Number of QAD QUIC connections that disconnected after being accepted, with an error.", qadConnectionsErrored);
        add("http_connections", "Number of accepted HTTP(S) connections.", httpConnections);
        add("http_connections_closed", "Number of terminated HTTP(S) connections.", httpConnectionsClosed);
        add("http_connections_errored", "Number of HTTP(S) connections that terminated with an error.", httpConnectionsErrored);
    }

    private void add(String name, String help, LongAdder value) {
        metrics.put(name, new Metric(help, value));
    }

    /** Counts the key once per UTC day. */
    void clientConnected(EndpointId key) {
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        if (!today.equals(day)) {
            synchronized (this) {
                if (!today.equals(day)) {
                    keysToday = ConcurrentHashMap.newKeySet();
                    day = today;
                }
            }
        }
        if (keysToday.add(key)) {
            uniqueClientKeys.increment();
        }
    }

    /** OpenMetrics text exposition, as iroh-metrics encodes it. */
    public String render() {
        StringBuilder out = new StringBuilder();
        metrics.forEach((name, metric) -> {
            String full = "relayserver_" + name;
            out.append("# HELP ").append(full).append(' ').append(metric.help()).append('\n');
            out.append("# TYPE ").append(full).append(" counter\n");
            out.append(full).append(name.endsWith("_total")? "": "_total").append(' ').append(metric.value().sum()).append('\n');
        });
        return out.append("# EOF\n").toString();
    }
}
