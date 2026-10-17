package org.peergos.iroh;

import tech.kwik.core.ConnectionListener;
import tech.kwik.core.ConnectionTerminatedEvent;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The relay's QUIC Address Discovery port (iroh-relay/src/quic.rs): clients connect with ALPN /iroh-qad/0 and the
 * relay reports the address it sees them at in an OBSERVED_ADDRESS frame. No streams are allowed. It uses the
 * relay's certificate and restarts when that changes.
 */
final class QadServer implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(QadServer.class.getName());
    private static final char[] PASSWORD = new char[0];
    private static final Duration IDLE_TIMEOUT = Duration.ofSeconds(35);

    private final InetSocketAddress bind;
    private final RelayCertificate certificate;
    private final RelayMetrics metrics;
    private ServerConnector connector;
    private DatagramSocket socket;
    private int port;
    private boolean closed;

    QadServer(InetSocketAddress bind, RelayCertificate certificate, RelayMetrics metrics) throws IOException {
        this.bind = bind;
        this.certificate = certificate;
        this.metrics = metrics;
        // The socket is bound now, so the port is known and taken even before there is a certificate.
        socket = new DatagramSocket(bind);
        port = socket.getLocalPort();
        certificate.onChange(this::restart);
        restart();
    }

    synchronized int port() {
        return port;
    }

    private synchronized void restart() {
        if (closed) {
            return;
        }
        try {
            Optional<KeyStore> keyStore = certificate.keyStore(PASSWORD);
            if (keyStore.isEmpty()) {
                return;
            }
            if (connector != null) {
                connector.close();
                socket = new DatagramSocket(new InetSocketAddress(bind.getAddress(), port));
            }
            ServerConnectionConfig config = ServerConnectionConfig.builder()
                    .maxIdleTimeoutInSeconds((int) IDLE_TIMEOUT.toSeconds())
                    .maxOpenPeerInitiatedBidirectionalStreams(0)
                    .maxOpenPeerInitiatedUnidirectionalStreams(0)
                    .build();
            connector = ServerConnector.builder()
                    .withSocket(socket)
                    // Clients close with an error code once they have their address.
                    .withLogger(new KwikLog(true))
                    .withKeyStore(keyStore.get(), RelayCertificate.alias(), PASSWORD, certificate.ecCurve().orElse(null))
                    .withConfiguration(config)
                    .build();
            connector.registerApplicationProtocol(QuicAddressDiscovery.ALPN, new Factory());
            connector.start();
            LOG.info("QUIC address discovery on " + bind.getAddress().getHostAddress() + ":" + port);
        }
        catch (Exception e) {
            LOG.log(Level.WARNING, "could not start QUIC address discovery", e);
        }
    }

    private final class Factory implements ApplicationProtocolConnectionFactory {
        @Override
        public ApplicationProtocolConnection createConnection(String protocol, QuicConnection connection) {
            metrics.qadIncoming.increment();
            metrics.qadConnections.increment();
            connection.setConnectionListener(new ConnectionListener() {
                @Override
                public void disconnected(ConnectionTerminatedEvent event) {
                    metrics.qadConnectionsClosed.increment();
                    if (event.hasError() && !event.closedByPeer()) {
                        metrics.qadConnectionsErrored.increment();
                    }
                }
            });
            return new ApplicationProtocolConnection() {};
        }

        @Override
        public boolean sendObservedAddressReports() {
            return true;
        }

        @Override
        public int maxConcurrentPeerInitiatedUnidirectionalStreams() {
            return 0;
        }

        @Override
        public int maxConcurrentPeerInitiatedBidirectionalStreams() {
            return 0;
        }
    }

    @Override
    public synchronized void close() {
        closed = true;
        if (connector != null) {
            connector.close();
        }
        socket.close();
    }
}
