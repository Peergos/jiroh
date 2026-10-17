package org.peergos.iroh;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;

/** A {@link RelayServer} on a local port. */
final class JavaRelay implements TestRelay {

    private final SSLContext tls;
    private volatile RelayServer server;

    JavaRelay() throws IOException {
        this(null);
    }

    JavaRelay(SSLContext tls) throws IOException {
        this.tls = tls;
        this.server = start(0);
    }

    private RelayServer start(int port) throws IOException {
        RelayServer.Builder builder = RelayServer.builder().bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
        if (tls != null) {
            builder.tls(tls);
        }
        return builder.start();
    }

    RelayServer server() {
        return server;
    }

    @Override
    public URI url() {
        return server.url();
    }

    @Override
    public void restart(long downMillis) throws Exception {
        int port = server.address().getPort();
        server.close();
        Thread.sleep(downMillis);
        server = start(port);
    }

    @Override
    public void close() {
        server.close();
    }
}
