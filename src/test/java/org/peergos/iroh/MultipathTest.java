package org.peergos.iroh;

import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.path.PathManager;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MultipathTest {

    private static final InetSocketAddress LOCALHOST = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

    @Test
    void connectionIdsShouldBeIssuedForEachAllowedPath() throws Exception {
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint a = Endpoint.builder(SecretKey.generate()).bind(LOCALHOST).publish(false).relayQuicPort(null).maxPathId(3).build();
             Endpoint b = Endpoint.builder(SecretKey.generate()).bind(LOCALHOST).publish(false).relayQuicPort(null).maxPathId(2)
                     .protocol(EchoProtocol.ALPN, echo).build()) {
            QuicClientConnection connection = a.connect(b.id(), b.localAddress(), EchoProtocol.ALPN);
            assertEquals("hello", EchoProtocol.echo(connection, "hello"));

            PathManager paths = ((QuicConnectionImpl) connection).getPathManager();
            long deadline = System.currentTimeMillis() + 5000;
            while (!(paths.hasConnectionIds(1) && paths.hasConnectionIds(2)) && System.currentTimeMillis() < deadline) {
                Thread.sleep(20);
            }
            assertTrue(paths.hasConnectionIds(1), "path 1");
            assertTrue(paths.hasConnectionIds(2), "path 2");
            // Both sides allow path IDs up to the smaller of the two maximums.
            assertTrue(!paths.hasConnectionIds(3), "path 3");
            assertEquals("still works", EchoProtocol.echo(connection, "still works"));
            connection.close();
        }
    }
}
