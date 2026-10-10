package org.peergos.iroh;

import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.path.PathManager;

import tech.kwik.core.QuicStream;
import tech.kwik.core.send.QuicPath;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

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

    @Test
    void secondPathBesideTheRelayShouldCarryTheData() throws Exception {
        FakeRelay relay = new FakeRelay();
        relay.delayMillis = 20;
        SecretKey keyA = SecretKey.generate();
        SecretKey keyB = SecretKey.generate();
        FakeRelay.Client relayA = relay.client(keyA.endpointId());
        FakeRelay.Client relayB = relay.client(keyB.endpointId());
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint a = Endpoint.builder(keyA).bind(LOCALHOST).publish(false).relayQuicPort(null).maxPathId(2)
                     .transport(relayA).build();
             Endpoint b = Endpoint.builder(keyB).bind(LOCALHOST).publish(false).relayQuicPort(null).maxPathId(2)
                     .transport(relayB).protocol(EchoProtocol.ALPN, echo).build()) {
            QuicClientConnection connection = a.connect(b.id(), relayA.addressFor(b.id()), EchoProtocol.ALPN);
            assertEquals("over the relay", EchoProtocol.echo(connection, "over the relay"));

            QuicConnectionImpl impl = (QuicConnectionImpl) connection;
            awaitConnectionIds(impl.getPathManager(), 1);
            CompletableFuture<QuicPath> active = new CompletableFuture<>();
            impl.setPathListener(active::complete);
            QuicPath direct = impl.openPath(b.localAddress()).orElseThrow();
            assertEquals(1, direct.getId());
            assertEquals(1, active.get(5, TimeUnit.SECONDS).getId());

            int relayedBefore = relay.forwarded.get();
            byte[] payload = new byte[2_000_000];
            Arrays.fill(payload, (byte) 7);
            assertTrue(Arrays.equals(payload, echoBytes(connection, payload)));
            int relayed = relay.forwarded.get() - relayedBefore;
            // 2 MB each way is about 3000 packets. The direct path has the lower RTT, so it carries them once each side
            // has an RTT sample for it; the relay carries the acks of the initial path and what went before.
            assertTrue(relayed < 600, "relayed " + relayed);
            connection.close();
        }
    }

    @Test
    void connectionShouldSurviveLosingTheRelayPath() throws Exception {
        FakeRelay relay = new FakeRelay();
        SecretKey keyA = SecretKey.generate();
        SecretKey keyB = SecretKey.generate();
        FakeRelay.Client relayA = relay.client(keyA.endpointId());
        FakeRelay.Client relayB = relay.client(keyB.endpointId());
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint a = Endpoint.builder(keyA).bind(LOCALHOST).publish(false).relayQuicPort(null)
                     .transport(relayA).build();
             Endpoint b = Endpoint.builder(keyB).bind(LOCALHOST).publish(false).relayQuicPort(null)
                     .transport(relayB).protocol(EchoProtocol.ALPN, echo).build()) {
            QuicClientConnection connection = a.connect(b.id(), relayA.addressFor(b.id()), EchoProtocol.ALPN);
            assertEquals("hello", EchoProtocol.echo(connection, "hello"));
            QuicConnectionImpl impl = (QuicConnectionImpl) connection;
            awaitConnectionIds(impl.getPathManager(), 1);

            // The transfer starts on the relay path alone; the direct path joins halfway, then the relay goes down.
            byte[] payload = new byte[4_000_000];
            Arrays.fill(payload, (byte) 3);
            int relayedBefore = relay.forwarded.get();
            CompletableFuture<byte[]> echoed = CompletableFuture.supplyAsync(() -> {
                try {
                    return echoBytes(connection, payload);
                }
                catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            long deadline = System.currentTimeMillis() + 10_000;
            while (relay.forwarded.get() - relayedBefore < 500 && !echoed.isDone() && System.currentTimeMillis() < deadline) {
                Thread.sleep(1);
            }
            assertTrue(relay.forwarded.get() - relayedBefore >= 500, "relay path carried the transfer");
            CompletableFuture<QuicPath> active = new CompletableFuture<>();
            impl.setPathListener(active::complete);
            impl.openPath(b.localAddress()).orElseThrow();
            active.get(5, TimeUnit.SECONDS);
            relay.down = true;
            assertTrue(Arrays.equals(payload, echoed.get(30, TimeUnit.SECONDS)));
            assertEquals("still here", EchoProtocol.echo(connection, "still here"));
            connection.close();
        }
    }

    @Test
    void initialPathCanBeAbandonedWhileAnotherRemains() throws Exception {
        FakeRelay relay = new FakeRelay();
        SecretKey keyA = SecretKey.generate();
        SecretKey keyB = SecretKey.generate();
        FakeRelay.Client relayA = relay.client(keyA.endpointId());
        FakeRelay.Client relayB = relay.client(keyB.endpointId());
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint a = Endpoint.builder(keyA).bind(LOCALHOST).publish(false).relayQuicPort(null).transport(relayA).build();
             Endpoint b = Endpoint.builder(keyB).bind(LOCALHOST).publish(false).relayQuicPort(null).transport(relayB)
                     .protocol(EchoProtocol.ALPN, echo).build()) {
            QuicClientConnection connection = a.connect(b.id(), relayA.addressFor(b.id()), EchoProtocol.ALPN);
            assertEquals("hello", EchoProtocol.echo(connection, "hello"));
            QuicConnectionImpl impl = (QuicConnectionImpl) connection;
            awaitConnectionIds(impl.getPathManager(), 1);
            CompletableFuture<QuicPath> active = new CompletableFuture<>();
            impl.setPathListener(active::complete);
            impl.openPath(b.localAddress()).orElseThrow();
            active.get(5, TimeUnit.SECONDS);

            impl.abandonPath(0, 0);
            assertEquals("after abandoning the relay path", EchoProtocol.echo(connection, "after abandoning the relay path"));
            Thread.sleep(200);
            int relayed = relay.forwarded.get();
            byte[] payload = new byte[500_000];
            assertTrue(Arrays.equals(payload, echoBytes(connection, payload)));
            assertEquals(relayed, relay.forwarded.get(), "nothing more over the relay");
            connection.close();
        }
    }

    @Test
    void pathThatIsNotValidatedShouldBeAbandoned() throws Exception {
        EchoProtocol echo = new EchoProtocol();
        try (Endpoint a = Endpoint.builder(SecretKey.generate()).bind(LOCALHOST).publish(false).relayQuicPort(null).build();
             Endpoint b = Endpoint.builder(SecretKey.generate()).bind(LOCALHOST).publish(false).relayQuicPort(null)
                     .protocol(EchoProtocol.ALPN, echo).build()) {
            QuicClientConnection connection = a.connect(b.id(), b.localAddress(), EchoProtocol.ALPN);
            assertEquals("hello", EchoProtocol.echo(connection, "hello"));
            QuicConnectionImpl impl = (QuicConnectionImpl) connection;
            awaitConnectionIds(impl.getPathManager(), 1);
            // TEST-NET-1 never answers.
            QuicPath dead = impl.openPath(new InetSocketAddress(InetAddress.getByName("192.0.2.1"), 4433)).orElseThrow();
            long deadline = System.currentTimeMillis() + 10_000;
            while (!impl.getPaths().isEmpty() && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            assertTrue(impl.getPaths().isEmpty(), impl.getPaths().toString());
            assertTrue(impl.getPathManager().isAbandoned(dead.getId()));
            assertEquals("still fine", EchoProtocol.echo(connection, "still fine"));
            // The next path gets a fresh path id.
            awaitConnectionIds(impl.getPathManager(), 2);
            connection.close();
        }
    }

    private static void awaitConnectionIds(PathManager paths, long pathId) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5000;
        while (!paths.hasConnectionIds(pathId) && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        assertTrue(paths.hasConnectionIds(pathId), "connection ids for path " + pathId);
    }

    private static byte[] echoBytes(QuicClientConnection connection, byte[] data) throws Exception {
        QuicStream stream = connection.createStream(true);
        CompletableFuture<byte[]> received = CompletableFuture.supplyAsync(() -> {
            try (InputStream in = stream.getInputStream()) {
                return in.readAllBytes();
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        try (OutputStream out = stream.getOutputStream()) {
            out.write(data);
        }
        return received.get(30, TimeUnit.SECONDS);
    }
}
