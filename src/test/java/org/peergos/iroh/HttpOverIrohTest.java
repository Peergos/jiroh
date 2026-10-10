package org.peergos.iroh;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicClientConnection;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class HttpOverIrohTest {

    private static final InetSocketAddress LOCALHOST = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

    @Test
    void requestsShouldBeProxiedToLocalServerWithAuthenticatedSource() throws Exception {
        AtomicReference<String> source = new AtomicReference<>();
        AtomicReference<String> query = new AtomicReference<>();
        HttpServer local = HttpServer.create(LOCALHOST, 0);
        local.createContext("/api/", exchange -> {
            source.set(exchange.getRequestHeaders().getFirst("Source"));
            query.set(exchange.getRequestURI().getRawQuery());
            byte[] body = exchange.getRequestBody().readAllBytes();
            byte[] reply = ("got " + new String(body, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("X-Reply", "yes");
            exchange.sendResponseHeaders(201, reply.length);
            exchange.getResponseBody().write(reply);
            exchange.close();
        });
        local.start();
        URI target = URI.create("http://127.0.0.1:" + local.getAddress().getPort() + "/");
        SecretKey clientKey = SecretKey.generate();
        try (Endpoint server = Endpoint.bind(SecretKey.generate(), LOCALHOST,
                     Map.of(HttpOverIroh.ALPN, HttpOverIroh.proxyTo(target, EndpointId::toHex)));
             Endpoint client = Endpoint.bind(clientKey, LOCALHOST, Map.of())) {
            QuicClientConnection connection = client.connection(EndpointAddr.of(server.id()).withDirect(server.localAddress()), HttpOverIroh.ALPN);
            HttpOverIroh.Response response = HttpOverIroh.send(connection, new HttpOverIroh.Request("POST", "/api/v0/test?arg=1&b=2",
                    Map.of("Source", List.of("forged"), "X-Custom", List.of("v")), "hello".getBytes(StandardCharsets.UTF_8)));
            assertEquals(201, response.status());
            assertEquals("got hello", new String(response.body(), StandardCharsets.UTF_8));
            assertEquals(List.of("yes"), response.headers().entrySet().stream()
                    .filter(e -> e.getKey().equalsIgnoreCase("X-Reply")).findFirst().orElseThrow().getValue());
            // The Source the client sent is replaced by its authenticated id
            assertEquals(clientKey.endpointId().toHex(), source.get());
            assertEquals("arg=1&b=2", query.get());
        }
        finally {
            local.stop(0);
        }
    }

    @Test
    void connectionsShouldBeReused() throws Exception {
        try (Endpoint server = Endpoint.bind(SecretKey.generate(), LOCALHOST, Map.of(EchoProtocol.ALPN, new EchoProtocol()));
             Endpoint client = Endpoint.bind(SecretKey.generate(), LOCALHOST, Map.of())) {
            EndpointAddr addr = EndpointAddr.of(server.id()).withDirect(server.localAddress());
            // Concurrent callers share one dial
            List<CompletableFuture<QuicClientConnection>> concurrent = java.util.stream.IntStream.range(0, 8)
                    .mapToObj(i -> CompletableFuture.supplyAsync(() -> {
                        try {
                            return client.connection(addr, EchoProtocol.ALPN);
                        }
                        catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }))
                    .toList();
            QuicClientConnection first = concurrent.get(0).join();
            concurrent.forEach(f -> assertSame(first, f.join()));
            assertEquals("still open", EchoProtocol.echo(first, "still open"));

            // A closed connection is replaced
            first.close();
            long deadline = System.currentTimeMillis() + 5000;
            QuicClientConnection next = client.connection(addr, EchoProtocol.ALPN);
            while (next == first && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
                next = client.connection(addr, EchoProtocol.ALPN);
            }
            assertNotSame(first, next);
            assertEquals("new connection", EchoProtocol.echo(next, "new connection"));
        }
    }
}
