package org.peergos.iroh;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicStream;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/** The echo protocol of interop-probe: each bidirectional stream echoes what it receives. */
final class EchoProtocol implements ProtocolHandler {

    static final String ALPN = "iroh-interop/echo/0";

    volatile EndpointId lastRemote;
    volatile InetSocketAddress lastRemoteAddress;

    @Override
    public void acceptStream(EndpointId remote, InetSocketAddress remoteAddress, QuicStream stream) {
        lastRemote = remote;
        lastRemoteAddress = remoteAddress;
        Thread.ofVirtual().start(() -> {
            try (OutputStream out = stream.getOutputStream()) {
                out.write(stream.getInputStream().readAllBytes());
            }
            catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    static String echo(QuicClientConnection connection, String message) throws IOException {
        QuicStream stream = connection.createStream(true);
        try (OutputStream out = stream.getOutputStream()) {
            out.write(message.getBytes(StandardCharsets.UTF_8));
        }
        return new String(stream.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
}
