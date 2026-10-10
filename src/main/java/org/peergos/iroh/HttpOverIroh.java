package org.peergos.iroh;

import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HTTP over iroh, the replacement for nabu's p2p HTTP proxy: one HTTP/1.1 request and its response per
 * bidirectional stream, under ALPN {@value #ALPN}. The serving side forwards each request to a local HTTP server,
 * telling it who is calling in the {@code Source} header, as nabu does.
 */
public final class HttpOverIroh {

    private static final Logger LOG = Logger.getLogger(HttpOverIroh.class.getName());

    public static final String ALPN = "peergos/http/1";
    public static final String SOURCE_HEADER = "Source";
    private static final int MAX_HEADER_BYTES = 64 * 1024;
    private static final Duration RESPONSE_TIMEOUT = Duration.ofSeconds(60);
    // Headers that describe the hop rather than the message; the JDK client also refuses to set them.
    private static final Set<String> HOP_HEADERS = Set.of("connection", "content-length", "host", "transfer-encoding",
            "upgrade", "expect", "keep-alive", "te", "trailer", "proxy-connection");

    public record Request(String method, String pathAndQuery, Map<String, List<String>> headers, byte[] body) {}

    public record Response(int status, Map<String, List<String>> headers, byte[] body) {}

    private HttpOverIroh() {}

    /**
     * Sends a request on a new stream of the connection and waits for the response.
     */
    public static Response send(QuicConnection connection, Request request) throws IOException {
        QuicStream stream = connection.createStream(true);
        try (OutputStream out = stream.getOutputStream()) {
            writeRequest(out, request);
        }
        return readResponse(stream.getInputStream());
    }

    /**
     * A protocol handler that forwards requests to the HTTP server at {@code target}.
     * @param sourceHeader  formats the caller's endpoint id for the Source header (e.g. as a libp2p peer id)
     */
    public static ProtocolHandler proxyTo(URI target, Function<EndpointId, String> sourceHeader) {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        return (remote, remoteAddress, stream) -> Thread.ofVirtual().start(() -> {
            try (OutputStream out = stream.getOutputStream()) {
                Response response;
                try {
                    Request request = readRequest(stream.getInputStream());
                    response = forward(client, target, request, sourceHeader.apply(remote));
                }
                catch (IOException | InterruptedException e) {
                    LOG.log(Level.FINE, "p2p http request from " + remote + " failed", e);
                    response = new Response(502, Map.of(), new byte[0]);
                }
                writeResponse(out, response);
            }
            catch (IOException e) {
                LOG.log(Level.FINE, "cannot reply to " + remote, e);
            }
        });
    }

    private static Response forward(HttpClient client, URI target, Request request, String source) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(target.resolve(request.pathAndQuery()))
                .timeout(RESPONSE_TIMEOUT)
                .method(request.method(), request.body().length == 0
                        ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofByteArray(request.body()));
        request.headers().forEach((name, values) -> {
            if (!HOP_HEADERS.contains(name.toLowerCase(Locale.ROOT)) && !name.equalsIgnoreCase(SOURCE_HEADER)) {
                values.forEach(v -> builder.header(name, v));
            }
        });
        // The caller is authenticated by the QUIC handshake; whatever Source header it sent is replaced.
        builder.header(SOURCE_HEADER, source);
        HttpResponse<byte[]> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        Map<String, List<String>> headers = new LinkedHashMap<>();
        response.headers().map().forEach((name, values) -> {
            if (!HOP_HEADERS.contains(name.toLowerCase(Locale.ROOT)) && !name.startsWith(":")) {
                headers.put(name, values);
            }
        });
        return new Response(response.statusCode(), headers, response.body());
    }

    static void writeRequest(OutputStream out, Request request) throws IOException {
        StringBuilder head = new StringBuilder();
        head.append(request.method()).append(' ').append(request.pathAndQuery()).append(" HTTP/1.1\r\n");
        appendHeaders(head, request.headers(), request.body().length);
        out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(request.body());
    }

    static void writeResponse(OutputStream out, Response response) throws IOException {
        StringBuilder head = new StringBuilder();
        head.append("HTTP/1.1 ").append(response.status()).append(' ').append(reason(response.status())).append("\r\n");
        appendHeaders(head, response.headers(), response.body().length);
        out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(response.body());
    }

    private static void appendHeaders(StringBuilder head, Map<String, List<String>> headers, int bodyLength) {
        headers.forEach((name, values) -> {
            if (!HOP_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                for (String value : values) {
                    if (name.indexOf('\r') >= 0 || name.indexOf('\n') >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
                        throw new IllegalArgumentException("invalid header " + name);
                    }
                    head.append(name).append(": ").append(value).append("\r\n");
                }
            }
        });
        head.append("Content-Length: ").append(bodyLength).append("\r\n\r\n");
    }

    static Request readRequest(InputStream in) throws IOException {
        List<String> head = readHead(in);
        String[] requestLine = head.get(0).split(" ", 3);
        if (requestLine.length != 3 || !requestLine[2].startsWith("HTTP/1.")) {
            throw new IOException("invalid request line");
        }
        Map<String, List<String>> headers = parseHeaders(head);
        return new Request(requestLine[0], requestLine[1], headers, readBody(in, headers));
    }

    static Response readResponse(InputStream in) throws IOException {
        List<String> head = readHead(in);
        String[] statusLine = head.get(0).split(" ", 3);
        if (statusLine.length < 2 || !statusLine[0].startsWith("HTTP/1.")) {
            throw new IOException("invalid status line");
        }
        Map<String, List<String>> headers = parseHeaders(head);
        return new Response(Integer.parseInt(statusLine[1]), headers, readBody(in, headers));
    }

    private static List<String> readHead(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        java.util.ArrayList<String> lines = new java.util.ArrayList<>();
        int total = 0;
        int previous = -1;
        while (true) {
            int b = in.read();
            if (b < 0) {
                throw new EOFException("stream ended in HTTP head");
            }
            if (++total > MAX_HEADER_BYTES) {
                throw new IOException("HTTP head too large");
            }
            if (b == '\n' && previous == '\r') {
                byte[] bytes = line.toByteArray();
                String text = new String(bytes, 0, bytes.length - 1, StandardCharsets.ISO_8859_1);
                if (text.isEmpty()) {
                    if (lines.isEmpty()) {
                        throw new IOException("empty HTTP head");
                    }
                    return lines;
                }
                lines.add(text);
                line.reset();
            }
            else {
                line.write(b);
            }
            previous = b;
        }
    }

    private static Map<String, List<String>> parseHeaders(List<String> head) throws IOException {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (String line : head.subList(1, head.size())) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                throw new IOException("invalid header line");
            }
            headers.computeIfAbsent(line.substring(0, colon).trim(), k -> new java.util.ArrayList<>())
                    .add(line.substring(colon + 1).trim());
        }
        return headers;
    }

    private static byte[] readBody(InputStream in, Map<String, List<String>> headers) throws IOException {
        String length = headers.entrySet().stream()
                .filter(e -> e.getKey().equalsIgnoreCase("Content-Length"))
                .map(e -> e.getValue().get(0))
                .findFirst()
                .orElse(null);
        if (length == null) {
            // One message per stream, so the end of the stream ends the body.
            return in.readAllBytes();
        }
        long expected = Long.parseLong(length);
        if (expected < 0 || expected > Integer.MAX_VALUE - 8) {
            throw new IOException("invalid content length");
        }
        byte[] body = in.readNBytes((int) expected);
        if (body.length != expected) {
            throw new EOFException("stream ended in HTTP body");
        }
        return body;
    }

    private static String reason(int status) {
        return switch (status) {
            case 200 -> "OK";
            case 400 -> "Bad Request";
            case 404 -> "Not Found";
            case 500 -> "Internal Server Error";
            case 502 -> "Bad Gateway";
            default -> "Status";
        };
    }
}
