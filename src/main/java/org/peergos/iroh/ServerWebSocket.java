package org.peergos.iroh;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** The server side of an HTTP/1.1 request and a WebSocket (RFC 6455) on top of it, as much as a relay needs. */
final class ServerWebSocket {

    static final int CONTINUATION = 0;
    static final int TEXT = 1;
    static final int BINARY = 2;
    static final int CLOSE = 8;
    static final int PING = 9;
    static final int PONG = 10;

    private static final int MAX_HEADER_SIZE = 16 * 1024;
    private static final String ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    record Request(String method, String path, Map<String, String> headers) {
        String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }
    }

    record Message(int opcode, byte[] data) {}

    private final DataInputStream in;
    private final OutputStream out;
    private final byte[] mask = new byte[4];
    private final byte[] header = new byte[10];
    private final ByteArrayOutputStream fragments = new ByteArrayOutputStream();
    private int fragmentedOpcode = -1;

    ServerWebSocket(InputStream in, OutputStream out) {
        this.in = new DataInputStream(in);
        this.out = out;
    }

    /** Reads a request line and headers, or returns null at end of stream. Repeated headers are comma joined. */
    static Request readRequest(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int matched = 0;
        while (matched < 4) {
            int b = in.read();
            if (b < 0) {
                if (head.size() == 0) {
                    return null;
                }
                throw new EOFException("end of stream in request header");
            }
            head.write(b);
            if (head.size() > MAX_HEADER_SIZE) {
                throw new ProtocolException("request header too large");
            }
            matched = (b == (matched % 2 == 0? '\r': '\n'))? matched + 1: (b == '\r'? 1: 0);
        }
        String[] lines = head.toString(StandardCharsets.ISO_8859_1).split("\r\n");
        String[] requestLine = lines[0].split(" ");
        if (requestLine.length != 3 || !requestLine[2].startsWith("HTTP/1.")) {
            throw new ProtocolException("bad request line: " + lines[0]);
        }
        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon <= 0) {
                throw new ProtocolException("bad header line: " + lines[i]);
            }
            String name = lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = lines[i].substring(colon + 1).trim();
            headers.merge(name, value, (a, b) -> a + ", " + b);
        }
        String path = requestLine[1];
        int query = path.indexOf('?');
        return new Request(requestLine[0], query < 0? path: path.substring(0, query), headers);
    }

    static void writeResponse(OutputStream out, int status, String reason, Map<String, String> headers, byte[] body) throws IOException {
        StringBuilder response = new StringBuilder("HTTP/1.1 ").append(status).append(' ').append(reason).append("\r\n");
        headers.forEach((name, value) -> response.append(name).append(": ").append(value).append("\r\n"));
        if (body != null) {
            response.append("Content-Length: ").append(body.length).append("\r\n");
        }
        response.append("\r\n");
        out.write(response.toString().getBytes(StandardCharsets.ISO_8859_1));
        if (body != null) {
            out.write(body);
        }
        out.flush();
    }

    static String acceptKey(String key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1").digest((key + ACCEPT_GUID).getBytes(StandardCharsets.ISO_8859_1));
            return Base64.getEncoder().encodeToString(digest);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Reads the next message: a control frame as it arrives (they may come between fragments), or a whole data
     * message. Returns null at end of stream.
     */
    Message read(int maxSize) throws IOException {
        while (true) {
            int first = in.read();
            if (first < 0) {
                return null;
            }
            int second = in.readUnsignedByte();
            boolean fin = (first & 0x80) != 0;
            int opcode = first & 0x0f;
            if ((first & 0x70) != 0) {
                throw new ProtocolException("websocket extension bits set");
            }
            if ((second & 0x80) == 0) {
                throw new ProtocolException("unmasked client frame");
            }
            long length = second & 0x7f;
            if (length == 126) {
                length = in.readUnsignedShort();
            }
            else if (length == 127) {
                length = in.readLong();
            }
            boolean control = opcode >= 8;
            if (control && (length > 125 || !fin)) {
                throw new ProtocolException("invalid control frame");
            }
            if (length < 0 || fragments.size() + length > maxSize) {
                throw new ProtocolException("websocket message too large");
            }
            in.readFully(mask);
            byte[] payload = new byte[(int) length];
            in.readFully(payload);
            for (int i = 0; i < payload.length; i++) {
                payload[i] ^= mask[i & 3];
            }
            if (control) {
                return new Message(opcode, payload);
            }
            if (opcode == CONTINUATION) {
                if (fragmentedOpcode < 0) {
                    throw new ProtocolException("continuation without a message");
                }
            }
            else {
                if (fragmentedOpcode >= 0) {
                    throw new ProtocolException("new message inside a fragmented one");
                }
                if (fin) {
                    return new Message(opcode, payload);
                }
                fragmentedOpcode = opcode;
            }
            fragments.write(payload);
            if (fin) {
                Message message = new Message(fragmentedOpcode, fragments.toByteArray());
                fragments.reset();
                fragmentedOpcode = -1;
                return message;
            }
        }
    }

    /** Writes one unmasked frame without flushing. Not thread safe. */
    void write(int opcode, byte[] data, int offset, int length) throws IOException {
        int headerLength;
        header[0] = (byte) (0x80 | opcode);
        if (length < 126) {
            header[1] = (byte) length;
            headerLength = 2;
        }
        else if (length < 65536) {
            header[1] = 126;
            header[2] = (byte) (length >> 8);
            header[3] = (byte) length;
            headerLength = 4;
        }
        else {
            header[1] = 127;
            for (int i = 0; i < 8; i++) {
                header[2 + i] = (byte) ((long) length >> (56 - 8 * i));
            }
            headerLength = 10;
        }
        out.write(header, 0, headerLength);
        out.write(data, offset, length);
    }

    void flush() throws IOException {
        out.flush();
    }
}
