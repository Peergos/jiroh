package org.peergos.iroh.pkarr;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Bencoding (BEP3) for KRPC. Byte strings are byte[], integers Long, lists List, dictionaries Map with String keys
 * (DHT keys are ASCII), kept sorted on encoding as bencoding requires.
 */
public final class Bencode {

    private Bencode() {}

    public static byte[] encode(Object value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encode(value, out);
        return out.toByteArray();
    }

    private static void encode(Object value, ByteArrayOutputStream out) {
        if (value instanceof byte[] bytes) {
            out.writeBytes((bytes.length + ":").getBytes(StandardCharsets.US_ASCII));
            out.writeBytes(bytes);
        }
        else if (value instanceof String s) {
            encode(s.getBytes(StandardCharsets.UTF_8), out);
        }
        else if (value instanceof Long || value instanceof Integer) {
            out.writeBytes(("i" + value + "e").getBytes(StandardCharsets.US_ASCII));
        }
        else if (value instanceof List<?> list) {
            out.write('l');
            list.forEach(item -> encode(item, out));
            out.write('e');
        }
        else if (value instanceof Map<?, ?> map) {
            out.write('d');
            new TreeMap<>(map).forEach((key, item) -> {
                encode(key, out);
                encode(item, out);
            });
            out.write('e');
        }
        else {
            throw new IllegalArgumentException("cannot bencode " + value);
        }
    }

    public static Object decode(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        Object value = decode(buffer, 0);
        if (buffer.hasRemaining()) {
            throw new IllegalArgumentException("trailing data");
        }
        return value;
    }

    private static Object decode(ByteBuffer buffer, int depth) {
        if (depth > 32) {
            throw new IllegalArgumentException("nesting too deep");
        }
        byte type = buffer.get(buffer.position());
        switch (type) {
            case 'i' -> {
                buffer.get();
                return readNumber(buffer, (byte) 'e');
            }
            case 'l' -> {
                buffer.get();
                List<Object> list = new ArrayList<>();
                while (buffer.get(buffer.position()) != 'e') {
                    list.add(decode(buffer, depth + 1));
                }
                buffer.get();
                return list;
            }
            case 'd' -> {
                buffer.get();
                Map<String, Object> map = new TreeMap<>();
                while (buffer.get(buffer.position()) != 'e') {
                    String key = new String(readBytes(buffer), StandardCharsets.UTF_8);
                    map.put(key, decode(buffer, depth + 1));
                }
                buffer.get();
                return map;
            }
            default -> {
                if (type >= '0' && type <= '9') {
                    return readBytes(buffer);
                }
                throw new IllegalArgumentException("invalid bencode type " + (char) type);
            }
        }
    }

    private static byte[] readBytes(ByteBuffer buffer) {
        long length = readNumber(buffer, (byte) ':');
        if (length < 0 || length > buffer.remaining()) {
            throw new IllegalArgumentException("invalid string length");
        }
        byte[] bytes = new byte[(int) length];
        buffer.get(bytes);
        return bytes;
    }

    private static long readNumber(ByteBuffer buffer, byte terminator) {
        StringBuilder digits = new StringBuilder();
        byte b;
        while ((b = buffer.get()) != terminator) {
            if (digits.length() > 20) {
                throw new IllegalArgumentException("number too long");
            }
            digits.append((char) b);
        }
        return Long.parseLong(digits.toString());
    }

    /** Typed accessors for decoded dictionaries. */
    public static byte[] bytes(Map<?, ?> map, String key) {
        return map.get(key) instanceof byte[] b? b: null;
    }

    public static Long number(Map<?, ?> map, String key) {
        return map.get(key) instanceof Long l? l: null;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> dict(Map<?, ?> map, String key) {
        return map.get(key) instanceof Map<?, ?> m? (Map<String, Object>) m: null;
    }

    public static String string(Map<?, ?> map, String key) {
        byte[] b = bytes(map, key);
        return b == null? null: new String(b, StandardCharsets.UTF_8);
    }

    public static boolean equalsBytes(Object a, byte[] b) {
        return a instanceof byte[] bytes && Arrays.equals(bytes, b);
    }
}
