package org.peergos.iroh.acme;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Just enough JSON for ACME: parses to Map, List, String, Double, Boolean and null; quotes strings for output. */
final class Json {

    private final String text;
    private int pos;

    private Json(String text) {
        this.text = text;
    }

    static Object parse(String text) {
        Json json = new Json(text);
        Object value = json.value();
        json.whitespace();
        if (json.pos != text.length()) {
            throw json.error("trailing characters");
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(String text) {
        Object value = parse(text);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("expected a JSON object");
        }
        return (Map<String, Object>) value;
    }

    static String quote(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    private Object value() {
        whitespace();
        if (pos >= text.length()) {
            throw error("unexpected end");
        }
        char c = text.charAt(pos);
        return switch (c) {
            case '{' -> object();
            case '[' -> array();
            case '"' -> string();
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case 'n' -> literal("null", null);
            default -> number();
        };
    }

    private Map<String, Object> object() {
        Map<String, Object> map = new LinkedHashMap<>();
        pos++;
        whitespace();
        if (peek() == '}') {
            pos++;
            return map;
        }
        while (true) {
            whitespace();
            if (peek() != '"') {
                throw error("expected a key");
            }
            String key = string();
            whitespace();
            expect(':');
            map.put(key, value());
            whitespace();
            char c = text.charAt(pos++);
            if (c == '}') {
                return map;
            }
            if (c != ',') {
                throw error("expected , or }");
            }
        }
    }

    private List<Object> array() {
        List<Object> list = new ArrayList<>();
        pos++;
        whitespace();
        if (peek() == ']') {
            pos++;
            return list;
        }
        while (true) {
            list.add(value());
            whitespace();
            char c = text.charAt(pos++);
            if (c == ']') {
                return list;
            }
            if (c != ',') {
                throw error("expected , or ]");
            }
        }
    }

    private String string() {
        pos++;
        StringBuilder out = new StringBuilder();
        while (true) {
            char c = text.charAt(pos++);
            if (c == '"') {
                return out.toString();
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char e = text.charAt(pos++);
            switch (e) {
                case '"', '\\', '/' -> out.append(e);
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                    pos += 4;
                }
                default -> throw error("bad escape");
            }
        }
    }

    private Object literal(String word, Object value) {
        if (!text.startsWith(word, pos)) {
            throw error("unexpected token");
        }
        pos += word.length();
        return value;
    }

    private Double number() {
        int start = pos;
        while (pos < text.length() && "+-0123456789.eE".indexOf(text.charAt(pos)) >= 0) {
            pos++;
        }
        if (start == pos) {
            throw error("unexpected character");
        }
        return Double.parseDouble(text.substring(start, pos));
    }

    private void whitespace() {
        while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
            pos++;
        }
    }

    private char peek() {
        if (pos >= text.length()) {
            throw error("unexpected end");
        }
        return text.charAt(pos);
    }

    private void expect(char c) {
        if (peek() != c) {
            throw error("expected " + c);
        }
        pos++;
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException("invalid JSON at " + pos + ": " + message);
    }
}
