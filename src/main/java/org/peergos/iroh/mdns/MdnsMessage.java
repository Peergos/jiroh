package org.peergos.iroh.mdns;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The DNS messages of swarm-discovery's mDNS (RFC 6762): PTR queries for the service, and responses with SRV and
 * TXT answers and A/AAAA additionals. Names are written and compared without the trailing dot.
 */
final class MdnsMessage {

    static final int TYPE_A = 1;
    static final int TYPE_PTR = 12;
    static final int TYPE_TXT = 16;
    static final int TYPE_AAAA = 28;
    static final int TYPE_SRV = 33;
    static final int CLASS_IN = 1;
    private static final int FLAG_RESPONSE = 0x8000;
    private static final int FLAG_AUTHORITATIVE = 0x0400;

    record Question(String name, int type, int dnsClass) {}

    sealed interface Data {}
    record Srv(int port, String target) implements Data {}
    record Txt(List<String> strings) implements Data {}
    record Address(InetAddress address) implements Data {}
    record Other(int type) implements Data {}

    record Record(String name, int dnsClass, long ttl, Data data) {}

    record Message(boolean response, List<Question> questions, List<Record> answers, List<Record> additionals) {}

    private MdnsMessage() {}

    static byte[] query(String name) {
        Writer out = new Writer();
        out.header(0, 1, 0, 0);
        out.name(name, true);
        out.u16(TYPE_PTR);
        out.u16(CLASS_IN);
        return out.toByteArray();
    }

    static byte[] response(List<Record> answers, List<Record> additionals) {
        Writer out = new Writer();
        out.header(FLAG_RESPONSE | FLAG_AUTHORITATIVE, 0, answers.size(), additionals.size());
        for (Record record : answers) {
            out.record(record);
        }
        for (Record record : additionals) {
            out.record(record);
        }
        return out.toByteArray();
    }

    private static final class Writer {
        // RFC 6762 §17: an mDNS message is at most 9000 bytes.
        private final ByteBuffer out = ByteBuffer.allocate(9000);
        private final Map<String, Integer> offsets = new HashMap<>();

        void header(int flags, int questions, int answers, int additionals) {
            u16(0);
            u16(flags);
            u16(questions);
            u16(answers);
            u16(0);
            u16(additionals);
        }

        void record(Record record) {
            name(record.name, true);
            int type = switch (record.data) {
                case Srv s -> TYPE_SRV;
                case Txt t -> TYPE_TXT;
                case Address a -> a.address.getAddress().length == 4? TYPE_A: TYPE_AAAA;
                case Other o -> throw new IllegalArgumentException("cannot encode type " + o.type);
            };
            u16(type);
            u16(record.dnsClass);
            u16((int) (record.ttl >> 16) & 0xffff);
            u16((int) record.ttl & 0xffff);
            int lengthAt = out.position();
            u16(0);
            switch (record.data) {
                case Srv srv -> {
                    u16(0); // priority
                    u16(0); // weight
                    u16(srv.port);
                    // RFC 2782: the target is not compressed, though later names may point to it.
                    name(srv.target, false);
                }
                case Txt txt -> {
                    for (String s : txt.strings) {
                        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
                        if (bytes.length > 255) {
                            throw new IllegalArgumentException("TXT string too long");
                        }
                        out.put((byte) bytes.length);
                        out.put(bytes);
                    }
                }
                case Address a -> out.put(a.address.getAddress());
                case Other o -> throw new IllegalStateException();
            }
            out.putShort(lengthAt, (short) (out.position() - lengthAt - 2));
        }

        void name(String name, boolean compress) {
            String remaining = name.endsWith(".")? name.substring(0, name.length() - 1): name;
            while (!remaining.isEmpty()) {
                String key = remaining.toLowerCase();
                Integer pointer = offsets.get(key);
                if (compress && pointer != null) {
                    u16(0xc000 | pointer);
                    return;
                }
                if (pointer == null && out.position() < 0x4000) {
                    offsets.put(key, out.position());
                }
                int dot = remaining.indexOf('.');
                String label = dot < 0? remaining: remaining.substring(0, dot);
                byte[] bytes = label.getBytes(StandardCharsets.UTF_8);
                if (bytes.length == 0 || bytes.length > 63) {
                    throw new IllegalArgumentException("invalid DNS label in " + name);
                }
                out.put((byte) bytes.length);
                out.put(bytes);
                remaining = dot < 0? "": remaining.substring(dot + 1);
            }
            out.put((byte) 0);
        }

        void u16(int value) {
            out.putShort((short) value);
        }

        byte[] toByteArray() {
            return java.util.Arrays.copyOf(out.array(), out.position());
        }
    }

    /** Decodes a message; throws IllegalArgumentException (or a runtime exception from the buffer) if malformed. */
    static Message decode(byte[] packet) {
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        buffer.getShort(); // id
        int flags = buffer.getShort() & 0xffff;
        int questions = buffer.getShort() & 0xffff;
        int answers = buffer.getShort() & 0xffff;
        int authorities = buffer.getShort() & 0xffff;
        int additionals = buffer.getShort() & 0xffff;
        List<Question> qs = new ArrayList<>();
        for (int i = 0; i < questions; i++) {
            String name = readName(buffer, packet);
            qs.add(new Question(name, buffer.getShort() & 0xffff, buffer.getShort() & 0xffff));
        }
        List<Record> an = readRecords(buffer, packet, answers);
        readRecords(buffer, packet, authorities);
        List<Record> ad = readRecords(buffer, packet, additionals);
        return new Message((flags & FLAG_RESPONSE) != 0, qs, an, ad);
    }

    private static List<Record> readRecords(ByteBuffer buffer, byte[] packet, int count) {
        List<Record> records = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String name = readName(buffer, packet);
            int type = buffer.getShort() & 0xffff;
            int dnsClass = buffer.getShort() & 0xffff;
            long ttl = buffer.getInt() & 0xffffffffL;
            int length = buffer.getShort() & 0xffff;
            int start = buffer.position();
            int end = start + length;
            if (end > packet.length) {
                throw new IllegalArgumentException("truncated record");
            }
            Data data = switch (type) {
                case TYPE_SRV -> {
                    buffer.getShort();
                    buffer.getShort();
                    int port = buffer.getShort() & 0xffff;
                    yield new Srv(port, readName(buffer, packet));
                }
                case TYPE_TXT -> {
                    List<String> strings = new ArrayList<>();
                    int offset = start;
                    while (offset < end) {
                        int len = packet[offset] & 0xff;
                        if (offset + 1 + len > end) {
                            throw new IllegalArgumentException("truncated TXT");
                        }
                        strings.add(new String(packet, offset + 1, len, StandardCharsets.UTF_8));
                        offset += 1 + len;
                    }
                    yield new Txt(strings);
                }
                case TYPE_A, TYPE_AAAA -> {
                    if (length != (type == TYPE_A? 4: 16)) {
                        throw new IllegalArgumentException("bad address length");
                    }
                    byte[] raw = new byte[length];
                    buffer.get(raw);
                    try {
                        yield new Address(InetAddress.getByAddress(raw));
                    }
                    catch (UnknownHostException e) {
                        throw new IllegalArgumentException(e);
                    }
                }
                default -> new Other(type);
            };
            buffer.position(end);
            records.add(new Record(name, dnsClass, ttl, data));
        }
        return records;
    }

    private static String readName(ByteBuffer buffer, byte[] packet) {
        StringBuilder name = new StringBuilder();
        int position = buffer.position();
        boolean jumped = false;
        int jumps = 0;
        while (true) {
            int length = packet[position] & 0xff;
            if ((length & 0xc0) == 0xc0) {
                if (++jumps > 64) {
                    throw new IllegalArgumentException("compression loop");
                }
                int pointer = ((length & 0x3f) << 8) | (packet[position + 1] & 0xff);
                if (!jumped) {
                    buffer.position(position + 2);
                }
                jumped = true;
                position = pointer;
                continue;
            }
            if ((length & 0xc0) != 0) {
                throw new IllegalArgumentException("bad label type");
            }
            if (length == 0) {
                if (!jumped) {
                    buffer.position(position + 1);
                }
                return name.toString();
            }
            if (name.length() > 0) {
                name.append('.');
            }
            name.append(new String(packet, position + 1, length, StandardCharsets.UTF_8));
            position += 1 + length;
        }
    }
}
