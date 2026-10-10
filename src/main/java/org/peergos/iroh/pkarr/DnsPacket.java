package org.peergos.iroh.pkarr;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The DNS message subset pkarr needs (RFC 1035): a response with answer records only. Names are encoded with
 * compression, as pkarr requires for its long TLDs; TXT records are decoded, other types are kept raw.
 */
public final class DnsPacket {

    public static final int TYPE_A = 1;
    public static final int TYPE_TXT = 16;
    public static final int TYPE_AAAA = 28;
    private static final int CLASS_IN = 1;
    private static final int FLAG_RESPONSE = 0x8000;

    public record Record(String name, int type, long ttl, byte[] rdata) {
        public static Record txt(String name, long ttl, String value) {
            byte[] text = value.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream rdata = new ByteArrayOutputStream();
            // A TXT record is a sequence of length-prefixed character strings of at most 255 bytes.
            for (int offset = 0; offset < text.length || offset == 0; offset += 255) {
                int length = Math.min(255, text.length - offset);
                rdata.write(length);
                rdata.write(text, offset, length);
                if (text.length == 0) {
                    break;
                }
            }
            return new Record(name, TYPE_TXT, ttl, rdata.toByteArray());
        }

        /** The TXT value: its character strings concatenated. */
        public String text() {
            if (type != TYPE_TXT) {
                throw new IllegalStateException("not a TXT record");
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offset = 0;
            while (offset < rdata.length) {
                int length = rdata[offset] & 0xff;
                out.write(rdata, offset + 1, Math.min(length, rdata.length - offset - 1));
                offset += 1 + length;
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    private DnsPacket() {}

    public static byte[] encode(List<Record> answers) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeShort(out, 0);               // id
        writeShort(out, FLAG_RESPONSE);
        writeShort(out, 0);               // questions
        writeShort(out, answers.size());
        writeShort(out, 0);               // authority
        writeShort(out, 0);               // additional
        Map<String, Integer> nameOffsets = new HashMap<>();
        for (Record record : answers) {
            writeName(out, record.name, nameOffsets);
            writeShort(out, record.type);
            writeShort(out, CLASS_IN);
            writeInt(out, record.ttl);
            writeShort(out, record.rdata.length);
            out.writeBytes(record.rdata);
        }
        return out.toByteArray();
    }

    private static void writeName(ByteArrayOutputStream out, String name, Map<String, Integer> offsets) {
        String remaining = name.endsWith(".")? name.substring(0, name.length() - 1): name;
        while (!remaining.isEmpty()) {
            Integer pointer = offsets.get(remaining.toLowerCase());
            if (pointer != null) {
                writeShort(out, 0xc000 | pointer);
                return;
            }
            if (out.size() < 0x4000) {
                offsets.put(remaining.toLowerCase(), out.size());
            }
            int dot = remaining.indexOf('.');
            String label = dot < 0? remaining: remaining.substring(0, dot);
            byte[] bytes = label.getBytes(StandardCharsets.UTF_8);
            if (bytes.length == 0 || bytes.length > 63) {
                throw new IllegalArgumentException("invalid DNS label in " + name);
            }
            out.write(bytes.length);
            out.writeBytes(bytes);
            remaining = dot < 0? "": remaining.substring(dot + 1);
        }
        out.write(0);
    }

    /** Decodes the answer records of a DNS message; questions are skipped, authority and additional ignored. */
    public static List<Record> decodeAnswers(byte[] packet) {
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        buffer.position(4);
        int questions = buffer.getShort() & 0xffff;
        int answers = buffer.getShort() & 0xffff;
        buffer.position(12);
        for (int i = 0; i < questions; i++) {
            readName(buffer, packet);
            buffer.position(buffer.position() + 4);
        }
        List<Record> records = new ArrayList<>();
        for (int i = 0; i < answers; i++) {
            String name = readName(buffer, packet);
            int type = buffer.getShort() & 0xffff;
            buffer.getShort(); // class
            long ttl = buffer.getInt() & 0xffffffffL;
            int length = buffer.getShort() & 0xffff;
            byte[] rdata = new byte[length];
            buffer.get(rdata);
            records.add(new Record(name, type, ttl, rdata));
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

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write((value >> 8) & 0xff);
        out.write(value & 0xff);
    }

    private static void writeInt(ByteArrayOutputStream out, long value) {
        writeShort(out, (int) (value >> 16) & 0xffff);
        writeShort(out, (int) value & 0xffff);
    }
}
