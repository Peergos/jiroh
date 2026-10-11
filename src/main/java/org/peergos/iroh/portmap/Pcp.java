package org.peergos.iroh.portmap;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;

/**
 * Port Control Protocol client (RFC 6887): UDP MAP requests to the gateway, as iroh's portmapper makes them.
 */
final class Pcp {

    static final int SERVER_PORT = 5351;
    static final int VERSION = 2;
    static final int OPCODE_ANNOUNCE = 0;
    static final int OPCODE_MAP = 1;
    static final int RESPONSE = 0x80;
    static final int PROTOCOL_UDP = 17;
    static final int MAP_SIZE = 24 + 36;
    private static final int LIFETIME_SECONDS = 60 * 60;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Pcp() {}

    record Response(int opcode, int resultCode, long lifetimeSeconds, byte[] nonce, int protocol, int localPort,
                    int externalPort, InetAddress externalAddress) {}

    static byte[] announce(Inet4Address client) {
        return header(OPCODE_ANNOUNCE, 0, client).array();
    }

    static byte[] map(byte[] nonce, Inet4Address local, int localPort, InetSocketAddress preferredExternal, long lifetimeSeconds) {
        ByteBuffer buffer = header(OPCODE_MAP, lifetimeSeconds, local);
        buffer.put(nonce);
        buffer.put((byte) PROTOCOL_UDP);
        buffer.put(new byte[3]);
        buffer.putShort((short) localPort);
        buffer.putShort((short) (preferredExternal == null? 0: preferredExternal.getPort()));
        buffer.put(mapped(preferredExternal == null? null: preferredExternal.getAddress()));
        return buffer.array();
    }

    private static ByteBuffer header(int opcode, long lifetimeSeconds, Inet4Address client) {
        ByteBuffer buffer = ByteBuffer.allocate(opcode == OPCODE_MAP? MAP_SIZE: 24);
        buffer.put((byte) VERSION);
        buffer.put((byte) opcode);
        buffer.putShort((short) 0);
        buffer.putInt((int) lifetimeSeconds);
        buffer.put(mapped(client));
        return buffer;
    }

    /** An IPv4 address as IPv4-mapped IPv6, the unspecified address for null. */
    static byte[] mapped(InetAddress address) {
        byte[] result = new byte[16];
        if (address != null) {
            result[10] = (byte) 0xff;
            result[11] = (byte) 0xff;
            System.arraycopy(address.getAddress(), 0, result, 12, 4);
        }
        return result;
    }

    static Response decode(byte[] data, int length) throws IOException {
        if (length < 24 || data[0] != VERSION || (data[1] & RESPONSE) == 0) {
            throw new IOException("not a PCP response");
        }
        ByteBuffer buffer = ByteBuffer.wrap(data, 0, length);
        int opcode = buffer.get(1) & 0x7f;
        int resultCode = buffer.get(3) & 0xff;
        long lifetime = buffer.getInt(4) & 0xffffffffL;
        if (opcode != OPCODE_MAP || resultCode != 0) {
            return new Response(opcode, resultCode, lifetime, null, 0, 0, 0, null);
        }
        if (length < MAP_SIZE) {
            throw new IOException("short PCP MAP response");
        }
        buffer.position(24);
        byte[] nonce = new byte[12];
        buffer.get(nonce);
        int protocol = buffer.get() & 0xff;
        buffer.position(buffer.position() + 3);
        int localPort = buffer.getShort() & 0xffff;
        int externalPort = buffer.getShort() & 0xffff;
        byte[] address = new byte[16];
        buffer.get(address);
        return new Response(opcode, resultCode, lifetime, nonce, protocol, localPort, externalPort, InetAddress.getByAddress(address));
    }

    /** Whether the gateway answers PCP. */
    static boolean probe(Inet4Address local, InetAddress gateway, int port, Duration timeout) {
        try {
            Response response = decode(Udp.exchange(local, new InetSocketAddress(gateway, port), announce(local), timeout));
            return response.opcode() == OPCODE_ANNOUNCE && response.resultCode() == 0;
        }
        catch (IOException e) {
            return false;
        }
    }

    private static Response decode(byte[] response) throws IOException {
        return decode(response, response.length);
    }

    static Mapping map(Inet4Address local, int localPort, InetAddress gateway, int port, InetSocketAddress preferredExternal,
                       Duration timeout) throws IOException {
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        InetSocketAddress server = new InetSocketAddress(gateway, port);
        Response response = decode(Udp.exchange(local, server, map(nonce, local, localPort, preferredExternal, LIFETIME_SECONDS), timeout));
        if (response.opcode() != OPCODE_MAP || response.resultCode() != 0) {
            throw new IOException("PCP MAP failed with result code " + response.resultCode());
        }
        if (!Arrays.equals(nonce, response.nonce()) || response.protocol() != PROTOCOL_UDP || response.localPort() != localPort
                || response.externalPort() == 0 || !(response.externalAddress() instanceof Inet4Address)) {
            throw new IOException("unexpected PCP MAP response");
        }
        InetSocketAddress external = new InetSocketAddress(response.externalAddress(), response.externalPort());
        return new Mapping(Mapping.Protocol.PCP, external, Duration.ofSeconds(response.lifetimeSeconds()), () ->
                Udp.send(local, server, map(nonce, local, localPort, null, 0)));
    }
}
