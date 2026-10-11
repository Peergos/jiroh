package org.peergos.iroh.portmap;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;

/**
 * NAT-PMP client (RFC 6886): the gateway's external address and a UDP mapping, as iroh's portmapper requests them.
 */
final class NatPmp {

    static final int SERVER_PORT = 5351;
    static final int OPCODE_EXTERNAL_ADDRESS = 0;
    static final int OPCODE_MAP_UDP = 1;
    static final int RESPONSE = 0x80;
    private static final int LIFETIME_SECONDS = 2 * 60 * 60;

    private NatPmp() {}

    static byte[] externalAddressRequest() {
        return new byte[] {0, OPCODE_EXTERNAL_ADDRESS};
    }

    static byte[] mapRequest(int localPort, int preferredExternalPort, long lifetimeSeconds) {
        ByteBuffer buffer = ByteBuffer.allocate(12);
        buffer.put((byte) 0);
        buffer.put((byte) OPCODE_MAP_UDP);
        buffer.putShort((short) 0);
        buffer.putShort((short) localPort);
        buffer.putShort((short) preferredExternalPort);
        buffer.putInt((int) lifetimeSeconds);
        return buffer.array();
    }

    private static ByteBuffer response(byte[] data, int opcode, int size) throws IOException {
        if (data.length < 8 || data[0] != 0 || (data[1] & 0xff) != (RESPONSE | opcode)) {
            throw new IOException("not a NAT-PMP response");
        }
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int resultCode = buffer.getShort(2) & 0xffff;
        if (resultCode != 0) {
            throw new IOException("NAT-PMP request failed with result code " + resultCode);
        }
        if (data.length < size) {
            throw new IOException("short NAT-PMP response");
        }
        return buffer;
    }

    static InetAddress externalAddress(Inet4Address local, InetSocketAddress server, Duration timeout) throws IOException {
        ByteBuffer response = response(Udp.exchange(local, server, externalAddressRequest(), timeout), OPCODE_EXTERNAL_ADDRESS, 12);
        byte[] ip = new byte[4];
        response.get(8, ip);
        return InetAddress.getByAddress(ip);
    }

    static boolean probe(Inet4Address local, InetAddress gateway, int port, Duration timeout) {
        try {
            externalAddress(local, new InetSocketAddress(gateway, port), timeout);
            return true;
        }
        catch (IOException e) {
            return false;
        }
    }

    static Mapping map(Inet4Address local, int localPort, InetAddress gateway, int port, InetSocketAddress preferredExternal,
                       Duration timeout) throws IOException {
        InetSocketAddress server = new InetSocketAddress(gateway, port);
        int preferredPort = preferredExternal == null? 0: preferredExternal.getPort();
        ByteBuffer response = response(Udp.exchange(local, server, mapRequest(localPort, preferredPort, LIFETIME_SECONDS), timeout), OPCODE_MAP_UDP, 16);
        int privatePort = response.getShort(8) & 0xffff;
        int externalPort = response.getShort(10) & 0xffff;
        long lifetime = response.getInt(12) & 0xffffffffL;
        if (privatePort != localPort || externalPort == 0) {
            throw new IOException("unexpected NAT-PMP mapping response");
        }
        InetAddress externalIp = externalAddress(local, server, timeout);
        return new Mapping(Mapping.Protocol.NAT_PMP, new InetSocketAddress(externalIp, externalPort), Duration.ofSeconds(lifetime),
                () -> Udp.send(local, server, mapRequest(localPort, 0, 0)));
    }
}
