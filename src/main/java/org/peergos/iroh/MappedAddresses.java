package org.peergos.iroh;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Mapped addresses as iroh uses them: IPv6 Unique Local Addresses that stand for a non-IP path, so QUIC can address
 * it. Relay paths are in fd15:70a:510b:1::/64, with a fixed dummy port.
 */
public final class MappedAddresses {

    public static final int MAPPED_PORT = 12345;

    private static final byte[] RELAY_PREFIX = {(byte) 0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x01};
    private static final SecureRandom RANDOM = new SecureRandom();

    private MappedAddresses() {}

    /**
     * A new relay mapped address; the host bits are random so a remote cannot guess a live one.
     */
    public static InetSocketAddress newRelayMapped() {
        byte[] address = Arrays.copyOf(RELAY_PREFIX, 16);
        byte[] host = new byte[8];
        RANDOM.nextBytes(host);
        System.arraycopy(host, 0, address, 8, 8);
        try {
            return new InetSocketAddress(InetAddress.getByAddress(address), MAPPED_PORT);
        }
        catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    public static boolean isRelayMapped(InetSocketAddress address) {
        return address.getAddress() instanceof Inet6Address
                && Arrays.equals(address.getAddress().getAddress(), 0, 8, RELAY_PREFIX, 0, 8);
    }
}
