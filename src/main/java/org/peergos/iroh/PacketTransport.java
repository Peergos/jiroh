package org.peergos.iroh;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * A non-UDP way of carrying QUIC datagrams, such as a relay. Like iroh, each remote reachable over a transport is
 * given a mapped address (see {@link MappedAddresses}), which is all QUIC sees.
 */
public interface PacketTransport {

    /**
     * Whether datagrams to this (mapped) address are carried by this transport.
     */
    boolean handles(InetSocketAddress destination);

    void send(InetSocketAddress destination, byte[] data, int offset, int length) throws IOException;

    /**
     * Called once by the socket; datagrams this transport receives must be passed to the sink.
     */
    void start(PacketSink sink);

    void close();

    interface PacketSink {
        void deliver(InetSocketAddress source, byte[] data, int offset, int length);
    }
}
