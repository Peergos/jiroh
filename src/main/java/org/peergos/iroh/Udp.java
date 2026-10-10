package org.peergos.iroh;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The endpoint's UDP socket: {@link LinuxUdp} (segmentation offload) where available, else a DatagramChannel. */
interface Udp extends AutoCloseable {

    interface Sink {
        /**
         * Datagrams received together from one source: segmentSize bytes each, the last possibly shorter. The sink
         * owns {@code data}. {@code more} tells whether more were already queued in the socket.
         */
        void received(InetSocketAddress source, byte[] data, int length, int segmentSize, boolean more);
    }

    InetSocketAddress localAddress();

    void send(byte[] data, int offset, int length, InetSocketAddress destination) throws IOException;

    default int maxSegments() {
        return 1;
    }

    default void sendSegmented(byte[] data, int offset, int length, int segmentSize, InetSocketAddress destination) throws IOException {
        for (int end = offset + length; offset < end; offset += segmentSize) {
            send(data, offset, Math.min(segmentSize, end - offset), destination);
        }
    }

    /** Receives datagrams until the socket is closed. */
    void receiveLoop(Sink sink) throws IOException;

    @Override
    void close();

    static Udp bind(InetSocketAddress bindAddress) throws IOException {
        if (LinuxUdp.isAvailable()) {
            try {
                return LinuxUdp.bind(bindAddress);
            }
            catch (IOException | RuntimeException e) {
                Logger.getLogger(Udp.class.getName()).log(Level.FINE, "native UDP unavailable", e);
            }
        }
        return new Nio(bindAddress);
    }

    final class Nio implements Udp {
        private final DatagramChannel channel;
        private final InetSocketAddress localAddress;

        Nio(InetSocketAddress bindAddress) throws IOException {
            channel = DatagramChannel.open();
            channel.bind(bindAddress);
            localAddress = (InetSocketAddress) channel.getLocalAddress();
        }

        @Override
        public InetSocketAddress localAddress() {
            return localAddress;
        }

        @Override
        public void send(byte[] data, int offset, int length, InetSocketAddress destination) throws IOException {
            channel.send(ByteBuffer.wrap(data, offset, length), destination);
        }

        @Override
        public void receiveLoop(Sink sink) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(65536);
            try {
                while (true) {
                    buffer.clear();
                    InetSocketAddress source = (InetSocketAddress) channel.receive(buffer);
                    int length = buffer.position();
                    sink.received(source, Arrays.copyOf(buffer.array(), length), length, length, false);
                }
            }
            catch (ClosedChannelException e) {
                // closed
            }
        }

        @Override
        public void close() {
            try {
                channel.close();
            }
            catch (IOException e) {
                // ignore
            }
        }
    }
}
