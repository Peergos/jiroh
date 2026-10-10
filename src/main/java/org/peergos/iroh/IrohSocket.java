package org.peergos.iroh;

import tech.kwik.core.socket.SegmentedDatagramSocket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * The single socket of an endpoint, as kwik sees it: datagrams go over UDP, or over a {@link PacketTransport} (e.g.
 * a relay) when addressed to that transport's mapped addresses. kwik only uses {@link DatagramSocket}'s send,
 * receive, local address and close, so presenting the paths as one {@code DatagramSocket} needs no QUIC changes.
 */
public final class IrohSocket extends DatagramSocket implements SegmentedDatagramSocket {

    private static final Received CLOSED = new Received(null, null, 0, 0, false);

    private final Udp udp;
    private final InetSocketAddress localAddress;
    private final List<PacketTransport> transports = new CopyOnWriteArrayList<>();
    private final BlockingQueue<Received> incoming = new LinkedBlockingQueue<>();
    private final Thread udpReader;
    private volatile boolean closed;
    // The batch being handed out by receive(), which only kwik's receiver thread calls.
    private Received current;
    private int currentOffset;
    private boolean lastBatchHadMore;

    private record Received(InetSocketAddress source, byte[] data, int length, int segmentSize, boolean more) {}

    public IrohSocket(InetSocketAddress bindAddress) throws IOException {
        // The superclass socket is never bound or used; every method kwik calls is overridden.
        super((SocketAddress) null);
        udp = Udp.bind(bindAddress);
        localAddress = udp.localAddress();
        // A platform thread: the native socket blocks in recvmsg, which would pin a virtual thread's carrier.
        udpReader = Thread.ofPlatform().daemon().name("iroh-udp-" + localAddress.getPort()).start(this::readUdp);
    }

    public void addTransport(PacketTransport transport) {
        transports.add(transport);
        transport.start((source, data, offset, length) -> {
            if (!closed) {
                byte[] copy = new byte[length];
                System.arraycopy(data, offset, copy, 0, length);
                incoming.add(new Received(source, copy, length, length, false));
            }
        });
    }

    private void readUdp() {
        try {
            udp.receiveLoop((source, data, length, segmentSize, more) -> incoming.add(new Received(source, data, length, segmentSize, more)));
        }
        catch (IOException e) {
            if (!closed) {
                close();
            }
        }
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        if (closed) {
            throw new SocketException("Socket is closed");
        }
        InetSocketAddress destination = (InetSocketAddress) packet.getSocketAddress();
        for (PacketTransport transport : transports) {
            if (transport.handles(destination)) {
                transport.send(destination, packet.getData(), packet.getOffset(), packet.getLength());
                return;
            }
        }
        udp.send(packet.getData(), packet.getOffset(), packet.getLength(), destination);
    }

    @Override
    public int maxSegments() {
        return udp.maxSegments();
    }

    @Override
    public void sendSegmented(byte[] data, int offset, int length, int segmentSize, InetSocketAddress destination) throws IOException {
        if (closed) {
            throw new SocketException("Socket is closed");
        }
        for (PacketTransport transport : transports) {
            if (transport.handles(destination)) {
                for (int end = offset + length; offset < end; offset += segmentSize) {
                    transport.send(destination, data, offset, Math.min(segmentSize, end - offset));
                }
                return;
            }
        }
        udp.sendSegmented(data, offset, length, segmentSize, destination);
    }

    @Override
    public void receive(DatagramPacket packet) throws IOException {
        DatagramPacket next = receive();
        int length = Math.min(next.getLength(), packet.getData().length - packet.getOffset());
        System.arraycopy(next.getData(), next.getOffset(), packet.getData(), packet.getOffset(), length);
        packet.setLength(length);
        packet.setSocketAddress(next.getSocketAddress());
    }

    @Override
    public DatagramPacket receive() throws IOException {
        if (current == null) {
            Received received;
            try {
                received = incoming.take();
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SocketException("interrupted");
            }
            if (received == CLOSED) {
                incoming.add(CLOSED);
                throw new SocketException("Socket is closed");
            }
            current = received;
            currentOffset = 0;
        }
        Received received = current;
        int segment = Math.min(received.segmentSize, received.length - currentOffset);
        DatagramPacket packet = new DatagramPacket(received.data, currentOffset, segment, received.source);
        currentOffset += segment;
        if (currentOffset >= received.length) {
            current = null;
            lastBatchHadMore = received.more;
        }
        return packet;
    }

    @Override
    public boolean moreReceived() {
        return current != null || lastBatchHadMore || !incoming.isEmpty();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return localAddress;
    }

    @Override
    public InetAddress getLocalAddress() {
        return localAddress.getAddress();
    }

    @Override
    public int getLocalPort() {
        return localAddress.getPort();
    }

    @Override
    public boolean isBound() {
        return true;
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        transports.forEach(PacketTransport::close);
        udp.close();
        incoming.add(CLOSED);
        super.close();
    }
}
