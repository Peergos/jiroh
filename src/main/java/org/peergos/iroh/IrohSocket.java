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
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The single socket of an endpoint, as kwik sees it: datagrams go over UDP, or over a {@link PacketTransport} (e.g.
 * a relay) when addressed to that transport's mapped addresses. kwik only uses {@link DatagramSocket}'s send,
 * receive, local address and close, so presenting the paths as one {@code DatagramSocket} needs no QUIC changes.
 */
public final class IrohSocket extends DatagramSocket implements SegmentedDatagramSocket {

    private final Udp udp;
    private final InetSocketAddress localAddress;
    // Where a zero-length datagram wakes the thread blocked in receive, when a transport delivers a packet.
    private final InetSocketAddress wakeAddress;
    private final List<PacketTransport> transports = new CopyOnWriteArrayList<>();
    // Packets from transports (relays); UDP is read directly by the receiving thread.
    private final Queue<Received> incoming = new ConcurrentLinkedQueue<>();
    private volatile boolean closed;
    // Receive state; only kwik's receiver thread calls receive and moreReceived.
    private Udp.Batch current;
    private int currentOffset;
    private Udp.Batch prefetched;

    private record Received(InetSocketAddress source, byte[] data) {}

    public IrohSocket(InetSocketAddress bindAddress) throws IOException {
        // The superclass socket is never bound or used; every method kwik calls is overridden.
        super((SocketAddress) null);
        udp = Udp.bind(bindAddress);
        localAddress = udp.localAddress();
        InetAddress local = localAddress.getAddress();
        wakeAddress = new InetSocketAddress(local.isAnyLocalAddress()? InetAddress.getLoopbackAddress(): local, localAddress.getPort());
    }

    public void addTransport(PacketTransport transport) {
        transports.add(transport);
        transport.start((source, data, offset, length) -> {
            if (!closed) {
                byte[] copy = new byte[length];
                System.arraycopy(data, offset, copy, 0, length);
                incoming.add(new Received(source, copy));
                wake();
            }
        });
    }

    private void wake() {
        try {
            udp.send(new byte[0], 0, 0, wakeAddress);
        }
        catch (IOException e) {
            // Closed, or the packet is picked up with the next UDP datagram.
        }
    }

    private boolean isWake(Udp.Batch batch) {
        return batch.length() == 0 && batch.source().getPort() == localAddress.getPort();
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
        while (true) {
            Udp.Batch batch = current;
            if (batch != null) {
                int segment = Math.min(batch.segmentSize(), batch.length() - currentOffset);
                DatagramPacket packet = new DatagramPacket(batch.data(), currentOffset, segment, batch.source());
                currentOffset += segment;
                if (currentOffset >= batch.length()) {
                    current = null;
                }
                return packet;
            }
            Received relayed = incoming.poll();
            if (relayed != null) {
                return new DatagramPacket(relayed.data, 0, relayed.data.length, relayed.source);
            }
            if (closed) {
                throw new SocketException("Socket is closed");
            }
            batch = prefetched != null? prefetched: udp.receive(true);
            prefetched = null;
            if (!isWake(batch)) {
                current = batch;
                currentOffset = 0;
            }
        }
    }

    @Override
    public boolean moreReceived() {
        if (current != null || prefetched != null || !incoming.isEmpty()) {
            return true;
        }
        try {
            Udp.Batch batch;
            while ((batch = udp.receive(false)) != null) {
                if (!isWake(batch)) {
                    prefetched = batch;
                    return true;
                }
                if (!incoming.isEmpty()) {
                    return true;
                }
            }
        }
        catch (IOException e) {
            // Closed: the next receive says so.
        }
        return false;
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
        super.close();
    }
}
