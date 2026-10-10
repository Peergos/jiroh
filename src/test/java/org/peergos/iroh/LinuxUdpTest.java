package org.peergos.iroh;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class LinuxUdpTest {

    private record Datagram(InetSocketAddress source, int length, byte first) {}

    @Test
    void segmentedSendShouldArriveAsSeparateDatagrams() throws Exception {
        Assumptions.assumeTrue(LinuxUdp.isAvailable(), "native UDP not available");
        exchange(LinuxUdp.bind(loopback()), LinuxUdp.bind(loopback()));
    }

    @Test
    void segmentedSendShouldReachNioSocket() throws Exception {
        Assumptions.assumeTrue(LinuxUdp.isAvailable(), "native UDP not available");
        exchange(LinuxUdp.bind(loopback()), new Udp.Nio(loopback()));
    }

    @Test
    void nioSocketShouldSendSegmentsOneByOne() throws Exception {
        exchange(new Udp.Nio(loopback()), new Udp.Nio(loopback()));
    }

    private static void exchange(Udp sender, Udp receiver) throws Exception {
        Thread reader;
        try (sender; receiver) {
            BlockingQueue<Datagram> received = new LinkedBlockingQueue<>();
            reader = Thread.ofPlatform().daemon().start(() -> {
                try {
                    receiver.receiveLoop((source, data, length, segmentSize, more) -> {
                        for (int offset = 0; offset < length; offset += segmentSize) {
                            received.add(new Datagram(source, Math.min(segmentSize, length - offset), data[offset]));
                        }
                    });
                }
                catch (Exception e) {
                    // closed
                }
            });
            byte[] data = new byte[3 * 1000 + 500];
            for (int i = 0; i < 4; i++) {
                data[i * 1000] = (byte) i;
            }
            sender.sendSegmented(data, 0, data.length, 1000, receiver.localAddress());
            for (Datagram expected : List.of(new Datagram(sender.localAddress(), 1000, (byte) 0),
                    new Datagram(sender.localAddress(), 1000, (byte) 1), new Datagram(sender.localAddress(), 1000, (byte) 2),
                    new Datagram(sender.localAddress(), 500, (byte) 3))) {
                assertEquals(expected, received.poll(5, TimeUnit.SECONDS));
            }
        }
        // Closing must wake the blocked reader.
        reader.join(2000);
        assertFalse(reader.isAlive());
    }

    private static InetSocketAddress loopback() {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
    }
}
