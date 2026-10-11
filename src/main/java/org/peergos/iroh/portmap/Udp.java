package org.peergos.iroh.portmap;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.Arrays;

/** One-shot UDP requests to the gateway, from a fresh socket on the local address. */
final class Udp {

    private Udp() {}

    static byte[] exchange(Inet4Address local, InetSocketAddress server, byte[] request, Duration timeout) throws IOException {
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(local, 0))) {
            socket.connect(server);
            socket.setSoTimeout((int) timeout.toMillis());
            socket.send(new DatagramPacket(request, request.length));
            byte[] buffer = new byte[1100];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(packet);
            }
            catch (SocketTimeoutException e) {
                throw new IOException("no response from " + server, e);
            }
            return Arrays.copyOf(buffer, packet.getLength());
        }
    }

    static void send(Inet4Address local, InetSocketAddress server, byte[] request) throws IOException {
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(local, 0))) {
            socket.send(new DatagramPacket(request, request.length, server));
        }
    }
}
