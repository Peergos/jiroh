package org.peergos.iroh;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * A PCP and NAT-PMP server for nat-test.sh's NAT namespace: each UDP MAP request becomes an nft DNAT rule from the
 * NAT's public address to the requester. Usage: PortMappingGateway lan-address public-address
 */
public final class PortMappingGateway {

    public static void main(String[] args) throws Exception {
        InetAddress lan = InetAddress.getByName(args[0]);
        InetAddress external = InetAddress.getByName(args[1]);
        Map<String, Integer> mapped = new HashMap<>();
        int nextPort = 30000;
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(lan, 5351))) {
            System.out.println("port mapping gateway on " + socket.getLocalSocketAddress());
            byte[] buffer = new byte[1100];
            while (true) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                ByteBuffer request = ByteBuffer.wrap(buffer, 0, packet.getLength());
                InetSocketAddress client = (InetSocketAddress) packet.getSocketAddress();
                ByteBuffer response;
                if (request.get(0) == 2) {
                    int opcode = request.get(1);
                    long lifetime = request.getInt(4) & 0xffffffffL;
                    response = ByteBuffer.allocate(opcode == 1? 60: 24);
                    response.put((byte) 2).put((byte) (0x80 | opcode)).put((byte) 0).put((byte) 0);
                    if (opcode == 1) {
                        int localPort = request.getShort(40) & 0xffff;
                        String target = client.getAddress().getHostAddress() + ":" + localPort;
                        Integer port = mapped.get(target);
                        if (port == null && lifetime > 0) {
                            port = nextPort++;
                            nft("add rule ip nat prerouting iifname wan udp dport " + port + " dnat to " + target);
                            mapped.put(target, port);
                            System.out.println("PCP mapped " + external.getHostAddress() + ":" + port + " -> " + target);
                        }
                        byte[] nonce = new byte[12];
                        request.get(24, nonce);
                        response.putInt((int) Math.min(lifetime, 3600)).putInt(1).put(new byte[12]);
                        response.put(nonce).put((byte) 17).put(new byte[3]).putShort((short) localPort)
                                .putShort((short) (port == null? 0: port)).put(new byte[10]).put((byte) 0xff).put((byte) 0xff)
                                .put(external.getAddress());
                    }
                    else {
                        response.putInt(0).putInt(1).put(new byte[12]);
                    }
                }
                else if (request.get(1) == 0) {
                    response = ByteBuffer.allocate(12).put((byte) 0).put((byte) 0x80).putShort((short) 0).putInt(1)
                            .put(external.getAddress());
                }
                else {
                    response = ByteBuffer.allocate(8).put((byte) 0).put((byte) (0x80 | request.get(1))).putShort((short) 5).putInt(1);
                }
                socket.send(new DatagramPacket(response.array(), response.position(), client));
            }
        }
    }

    private static void nft(String command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(("nft " + command).split(" ")).inheritIO().start();
        if (process.waitFor() != 0) {
            throw new IOException("nft " + command + " failed");
        }
    }
}
