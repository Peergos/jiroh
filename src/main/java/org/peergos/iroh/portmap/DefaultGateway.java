package org.peergos.iroh.portmap;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/** The IPv4 default gateway, and the local address used to reach it. */
record DefaultGateway(Inet4Address gateway, Inet4Address local) {

    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    static Optional<DefaultGateway> find() {
        Optional<Inet4Address> gateway = linux().or(DefaultGateway::netstat);
        return gateway.flatMap(g -> localAddressTowards(g).map(local -> new DefaultGateway(g, local)));
    }

    /** /proc/net/route: the gateway of the default route, little-endian hex. */
    static Optional<Inet4Address> linux() {
        try {
            return parseProcNetRoute(Files.readAllLines(Path.of("/proc/net/route")));
        }
        catch (IOException e) {
            return Optional.empty();
        }
    }

    static Optional<Inet4Address> parseProcNetRoute(List<String> lines) {
        for (String line : lines.subList(Math.min(1, lines.size()), lines.size())) {
            String[] fields = line.trim().split("\\s+");
            if (fields.length < 4 || !fields[1].equals("00000000")) {
                continue;
            }
            int flags = Integer.parseInt(fields[3], 16);
            if ((flags & 0x3) != 0x3) { // RTF_UP | RTF_GATEWAY
                continue;
            }
            long gateway = Long.parseLong(fields[2], 16);
            byte[] ip = {(byte) gateway, (byte) (gateway >> 8), (byte) (gateway >> 16), (byte) (gateway >> 24)};
            try {
                return Optional.of((Inet4Address) InetAddress.getByAddress(ip));
            }
            catch (IOException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    /** `netstat -rn` on macOS, the BSDs and Windows: the first non-zero IPv4 address on the default route's line. */
    static Optional<Inet4Address> netstat() {
        try {
            Process process = new ProcessBuilder("netstat", "-rn").redirectErrorStream(true).start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            process.waitFor(5, TimeUnit.SECONDS);
            return parseNetstat(output);
        }
        catch (IOException e) {
            return Optional.empty();
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    static Optional<Inet4Address> parseNetstat(String output) {
        for (String line : output.split("\\R")) {
            String[] fields = line.trim().split("\\s+");
            if (fields.length < 2 || !(fields[0].equals("default") || fields[0].equals("0.0.0.0"))) {
                continue;
            }
            for (int i = 1; i < fields.length; i++) {
                if (IPV4.matcher(fields[i]).matches() && !fields[i].equals("0.0.0.0")) {
                    try {
                        return Optional.of((Inet4Address) InetAddress.getByName(fields[i]));
                    }
                    catch (IOException e) {
                        break;
                    }
                }
            }
        }
        return Optional.empty();
    }

    static Optional<Inet4Address> localAddressTowards(Inet4Address gateway) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(new InetSocketAddress(gateway, Pcp.SERVER_PORT));
            return socket.getLocalAddress() instanceof Inet4Address local && !local.isAnyLocalAddress()? Optional.of(local): Optional.empty();
        }
        catch (IOException e) {
            return Optional.empty();
        }
    }
}
