package org.peergos.iroh.pkarr;

import org.peergos.iroh.EndpointId;
import org.peergos.iroh.SecretKey;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * What an iroh endpoint publishes about itself (iroh-dns/src/endpoint_info.rs): TXT records under {@code _iroh},
 * one per value, of the form {@code relay=<url>} and {@code addr=<ip:port>}.
 */
public record EndpointInfo(EndpointId endpointId, List<URI> relayUrls, List<InetSocketAddress> directAddresses) {

    public static final String IROH_TXT_NAME = "_iroh";
    public static final int DEFAULT_TTL = 30;

    public SignedPacket toSignedPacket(SecretKey key, long timestampMicros) {
        if (!key.endpointId().equals(endpointId)) {
            throw new IllegalArgumentException("key does not match endpoint id");
        }
        List<DnsPacket.Record> records = new ArrayList<>();
        // iroh orders the attributes relay, addr (its IrohAttr enum order)
        for (URI relay : relayUrls) {
            records.add(DnsPacket.Record.txt(IROH_TXT_NAME, DEFAULT_TTL, "relay=" + relay));
        }
        for (InetSocketAddress address : directAddresses) {
            records.add(DnsPacket.Record.txt(IROH_TXT_NAME, DEFAULT_TTL, "addr=" + format(address)));
        }
        return SignedPacket.sign(key, records, timestampMicros);
    }

    public static EndpointInfo fromSignedPacket(SignedPacket packet) {
        List<URI> relays = new ArrayList<>();
        List<InetSocketAddress> addresses = new ArrayList<>();
        for (String value : packet.txt(IROH_TXT_NAME)) {
            int eq = value.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = value.substring(0, eq);
            String v = value.substring(eq + 1);
            try {
                switch (key) {
                    case "relay" -> relays.add(URI.create(v));
                    case "addr" -> parse(v).ifPresent(addresses::add);
                    default -> { }
                }
            }
            catch (IllegalArgumentException e) {
                // skip values that do not parse, as iroh does
            }
        }
        return new EndpointInfo(packet.publicKey(), List.copyOf(relays), List.copyOf(addresses));
    }

    /** Rust's SocketAddr display: ip:port, or [ipv6]:port. */
    static String format(InetSocketAddress address) {
        String host = address.getAddress().getHostAddress();
        int zone = host.indexOf('%');
        if (zone >= 0) {
            host = host.substring(0, zone);
        }
        if (host.contains(":")) {
            host = "[" + compressIpv6(address.getAddress()) + "]";
        }
        return host + ":" + address.getPort();
    }

    private static String compressIpv6(InetAddress address) {
        // Java prints the full form; Rust (and humans) use RFC 5952's compressed form.
        String full = address.getHostAddress();
        int zone = full.indexOf('%');
        if (zone >= 0) {
            full = full.substring(0, zone);
        }
        String[] groups = full.split(":");
        int bestStart = -1, bestLength = 0;
        for (int i = 0; i < groups.length; ) {
            if (Integer.parseInt(groups[i], 16) == 0) {
                int j = i;
                while (j < groups.length && Integer.parseInt(groups[j], 16) == 0) {
                    j++;
                }
                if (j - i > bestLength && j - i > 1) {
                    bestStart = i;
                    bestLength = j - i;
                }
                i = j;
            }
            else {
                i++;
            }
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < groups.length; i++) {
            if (i == bestStart) {
                out.append(i == 0? "::": ":");
                i += bestLength - 1;
                continue;
            }
            out.append(Integer.toHexString(Integer.parseInt(groups[i], 16)));
            if (i < groups.length - 1) {
                out.append(':');
            }
        }
        return out.toString();
    }

    static java.util.Optional<InetSocketAddress> parse(String value) {
        int colon = value.lastIndexOf(':');
        if (colon < 0) {
            return java.util.Optional.empty();
        }
        String host = value.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        // Only literals: a published address must never cause a DNS lookup.
        if (!host.matches("[0-9a-fA-F:.]+")) {
            return java.util.Optional.empty();
        }
        try {
            int port = Integer.parseInt(value.substring(colon + 1));
            return java.util.Optional.of(new InetSocketAddress(InetAddress.getByName(host), port));
        }
        catch (NumberFormatException | UnknownHostException e) {
            return java.util.Optional.empty();
        }
    }
}
