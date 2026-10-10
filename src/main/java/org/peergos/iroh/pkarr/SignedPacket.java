package org.peergos.iroh.pkarr;

import org.peergos.iroh.EndpointId;
import org.peergos.iroh.SecretKey;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;

/**
 * A pkarr signed packet (pkarr design/base.md): {@code public-key(32) ‖ signature(64) ‖ timestamp(8, BE micros) ‖
 * DNS packet(≤ 1000)}, the signature being BEP44's over {@code 3:seqi<timestamp>e1:v<length>:<dns packet>}.
 */
public final class SignedPacket {

    public static final int MAX_DNS_PACKET_SIZE = 1000;
    private static final int HEADER_SIZE = 32 + 64 + 8;

    private final EndpointId publicKey;
    private final byte[] signature;
    private final long timestamp;
    private final byte[] dnsPacket;
    private final List<DnsPacket.Record> records;

    private SignedPacket(EndpointId publicKey, byte[] signature, long timestamp, byte[] dnsPacket) {
        this.publicKey = publicKey;
        this.signature = signature;
        this.timestamp = timestamp;
        this.dnsPacket = dnsPacket;
        this.records = DnsPacket.decodeAnswers(dnsPacket);
    }

    /**
     * Signs the given records, whose names are relative to the key (e.g. "_iroh"), with the current time in
     * microseconds as timestamp.
     */
    public static SignedPacket sign(SecretKey key, List<DnsPacket.Record> relativeRecords, long timestampMicros) {
        String origin = Z32.encode(key.endpointId().toBytes());
        List<DnsPacket.Record> absolute = relativeRecords.stream()
                .map(r -> new DnsPacket.Record(absoluteName(r.name(), origin), r.type(), r.ttl(), r.rdata()))
                .toList();
        byte[] dns = DnsPacket.encode(absolute);
        if (dns.length > MAX_DNS_PACKET_SIZE) {
            throw new IllegalArgumentException("DNS packet too large: " + dns.length);
        }
        byte[] signature = ed25519Sign(key, signable(timestampMicros, dns));
        return new SignedPacket(key.endpointId(), signature, timestampMicros, dns);
    }

    /**
     * Parses and verifies a packet in its canonical serialization.
     */
    public static SignedPacket fromBytes(byte[] bytes) {
        if (bytes.length < HEADER_SIZE || bytes.length > HEADER_SIZE + MAX_DNS_PACKET_SIZE) {
            throw new IllegalArgumentException("invalid signed packet length " + bytes.length);
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        byte[] key = new byte[32];
        buffer.get(key);
        byte[] signature = new byte[64];
        buffer.get(signature);
        long timestamp = buffer.getLong();
        byte[] dns = new byte[buffer.remaining()];
        buffer.get(dns);
        return fromParts(EndpointId.fromBytes(key), timestamp, signature, dns);
    }

    /**
     * Builds and verifies a packet from the fields of a BEP44 mutable item: k, seq, sig and v.
     */
    public static SignedPacket fromParts(EndpointId publicKey, long timestamp, byte[] signature, byte[] dnsPacket) {
        if (signature.length != 64 || dnsPacket.length > MAX_DNS_PACKET_SIZE) {
            throw new IllegalArgumentException("invalid signed packet");
        }
        if (!ed25519Verify(publicKey, signable(timestamp, dnsPacket), signature)) {
            throw new IllegalArgumentException("invalid signed packet signature");
        }
        return new SignedPacket(publicKey, signature.clone(), timestamp, dnsPacket.clone());
    }

    static byte[] signable(long timestamp, byte[] dnsPacket) {
        byte[] prefix = ("3:seqi" + timestamp + "e1:v" + dnsPacket.length + ":").getBytes(StandardCharsets.US_ASCII);
        byte[] signable = Arrays.copyOf(prefix, prefix.length + dnsPacket.length);
        System.arraycopy(dnsPacket, 0, signable, prefix.length, dnsPacket.length);
        return signable;
    }

    private static String absoluteName(String name, String origin) {
        String trimmed = name.endsWith(".")? name.substring(0, name.length() - 1): name;
        if (trimmed.isEmpty() || trimmed.equals("@")) {
            return origin;
        }
        if (trimmed.equals(origin) || trimmed.endsWith("." + origin)) {
            return trimmed;
        }
        return trimmed + "." + origin;
    }

    public byte[] toBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_SIZE + dnsPacket.length);
        buffer.put(publicKey.toBytes()).put(signature).putLong(timestamp).put(dnsPacket);
        return buffer.array();
    }

    public EndpointId publicKey() {
        return publicKey;
    }

    public long timestamp() {
        return timestamp;
    }

    public byte[] signature() {
        return signature.clone();
    }

    public byte[] dnsPacket() {
        return dnsPacket.clone();
    }

    public List<DnsPacket.Record> records() {
        return records;
    }

    /**
     * The TXT values of the records with the given name relative to the key, e.g. "_iroh".
     */
    public List<String> txt(String relativeName) {
        String name = absoluteName(relativeName, Z32.encode(publicKey.toBytes()));
        return records.stream()
                .filter(r -> r.type() == DnsPacket.TYPE_TXT && r.name().equalsIgnoreCase(name))
                .map(DnsPacket.Record::text)
                .toList();
    }

    private static byte[] ed25519Sign(SecretKey key, byte[] message) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key.keyPair().getPrivate());
            signature.update(message);
            return signature.sign();
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    static boolean ed25519Verify(EndpointId key, byte[] message, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(key.toPublicKey());
            signature.update(message);
            return signature.verify(signatureBytes);
        }
        catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
        catch (SignatureException e) {
            return false;
        }
    }
}
