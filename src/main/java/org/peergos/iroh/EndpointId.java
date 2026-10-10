package org.peergos.iroh;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * An iroh endpoint id: the 32-byte Ed25519 public key of an endpoint. It is also what the endpoint presents as its
 * raw public key (RFC 7250) in the TLS handshake, so a successful handshake proves the remote holds the key.
 */
public final class EndpointId {

    // DER prefix of an Ed25519 SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (33 bytes) }
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    private final byte[] key;

    private EndpointId(byte[] key) {
        if (key.length != 32) {
            throw new IllegalArgumentException("endpoint id must be 32 bytes");
        }
        this.key = key.clone();
    }

    public static EndpointId fromBytes(byte[] key) {
        return new EndpointId(key);
    }

    public static EndpointId fromHex(String hex) {
        return new EndpointId(HexFormat.of().parseHex(hex));
    }

    public static EndpointId fromPublicKey(PublicKey publicKey) {
        if (!(publicKey instanceof EdECPublicKey edKey) || !"Ed25519".equals(edKey.getParams().getName())) {
            throw new IllegalArgumentException("not an Ed25519 public key");
        }
        byte[] spki = publicKey.getEncoded();
        if (spki.length != SPKI_PREFIX.length + 32 || !Arrays.equals(spki, 0, SPKI_PREFIX.length, SPKI_PREFIX, 0, SPKI_PREFIX.length)) {
            throw new IllegalArgumentException("unexpected Ed25519 key encoding");
        }
        return new EndpointId(Arrays.copyOfRange(spki, SPKI_PREFIX.length, spki.length));
    }

    public PublicKey toPublicKey() {
        byte[] spki = new byte[SPKI_PREFIX.length + 32];
        System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
        System.arraycopy(key, 0, spki, SPKI_PREFIX.length, 32);
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Whether the given key, e.g. the raw public key a peer authenticated with, is this endpoint id.
     */
    public boolean matches(PublicKey publicKey) {
        try {
            return equals(fromPublicKey(publicKey));
        }
        catch (IllegalArgumentException e) {
            return false;
        }
    }

    public byte[] toBytes() {
        return key.clone();
    }

    public String toHex() {
        return HexFormat.of().formatHex(key);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof EndpointId other && Arrays.equals(key, other.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }

    @Override
    public String toString() {
        return toHex();
    }
}
