package org.peergos.iroh;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.util.HexFormat;

/**
 * An iroh secret key: a 32-byte Ed25519 seed (RFC 8032), from which the endpoint id is derived.
 */
public final class SecretKey {

    private final byte[] seed;
    private final KeyPair keyPair;

    private SecretKey(byte[] seed) {
        if (seed.length != 32) {
            throw new IllegalArgumentException("secret key must be 32 bytes");
        }
        this.seed = seed.clone();
        this.keyPair = deriveKeyPair(this.seed);
    }

    public static SecretKey generate() {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        return new SecretKey(seed);
    }

    public static SecretKey fromBytes(byte[] seed) {
        return new SecretKey(seed);
    }

    public static SecretKey fromHex(String hex) {
        return new SecretKey(HexFormat.of().parseHex(hex));
    }

    public EndpointId endpointId() {
        return EndpointId.fromPublicKey(keyPair.getPublic());
    }

    public KeyPair keyPair() {
        return keyPair;
    }

    public byte[] toBytes() {
        return seed.clone();
    }

    // JCA has no API to derive an Ed25519 public key from a seed, but the key pair generator takes the seed from its
    // source of randomness, as RFC 8032 section 5.1.5 specifies.
    private static KeyPair deriveKeyPair(byte[] seed) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            generator.initialize(NamedParameterSpec.ED25519, new FixedRandom(seed));
            return generator.generateKeyPair();
        }
        catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class FixedRandom extends SecureRandom {
        private final byte[] bytes;

        FixedRandom(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public void nextBytes(byte[] out) {
            if (out.length != bytes.length) {
                throw new IllegalStateException("unexpected request for " + out.length + " random bytes");
            }
            System.arraycopy(bytes, 0, out, 0, bytes.length);
        }
    }
}
