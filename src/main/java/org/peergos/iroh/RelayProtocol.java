package org.peergos.iroh;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Duration;

/**
 * The iroh-relay protocol, shared by {@link RelayTransport} and {@link RelayServer}: iroh-relay/src/protos/
 * {common,handshake,relay}.rs. Frames are binary WebSocket messages starting with a QUIC varint frame type.
 */
final class RelayProtocol {

    private RelayProtocol() {}

    static final String RELAY_PATH = "/relay";
    static final String PROBE_PATH = "/ping";
    static final String V1 = "iroh-relay-v1";
    static final String V2 = "iroh-relay-v2";
    static final String[] PROTOCOLS = {V2, V1};
    static final String CLIENT_AUTH_HEADER = "x-iroh-relay-client-auth-v1";
    static final String DOMAIN_SEP_CHALLENGE = "iroh-relay handshake v1 challenge signature";
    static final String DOMAIN_SEP_TLS_EXPORT_LABEL = "iroh-relay handshake v1";
    static final int MAX_FRAME_SIZE = 1024 * 1024;
    static final int MAX_PACKET_SIZE = 64 * 1024;
    static final Duration PING_INTERVAL = Duration.ofSeconds(15);

    // FrameType, iroh-relay/src/protos/common.rs
    static final int SERVER_CHALLENGE = 0;
    static final int CLIENT_AUTH = 1;
    static final int SERVER_CONFIRMS_AUTH = 2;
    static final int SERVER_DENIES_AUTH = 3;
    static final int CLIENT_TO_RELAY_DATAGRAM = 4;
    static final int CLIENT_TO_RELAY_DATAGRAM_BATCH = 5;
    static final int RELAY_TO_CLIENT_DATAGRAM = 6;
    static final int RELAY_TO_CLIENT_DATAGRAM_BATCH = 7;
    static final int ENDPOINT_GONE = 8;
    static final int PING = 9;
    static final int PONG = 10;
    static final int HEALTH = 11;
    static final int RESTARTING = 12;
    static final int STATUS = 13;

    // Status, iroh-relay/src/protos/relay.rs
    static final int STATUS_HEALTHY = 0;
    static final int STATUS_SAME_ENDPOINT_ID_CONNECTED = 1;

    /** The message a client signs to answer a ServerChallenge. */
    static byte[] challengeMessage(byte[] challenge) {
        return Blake3.deriveKey(DOMAIN_SEP_CHALLENGE, challenge);
    }

    static byte[] sign(SecretKey key, byte[] message) {
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

    static boolean verify(EndpointId key, byte[] message, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key.toPublicKey());
            verifier.update(message);
            return verifier.verify(signature);
        }
        catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
        catch (SignatureException | IllegalArgumentException e) {
            return false;
        }
    }

    static EndpointId readEndpointId(ByteBuffer frame) {
        byte[] id = new byte[32];
        frame.get(id);
        return EndpointId.fromBytes(id);
    }

    /** QUIC variable-length integer (RFC 9000 section 16). */
    static long readVarint(ByteBuffer buffer) {
        int first = buffer.get() & 0xff;
        int length = 1 << (first >> 6);
        long value = first & 0x3f;
        for (int i = 1; i < length; i++) {
            value = (value << 8) | (buffer.get() & 0xff);
        }
        return value;
    }

    /** postcard's LEB128 varint. */
    static long readPostcardVarint(ByteBuffer buffer) {
        long value = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            int b = buffer.get() & 0xff;
            value |= (long) (b & 0x7f) << shift;
            if ((b & 0x80) == 0) {
                break;
            }
        }
        return value;
    }

    static void writePostcardVarint(ByteBuffer buffer, long value) {
        while ((value & ~0x7fL) != 0) {
            buffer.put((byte) ((value & 0x7f) | 0x80));
            value >>>= 7;
        }
        buffer.put((byte) value);
    }

    static int postcardVarintLength(long value) {
        int length = 1;
        while ((value >>>= 7) != 0) {
            length++;
        }
        return length;
    }
}
