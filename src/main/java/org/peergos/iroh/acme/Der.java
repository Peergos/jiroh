package org.peergos.iroh.acme;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * The DER the JDK has no public API for: a PKCS#10 certificate signing request, and the self-signed certificate
 * of an ACME tls-alpn-01 challenge. Keys are EC P-256, signed with ecdsa-with-SHA256.
 */
final class Der {

    private Der() {}

    private static final byte[] ECDSA_WITH_SHA256 = sequence(oid("1.2.840.10045.4.3.2"));
    private static final String SUBJECT_ALT_NAME = "2.5.29.17";
    private static final String EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
    private static final String COMMON_NAME = "2.5.4.3";
    /** RFC 8737 section 6.1. */
    private static final String ACME_IDENTIFIER = "1.3.6.1.5.5.7.1.31";

    static byte[] csr(KeyPair key, List<String> domains) throws GeneralSecurityException {
        byte[] extensions = sequence(extension(SUBJECT_ALT_NAME, false, subjectAltNames(domains)));
        byte[] attribute = sequence(oid(EXTENSION_REQUEST), tagged(0x31, extensions));
        byte[] info = sequence(
                integer(BigInteger.ZERO),
                name(domains.get(0)),
                key.getPublic().getEncoded(),
                tagged(0xa0, attribute));
        return signed(info, key);
    }

    static X509Certificate tlsAlpnChallengeCertificate(KeyPair key, String domain, byte[] keyAuthorizationDigest) throws GeneralSecurityException {
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        byte[] extensions = sequence(
                extension(SUBJECT_ALT_NAME, false, subjectAltNames(List.of(domain))),
                extension(ACME_IDENTIFIER, true, tagged(0x04, keyAuthorizationDigest)));
        byte[] tbs = sequence(
                tagged(0xa0, integer(BigInteger.TWO)),
                integer(new BigInteger(64, new java.security.SecureRandom())),
                ECDSA_WITH_SHA256,
                name(domain),
                sequence(utcTime(now.minusDays(1)), utcTime(now.plusDays(7))),
                name(domain),
                key.getPublic().getEncoded(),
                tagged(0xa3, extensions));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(signed(tbs, key)));
    }

    private static byte[] signed(byte[] content, KeyPair key) throws GeneralSecurityException {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(key.getPrivate());
        signer.update(content);
        byte[] signature = signer.sign();
        byte[] bits = new byte[signature.length + 1];
        System.arraycopy(signature, 0, bits, 1, signature.length);
        return sequence(content, ECDSA_WITH_SHA256, tagged(0x03, bits));
    }

    private static byte[] subjectAltNames(List<String> domains) {
        byte[][] names = new byte[domains.size()][];
        for (int i = 0; i < names.length; i++) {
            names[i] = tagged(0x82, domains.get(i).getBytes(StandardCharsets.US_ASCII));
        }
        return sequence(names);
    }

    private static byte[] extension(String oid, boolean critical, byte[] value) {
        return critical
                ? sequence(oid(oid), new byte[]{0x01, 0x01, (byte) 0xff}, tagged(0x04, value))
                : sequence(oid(oid), tagged(0x04, value));
    }

    private static byte[] name(String commonName) {
        byte[] attribute = sequence(oid(COMMON_NAME), tagged(0x0c, commonName.getBytes(StandardCharsets.UTF_8)));
        return sequence(tagged(0x31, attribute));
    }

    private static byte[] utcTime(ZonedDateTime time) {
        return tagged(0x17, time.format(DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'")).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] integer(BigInteger value) {
        return tagged(0x02, value.toByteArray());
    }

    static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]));
        for (int i = 2; i < parts.length; i++) {
            long value = Long.parseLong(parts[i]);
            int groups = 1;
            for (long v = value >>> 7; v != 0; v >>>= 7) {
                groups++;
            }
            for (int g = groups - 1; g >= 0; g--) {
                int b = (int) ((value >>> (7 * g)) & 0x7f);
                out.write(g == 0? b: b | 0x80);
            }
        }
        return tagged(0x06, out.toByteArray());
    }

    static byte[] sequence(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return tagged(0x30, out.toByteArray());
    }

    static byte[] tagged(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int length = content.length;
        if (length < 128) {
            out.write(length);
        }
        else {
            int bytes = (32 - Integer.numberOfLeadingZeros(length) + 7) / 8;
            out.write(0x80 | bytes);
            for (int i = bytes - 1; i >= 0; i--) {
                out.write(length >>> (8 * i));
            }
        }
        out.writeBytes(content);
        return out.toByteArray();
    }
}
