package org.peergos.iroh;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The relay's X.509 certificate and key, which can be replaced while the relay runs (as ACME renewals do). The
 * HTTPS listener picks up a new certificate for the next handshake.
 */
public final class RelayCertificate {

    private static final String ALIAS = "relay";

    private record Credentials(PrivateKey key, X509Certificate[] chain) {}

    private volatile Credentials current;
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private volatile SSLContext sslContext;

    private RelayCertificate(Credentials current) {
        this.current = current;
    }

    /** No certificate yet: TLS handshakes fail until {@link #update} is called, except ACME challenges. */
    public static RelayCertificate empty() {
        return new RelayCertificate(null);
    }

    public static RelayCertificate of(PrivateKey key, X509Certificate[] chain) {
        return new RelayCertificate(new Credentials(key, chain.clone()));
    }

    /** A PEM certificate chain and a PEM PKCS#8 private key (EC, RSA or Ed25519). */
    public static RelayCertificate fromPem(Path certificateChain, Path privateKey) throws IOException, GeneralSecurityException {
        return of(readPrivateKey(privateKey), readChain(certificateChain));
    }

    public static X509Certificate[] readChain(Path pem) throws IOException, GeneralSecurityException {
        try (InputStream in = Files.newInputStream(pem)) {
            X509Certificate[] chain = CertificateFactory.getInstance("X.509").generateCertificates(in).stream()
                    .map(c -> (X509Certificate) c).toArray(X509Certificate[]::new);
            if (chain.length == 0) {
                throw new GeneralSecurityException("no certificates in " + pem);
            }
            return chain;
        }
    }

    public static PrivateKey readPrivateKey(Path pem) throws IOException, GeneralSecurityException {
        String text = Files.readString(pem);
        String begin = "-----BEGIN PRIVATE KEY-----";
        int start = text.indexOf(begin);
        int end = text.indexOf("-----END PRIVATE KEY-----");
        if (start < 0 || end < 0) {
            throw new GeneralSecurityException(pem + " is not a PKCS#8 private key (convert it with openssl pkcs8 -topk8 -nocrypt)");
        }
        byte[] der = Base64.getMimeDecoder().decode(text.substring(start + begin.length(), end));
        for (String algorithm : new String[]{"EC", "RSA", "Ed25519"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
            }
            catch (GeneralSecurityException wrongAlgorithm) {
                // try the next
            }
        }
        throw new GeneralSecurityException("unsupported private key in " + pem);
    }

    public void update(PrivateKey key, X509Certificate[] chain) {
        current = new Credentials(key, chain.clone());
        listeners.forEach(Runnable::run);
    }

    public Optional<X509Certificate[]> chain() {
        Credentials credentials = current;
        return credentials == null? Optional.empty(): Optional.of(credentials.chain().clone());
    }

    /** Called after each {@link #update}. */
    public void onChange(Runnable listener) {
        listeners.add(listener);
    }

    synchronized SSLContext sslContext() throws GeneralSecurityException {
        if (sslContext == null) {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(new KeyManager[]{new KeyManagerImpl()}, null, null);
            sslContext = context;
        }
        return sslContext;
    }

    private final class KeyManagerImpl extends X509ExtendedKeyManager {

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            Credentials credentials = current;
            return credentials != null && keyTypeMatches(keyType, credentials.key())? ALIAS: null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            Credentials credentials = current;
            return credentials != null && keyTypeMatches(keyType, credentials.key())? ALIAS: null;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            Credentials credentials = credentials(alias);
            return credentials == null? null: credentials.chain().clone();
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            Credentials credentials = credentials(alias);
            return credentials == null? null: credentials.key();
        }

        private Credentials credentials(String alias) {
            return ALIAS.equals(alias)? current: null;
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            Credentials credentials = current;
            return credentials != null && keyTypeMatches(keyType, credentials.key())? new String[]{ALIAS}: null;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return null;
        }
    }

    private static boolean keyTypeMatches(String keyType, PrivateKey key) {
        return switch (key.getAlgorithm()) {
            case "EC" -> keyType.equals("EC");
            case "RSA" -> keyType.equals("RSA") || keyType.equals("RSASSA-PSS");
            case "Ed25519", "EdDSA" -> keyType.equals("EdDSA") || keyType.equals("Ed25519");
            default -> keyType.equals(key.getAlgorithm());
        };
    }
}
