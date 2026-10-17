package org.peergos.iroh.acme;

import org.peergos.iroh.RelayCertificate;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Keeps a {@link RelayCertificate} issued and renewed by an ACME CA, as iroh-relay's LetsEncrypt cert mode does.
 * The certificate, its key and the account key are kept in a directory, so a restart reuses them. A certificate is
 * renewed when a third of its lifetime is left; failures are retried with backoff.
 */
public final class AcmeCertificates implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(AcmeCertificates.class.getName());
    private static final Duration CHECK_INTERVAL = Duration.ofHours(12);
    private static final Duration MIN_RETRY = Duration.ofMinutes(1);
    private static final Duration MAX_RETRY = Duration.ofHours(6);
    private static final Duration ORDER_TIMEOUT = Duration.ofMinutes(5);

    /**
     * @param directory       the ACME directory, e.g. {@link AcmeClient#LETS_ENCRYPT}
     * @param contact         e.g. mailto:admin@example.com
     * @param challengeTypes  in order of preference; those the relay cannot serve are skipped
     * @param acmeTls         for the ACME server's certificate (a test CA), or null for the default trust store
     */
    public record Config(URI directory, List<String> domains, List<String> contact, Path cacheDir,
                         List<String> challengeTypes, SSLContext acmeTls) {
        public Config {
            if (domains.isEmpty()) {
                throw new IllegalArgumentException("ACME needs at least one domain");
            }
            domains = List.copyOf(domains);
            contact = List.copyOf(contact);
            challengeTypes = List.copyOf(challengeTypes);
        }

        public Config(URI directory, List<String> domains, List<String> contact, Path cacheDir) {
            this(directory, domains, contact, cacheDir, List.of(AcmeClient.TLS_ALPN_01, AcmeClient.HTTP_01), null);
        }
    }

    private final Config config;
    private final RelayCertificate target;
    private final ChallengeResponder responder;
    private final Path certificateFile;
    private final Path keyFile;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "iroh-relay-acme");
        thread.setDaemon(true);
        return thread;
    });
    private AcmeClient client;
    private Duration retry = MIN_RETRY;

    private AcmeCertificates(Config config, RelayCertificate target, ChallengeResponder responder) {
        this.config = config;
        this.target = target;
        this.responder = responder;
        this.certificateFile = config.cacheDir().resolve("cert.pem");
        this.keyFile = config.cacheDir().resolve("cert.key");
    }

    /**
     * Installs a cached certificate if there is one for these domains, then checks in the background whether one
     * must be ordered, and again every 12 hours.
     */
    public static AcmeCertificates start(Config config, RelayCertificate target, ChallengeResponder responder) throws IOException {
        Files.createDirectories(config.cacheDir());
        AcmeCertificates certificates = new AcmeCertificates(config, target, responder);
        certificates.loadCached();
        certificates.scheduler.execute(certificates::check);
        return certificates;
    }

    private void loadCached() {
        if (!Files.exists(certificateFile) || !Files.exists(keyFile)) {
            return;
        }
        try {
            X509Certificate[] chain = RelayCertificate.readChain(certificateFile);
            if (!covers(chain[0], config.domains())) {
                LOG.info("ACME: cached certificate is for other domains, ordering a new one");
                return;
            }
            if (Instant.now().isAfter(chain[0].getNotAfter().toInstant())) {
                return;
            }
            target.update(RelayCertificate.readPrivateKey(keyFile), chain);
            LOG.info("ACME: using cached certificate valid until " + chain[0].getNotAfter().toInstant());
        }
        catch (IOException | GeneralSecurityException e) {
            LOG.log(Level.WARNING, "ACME: could not read the cached certificate", e);
        }
    }

    /** Whether the certificate in use needs replacing: missing, for other domains, or in the last third of its life. */
    boolean needsRenewal() {
        return target.chain().map(chain -> {
            X509Certificate leaf = chain[0];
            if (!covers(leaf, config.domains())) {
                return true;
            }
            Instant notBefore = leaf.getNotBefore().toInstant();
            Instant notAfter = leaf.getNotAfter().toInstant();
            Duration lifetime = Duration.between(notBefore, notAfter);
            return Instant.now().isAfter(notAfter.minus(lifetime.dividedBy(3)));
        }).orElse(true);
    }

    private void check() {
        try {
            if (needsRenewal()) {
                renew();
            }
            retry = MIN_RETRY;
            scheduler.schedule(this::check, CHECK_INTERVAL.toMillis(), TimeUnit.MILLISECONDS);
        }
        catch (Exception e) {
            LOG.log(Level.WARNING, "ACME: ordering a certificate for " + config.domains() + " failed, retrying in " + retry, e);
            scheduler.schedule(this::check, retry.toMillis(), TimeUnit.MILLISECONDS);
            retry = retry.multipliedBy(2).compareTo(MAX_RETRY) > 0? MAX_RETRY: retry.multipliedBy(2);
        }
    }

    /** Orders a certificate now, installs it and caches it. */
    public void renew() throws IOException, GeneralSecurityException {
        if (client == null) {
            client = new AcmeClient(config.directory(), accountKey(), config.contact(), config.acmeTls());
        }
        KeyPair key = AcmeClient.newKey();
        X509Certificate[] chain = client.issue(config.domains(), key, responder, config.challengeTypes(), ORDER_TIMEOUT);
        RelayCertificate.writePem(certificateFile, chain, keyFile, key.getPrivate());
        target.update(key.getPrivate(), chain);
        LOG.info("ACME: new certificate for " + config.domains() + " valid until " + chain[0].getNotAfter().toInstant());
    }

    /** The account key, kept as a PKCS#8 private key followed by its X.509 public key. */
    private KeyPair accountKey() throws IOException, GeneralSecurityException {
        Path file = config.cacheDir().resolve("account.key");
        if (Files.exists(file)) {
            String pem = Files.readString(file);
            String begin = "-----BEGIN PUBLIC KEY-----";
            int start = pem.indexOf(begin);
            int end = pem.indexOf("-----END PUBLIC KEY-----");
            if (start < 0 || end < 0) {
                throw new GeneralSecurityException(file + " has no public key");
            }
            byte[] der = Base64.getMimeDecoder().decode(pem.substring(start + begin.length(), end));
            KeyFactory factory = KeyFactory.getInstance("EC");
            return new KeyPair(factory.generatePublic(new X509EncodedKeySpec(der)), RelayCertificate.readPrivateKey(file));
        }
        KeyPair key = AcmeClient.newKey();
        Path tmp = file.resolveSibling("account.key.tmp");
        Files.writeString(tmp, RelayCertificate.pem("PRIVATE KEY", key.getPrivate().getEncoded())
                + RelayCertificate.pem("PUBLIC KEY", key.getPublic().getEncoded()));
        Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE);
        return key;
    }

    private static boolean covers(X509Certificate certificate, List<String> domains) {
        try {
            Set<String> names = new HashSet<>();
            if (certificate.getSubjectAlternativeNames() != null) {
                for (List<?> name : certificate.getSubjectAlternativeNames()) {
                    if (Integer.valueOf(2).equals(name.get(0))) {
                        names.add(((String) name.get(1)).toLowerCase());
                    }
                }
            }
            return domains.stream().allMatch(d -> names.contains(d.toLowerCase()));
        }
        catch (CertificateParsingException e) {
            return false;
        }
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
    }
}
