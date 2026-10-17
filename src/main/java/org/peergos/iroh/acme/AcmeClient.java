package org.peergos.iroh.acme;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * An ACME client (RFC 8555) that orders a certificate for some DNS names, answering http-01 or tls-alpn-01
 * (RFC 8737) challenges through a {@link ChallengeResponder}. The account key is EC P-256 (ES256).
 */
public final class AcmeClient {

    private static final Logger LOG = Logger.getLogger(AcmeClient.class.getName());

    public static final URI LETS_ENCRYPT = URI.create("https://acme-v02.api.letsencrypt.org/directory");
    public static final URI LETS_ENCRYPT_STAGING = URI.create("https://acme-staging-v02.api.letsencrypt.org/directory");
    public static final String HTTP_01 = "http-01";
    public static final String TLS_ALPN_01 = "tls-alpn-01";

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Duration POLL_INTERVAL = Duration.ofSeconds(1);
    private static final int BAD_NONCE_RETRIES = 5;

    private final URI directoryUrl;
    private final KeyPair accountKey;
    private final List<String> contact;
    private final HttpClient http;
    private Map<String, Object> directory;
    private String nonce;
    private String accountUrl;

    /**
     * @param contact     e.g. mailto:admin@example.com
     * @param sslContext  for the ACME server's certificate, or null for the default trust store
     */
    public AcmeClient(URI directoryUrl, KeyPair accountKey, List<String> contact, SSLContext sslContext) {
        if (!(accountKey.getPublic() instanceof ECPublicKey)) {
            throw new IllegalArgumentException("the account key must be EC P-256");
        }
        this.directoryUrl = directoryUrl;
        this.accountKey = accountKey;
        this.contact = List.copyOf(contact);
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30));
        if (sslContext != null) {
            builder.sslContext(sslContext);
        }
        this.http = builder.build();
    }

    public static KeyPair newKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Orders a certificate for the domains, signed for certificateKey, and returns its chain, leaf first.
     * @param challengeTypes  the challenge types to use, in order of preference, among those the responder supports
     */
    public X509Certificate[] issue(List<String> domains, KeyPair certificateKey, ChallengeResponder responder,
                                   List<String> challengeTypes, Duration timeout) throws IOException {
        long deadline = System.nanoTime() + timeout.toNanos();
        try {
            ensureAccount();
            String identifiers = domains.stream()
                    .map(d -> "{\"type\":\"dns\",\"value\":" + Json.quote(d) + "}")
                    .collect(Collectors.joining(",", "[", "]"));
            Response created = post(url("newOrder"), "{\"identifiers\":" + identifiers + "}");
            String orderUrl = created.location();
            Map<String, Object> order = created.json();
            for (Object authorization : (List<?>) order.get("authorizations")) {
                authorize((String) authorization, responder, challengeTypes, deadline);
            }
            String csr = B64.encodeToString(Der.csr(certificateKey, domains));
            post((String) order.get("finalize"), "{\"csr\":\"" + csr + "\"}");
            order = poll(orderUrl, deadline, "valid", "processing", "pending", "ready");
            Response certificate = post((String) order.get("certificate"), null);
            return CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(certificate.body().getBytes(StandardCharsets.US_ASCII)))
                    .stream().map(c -> (X509Certificate) c).toArray(X509Certificate[]::new);
        }
        catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
    }

    private void authorize(String authorizationUrl, ChallengeResponder responder, List<String> challengeTypes, long deadline)
            throws IOException, InterruptedException, GeneralSecurityException {
        Map<String, Object> authorization = post(authorizationUrl, null).json();
        if ("valid".equals(authorization.get("status"))) {
            return;
        }
        String domain = (String) ((Map<?, ?>) authorization.get("identifier")).get("value");
        Map<?, ?> challenge = null;
        for (String type : challengeTypes) {
            boolean supported = type.equals(HTTP_01)? responder.supportsHttp01(): type.equals(TLS_ALPN_01) && responder.supportsTlsAlpn01();
            if (!supported) {
                continue;
            }
            for (Object c : (List<?>) authorization.get("challenges")) {
                if (type.equals(((Map<?, ?>) c).get("type"))) {
                    challenge = (Map<?, ?>) c;
                    break;
                }
            }
            if (challenge != null) {
                break;
            }
        }
        if (challenge == null) {
            throw new IOException("no usable challenge for " + domain + " among " + challengeTypes);
        }
        String type = (String) challenge.get("type");
        String token = (String) challenge.get("token");
        String keyAuthorization = token + "." + thumbprint();
        if (type.equals(HTTP_01)) {
            responder.addHttp01(token, keyAuthorization);
        }
        else {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(keyAuthorization.getBytes(StandardCharsets.US_ASCII));
            KeyPair key = newKey();
            responder.addTlsAlpn01(domain, key.getPrivate(), Der.tlsAlpnChallengeCertificate(key, domain, digest));
        }
        try {
            LOG.info("ACME: answering " + type + " for " + domain);
            post((String) challenge.get("url"), "{}");
            poll(authorizationUrl, deadline, "valid", "pending");
        }
        finally {
            if (type.equals(HTTP_01)) {
                responder.removeHttp01(token);
            }
            else {
                responder.removeTlsAlpn01(domain);
            }
        }
    }

    /** Polls with POST-as-GET while the status is one of the waiting ones; returns the object once it is the wanted one. */
    private Map<String, Object> poll(String url, long deadline, String wanted, String... waiting)
            throws IOException, InterruptedException, GeneralSecurityException {
        while (true) {
            Response response = post(url, null);
            Map<String, Object> object = response.json();
            String status = (String) object.get("status");
            if (wanted.equals(status)) {
                return object;
            }
            if (!List.of(waiting).contains(status)) {
                throw new IOException("ACME " + url + " is " + status + ": " + response.body());
            }
            if (System.nanoTime() > deadline) {
                throw new IOException("ACME timed out waiting for " + url + " (" + status + ")");
            }
            Thread.sleep(retryAfter(response).orElse(POLL_INTERVAL));
        }
    }

    private static java.util.Optional<Duration> retryAfter(Response response) {
        return response.header("Retry-After").flatMap(value -> {
            try {
                return java.util.Optional.of(Duration.ofSeconds(Math.min(10, Long.parseLong(value.trim()))));
            }
            catch (NumberFormatException e) {
                return java.util.Optional.empty();
            }
        });
    }

    private void ensureAccount() throws IOException, InterruptedException, GeneralSecurityException {
        if (accountUrl != null) {
            return;
        }
        String contacts = contact.stream().map(Json::quote).collect(Collectors.joining(",", "[", "]"));
        Response response = post(url("newAccount"), "{\"termsOfServiceAgreed\":true,\"contact\":" + contacts + "}");
        accountUrl = response.location();
    }

    private String url(String name) throws IOException, InterruptedException {
        if (directory == null) {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(directoryUrl).GET().build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IOException("ACME directory " + directoryUrl + ": HTTP " + response.statusCode());
            }
            directory = Json.object(response.body());
        }
        Object url = directory.get(name);
        if (!(url instanceof String s)) {
            throw new IOException("ACME directory has no " + name);
        }
        return s;
    }

    private record Response(int status, String body, HttpResponse<String> raw) {
        Map<String, Object> json() {
            return Json.object(body);
        }

        String location() throws IOException {
            return header("Location").orElseThrow(() -> new IOException("ACME response without Location"));
        }

        java.util.Optional<String> header(String name) {
            return raw.headers().firstValue(name);
        }
    }

    /** A JWS-signed POST; a null payload is a POST-as-GET. Retries on badNonce. */
    private Response post(String url, String payload) throws IOException, InterruptedException, GeneralSecurityException {
        for (int attempt = 0; ; attempt++) {
            if (nonce == null) {
                HttpResponse<Void> head = http.send(HttpRequest.newBuilder(URI.create(url("newNonce")))
                        .method("HEAD", HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.discarding());
                nonce = head.headers().firstValue("Replay-Nonce").orElseThrow(() -> new IOException("ACME server gave no nonce"));
            }
            String key = accountUrl != null? "\"kid\":" + Json.quote(accountUrl): "\"jwk\":" + jwk();
            String header = "{\"alg\":\"ES256\"," + key + ",\"nonce\":" + Json.quote(nonce) + ",\"url\":" + Json.quote(url) + "}";
            nonce = null;
            String protectedHeader = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8));
            String encodedPayload = payload == null? "": B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
            Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
            signer.initSign(accountKey.getPrivate());
            signer.update((protectedHeader + "." + encodedPayload).getBytes(StandardCharsets.US_ASCII));
            String body = "{\"protected\":\"" + protectedHeader + "\",\"payload\":\"" + encodedPayload
                    + "\",\"signature\":\"" + B64.encodeToString(signer.sign()) + "\"}";
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(url))
                    .header("Content-Type", "application/jose+json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
            nonce = response.headers().firstValue("Replay-Nonce").orElse(null);
            if (response.statusCode() < 300) {
                return new Response(response.statusCode(), response.body(), response);
            }
            String type = "";
            try {
                type = String.valueOf(Json.object(response.body()).get("type"));
            }
            catch (IllegalArgumentException notJson) {
                // reported below
            }
            if (type.equals("urn:ietf:params:acme:error:badNonce") && attempt < BAD_NONCE_RETRIES) {
                continue;
            }
            throw new IOException("ACME " + url + ": HTTP " + response.statusCode() + " " + response.body());
        }
    }

    private String jwk() {
        ECPublicKey key = (ECPublicKey) accountKey.getPublic();
        // RFC 7638: the required members in lexicographic order, without whitespace
        return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + B64.encodeToString(coordinate(key.getW().getAffineX()))
                + "\",\"y\":\"" + B64.encodeToString(coordinate(key.getW().getAffineY())) + "\"}";
    }

    private String thumbprint() throws GeneralSecurityException {
        return B64.encodeToString(MessageDigest.getInstance("SHA-256").digest(jwk().getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] coordinate(BigInteger value) {
        byte[] bytes = value.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(bytes.length, 32);
        System.arraycopy(bytes, bytes.length - copy, out, 32 - copy, copy);
        return out;
    }
}
