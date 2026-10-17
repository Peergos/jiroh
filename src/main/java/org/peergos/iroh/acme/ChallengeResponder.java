package org.peergos.iroh.acme;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/** Where ACME challenge responses are served from. */
public interface ChallengeResponder {

    /** Whether http-01 responses are reachable on port 80 of the domain. */
    boolean supportsHttp01();

    /** Serve keyAuthorization at /.well-known/acme-challenge/token. */
    void addHttp01(String token, String keyAuthorization);

    void removeHttp01(String token);

    /** Whether tls-alpn-01 responses are reachable on port 443 of the domain. */
    boolean supportsTlsAlpn01();

    /** Present this certificate to handshakes for the domain that negotiate ALPN acme-tls/1. */
    void addTlsAlpn01(String domain, PrivateKey key, X509Certificate certificate);

    void removeTlsAlpn01(String domain);
}
