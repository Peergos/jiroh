package org.peergos.iroh;

import tech.kwik.core.QuicStream;

/**
 * Handles incoming connections for one ALPN. Mirrors iroh's {@code ProtocolHandler}.
 */
public interface ProtocolHandler {

    /**
     * Called for every stream the remote opens on a connection with this handler's ALPN.
     * @param remote  the authenticated endpoint id of the remote
     */
    void acceptStream(EndpointId remote, QuicStream stream);
}
