package org.peergos.iroh;

import tech.kwik.core.QuicStream;

import java.net.InetSocketAddress;

/**
 * Handles incoming connections for one ALPN. Mirrors iroh's {@code ProtocolHandler}.
 */
public interface ProtocolHandler {

    /**
     * Called for every stream the remote opens on a connection with this handler's ALPN.
     * @param remote  the authenticated endpoint id of the remote
     * @param remoteAddress  the address the connection came from
     */
    void acceptStream(EndpointId remote, InetSocketAddress remoteAddress, QuicStream stream);
}
