package org.peergos.iroh.portmap;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;

/** A port mapping on the gateway: the external address it gives the local port, until it is renewed or released. */
record Mapping(Protocol protocol, InetSocketAddress external, Duration lifetime, Release release) {

    enum Protocol { PCP, NAT_PMP, UPNP }

    interface Release {
        void release() throws IOException;
    }
}
