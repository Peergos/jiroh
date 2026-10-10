package org.peergos.iroh;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.List;

/**
 * Where an endpoint can be reached: its relay URLs and direct UDP addresses. Like iroh's {@code EndpointAddr}.
 */
public record EndpointAddr(EndpointId id, List<URI> relayUrls, List<InetSocketAddress> directAddresses) {

    public EndpointAddr {
        relayUrls = List.copyOf(relayUrls);
        directAddresses = List.copyOf(directAddresses);
    }

    public static EndpointAddr of(EndpointId id) {
        return new EndpointAddr(id, List.of(), List.of());
    }

    public EndpointAddr withRelay(URI relay) {
        List<URI> relays = new java.util.ArrayList<>(relayUrls);
        relays.add(relay);
        return new EndpointAddr(id, relays, directAddresses);
    }

    public EndpointAddr withDirect(InetSocketAddress address) {
        List<InetSocketAddress> addresses = new java.util.ArrayList<>(directAddresses);
        addresses.add(address);
        return new EndpointAddr(id, relayUrls, addresses);
    }
}
