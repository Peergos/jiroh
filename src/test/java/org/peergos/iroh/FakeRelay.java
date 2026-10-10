package org.peergos.iroh;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** An in-memory stand-in for an iroh relay: forwards datagrams between endpoints by endpoint id. */
final class FakeRelay {

    private final Map<EndpointId, Client> clients = new ConcurrentHashMap<>();
    final AtomicInteger forwarded = new AtomicInteger();

    Client client(EndpointId self) {
        Client client = new Client(self);
        clients.put(self, client);
        return client;
    }

    private void forward(EndpointId from, EndpointId to, byte[] data, int offset, int length) {
        Client destination = clients.get(to);
        if (destination != null && destination.sink != null) {
            forwarded.incrementAndGet();
            destination.sink.deliver(destination.addressFor(from), data, offset, length);
        }
    }

    final class Client implements PacketTransport {
        private final EndpointId self;
        private final Map<EndpointId, InetSocketAddress> addresses = new ConcurrentHashMap<>();
        private final Map<InetSocketAddress, EndpointId> endpoints = new ConcurrentHashMap<>();
        private volatile PacketSink sink;

        Client(EndpointId self) {
            this.self = self;
        }

        /** The mapped address under which the given endpoint is reachable via the relay. */
        InetSocketAddress addressFor(EndpointId remote) {
            return addresses.computeIfAbsent(remote, id -> {
                InetSocketAddress mapped = MappedAddresses.newRelayMapped();
                endpoints.put(mapped, id);
                return mapped;
            });
        }

        @Override
        public boolean handles(InetSocketAddress destination) {
            return endpoints.containsKey(destination);
        }

        @Override
        public void send(InetSocketAddress destination, byte[] data, int offset, int length) throws IOException {
            EndpointId to = endpoints.get(destination);
            if (to == null) {
                throw new IOException("unknown mapped address " + destination);
            }
            forward(self, to, data, offset, length);
        }

        @Override
        public void start(PacketSink sink) {
            this.sink = sink;
        }

        @Override
        public void close() {
            clients.remove(self);
        }
    }
}
