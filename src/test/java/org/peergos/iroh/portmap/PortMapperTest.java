package org.peergos.iroh.portmap;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PortMapperTest {

    private static final InetSocketAddress MAPPED = new InetSocketAddress(FakeGateway.EXTERNAL_IP, 40000);

    private static Optional<InetSocketAddress> mapWith(FakeGateway fake, int localPort) throws Exception {
        CompletableFuture<Optional<InetSocketAddress>> external = new CompletableFuture<>();
        try (PortMapper mapper = new PortMapper(localPort, () -> Optional.of(fake.gateway()), external::complete)) {
            mapper.procure();
            Optional<InetSocketAddress> result = external.get(5, TimeUnit.SECONDS);
            assertEquals(result, mapper.external());
            return result;
        }
    }

    @Test
    void pcpIsPreferred() throws Exception {
        try (FakeGateway fake = new FakeGateway()) {
            assertEquals(Optional.of(MAPPED), mapWith(fake, 1234));
            assertTrue(fake.requests.contains("pcp map 1234 suggested 0 lifetime 3600"), fake.requests.toString());
            assertTrue(fake.requests.stream().noneMatch(r -> r.startsWith("pmp map") || r.startsWith("upnp Add")), fake.requests.toString());
            // Released on close.
            Thread.sleep(200);
            assertTrue(fake.requests.contains("pcp map 1234 suggested 0 lifetime 0"), fake.requests.toString());
        }
    }

    @Test
    void natPmpWithoutPcp() throws Exception {
        try (FakeGateway fake = new FakeGateway()) {
            fake.pcp = false;
            assertEquals(Optional.of(MAPPED), mapWith(fake, 1234));
            assertTrue(fake.requests.contains("pmp map 1234 suggested 0 lifetime 7200"), fake.requests.toString());
            Thread.sleep(200);
            assertTrue(fake.requests.contains("pmp map 1234 suggested 0 lifetime 0"), fake.requests.toString());
        }
    }

    @Test
    void upnpWithoutPcpOrNatPmp() throws Exception {
        try (FakeGateway fake = new FakeGateway()) {
            fake.pcp = false;
            fake.natPmp = false;
            assertEquals(Optional.of(MAPPED), mapWith(fake, 1234));
            String add = fake.requests.stream().filter(r -> r.startsWith("upnp AddAnyPortMapping")).findFirst().orElseThrow();
            assertTrue(add.contains("<NewInternalPort>1234</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient>"), add);
            assertTrue(add.contains("<NewProtocol>UDP</NewProtocol>"), add);
            Thread.sleep(200);
            assertTrue(fake.requests.stream().anyMatch(r -> r.startsWith("upnp DeletePortMapping") && r.contains("<NewExternalPort>40000<")),
                    fake.requests.toString());
        }
    }

    @Test
    void upnpWithoutAddAnyPortMappingRetriesRandomPorts() throws Exception {
        try (FakeGateway fake = new FakeGateway()) {
            fake.pcp = false;
            fake.natPmp = false;
            fake.addAnyPortMapping = false;
            // The fake only accepts its own port; random ones conflict, so the 20 attempts fail.
            assertEquals(Optional.empty(), mapWithin(fake, 1234));
            assertTrue(fake.requests.stream().filter(r -> r.startsWith("upnp AddPortMapping")).count() >= 20, fake.requests.toString());
        }
    }

    private static Optional<InetSocketAddress> mapWithin(FakeGateway fake, int localPort) throws Exception {
        try (PortMapper mapper = new PortMapper(localPort, () -> Optional.of(fake.gateway()), external -> {})) {
            mapper.procure();
            Thread.sleep(1500);
            return mapper.external();
        }
    }

    @Test
    void noGatewayServicesMeansNoMapping() throws Exception {
        try (FakeGateway fake = new FakeGateway()) {
            fake.pcp = false;
            fake.natPmp = false;
            fake.upnp = false;
            try (PortMapper mapper = new PortMapper(1234, () -> Optional.of(fake.gateway()), external -> {})) {
                assertEquals(new PortMapper.Probe(false, false, false), mapper.probe());
                mapper.procure();
                Thread.sleep(1500);
                assertEquals(Optional.empty(), mapper.external());
            }
        }
    }

    @Test
    void mappingIsRenewedAtHalfItsLifetimeKeepingThePort() throws Exception {
        try (FakeGateway fake = new FakeGateway()) {
            fake.lifetimeSeconds = 2;
            LinkedBlockingQueue<Optional<InetSocketAddress>> changes = new LinkedBlockingQueue<>();
            try (PortMapper mapper = new PortMapper(1234, () -> Optional.of(fake.gateway()), changes::add)) {
                mapper.procure();
                assertEquals(Optional.of(MAPPED), changes.poll(5, TimeUnit.SECONDS));
                long deadline = System.currentTimeMillis() + 4000;
                while (!fake.requests.contains("pcp map 1234 suggested 40000 lifetime 3600") && System.currentTimeMillis() < deadline) {
                    Thread.sleep(50);
                }
                assertTrue(fake.requests.contains("pcp map 1234 suggested 40000 lifetime 3600"), fake.requests.toString());
                // The same external address, so no change is reported.
                assertEquals(null, changes.poll(200, TimeUnit.MILLISECONDS));
                assertEquals(Optional.of(MAPPED), mapper.external());
            }
        }
    }

    @Test
    void defaultRouteIsParsed() throws Exception {
        List<String> route = List.of(
                "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
                "wlp1s0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0",
                "wlp1s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0");
        assertEquals(Optional.of(InetAddress.getByName("192.168.1.1")), DefaultGateway.parseProcNetRoute(route));
        String mac = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n"
                + "default            10.0.0.1           UGScg                 en0\n127                127.0.0.1          UCS                   lo0\n";
        assertEquals(Optional.of(InetAddress.getByName("10.0.0.1")), DefaultGateway.parseNetstat(mac));
        String windows = "IPv4 Route Table\n===\nActive Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n"
                + "          0.0.0.0          0.0.0.0      172.16.0.1     172.16.0.23     25\n";
        assertEquals(Optional.of(InetAddress.getByName("172.16.0.1")), DefaultGateway.parseNetstat(windows));
        assertFalse(DefaultGateway.parseNetstat("Kernel IP routing table\n").isPresent());
    }
}
