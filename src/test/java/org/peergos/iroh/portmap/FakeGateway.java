package org.peergos.iroh.portmap;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** A gateway on loopback answering PCP, NAT-PMP and UPnP IGD as configured, recording the requests. */
final class FakeGateway implements AutoCloseable {

    static final Inet4Address EXTERNAL_IP = ip("203.0.113.5");
    static final Inet4Address LOOPBACK = ip("127.0.0.1");

    volatile boolean pcp = true, natPmp = true, upnp = true, addAnyPortMapping = true;
    volatile int externalPort = 40000;
    volatile long lifetimeSeconds = 7200;
    final List<String> requests = new CopyOnWriteArrayList<>();
    private final DatagramSocket pcpSocket;
    private final DatagramSocket ssdpSocket;
    private final HttpServer http;

    FakeGateway() throws IOException {
        pcpSocket = new DatagramSocket(new InetSocketAddress(LOOPBACK, 0));
        ssdpSocket = new DatagramSocket(new InetSocketAddress(LOOPBACK, 0));
        http = HttpServer.create(new InetSocketAddress(LOOPBACK, 0), 0);
        http.createContext("/rootDesc.xml", exchange -> respond(exchange, rootDescription()));
        http.createContext("/scpd.xml", exchange -> respond(exchange, scpd()));
        http.createContext("/ctl", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String action = exchange.getRequestHeaders().getFirst("SOAPAction").replaceAll(".*#|\"", "");
            requests.add("upnp " + action + " " + body.replaceAll("(?s).*<u:\\w+[^>]*>(.*)</u:.*", "$1"));
            String result = switch (action) {
                case "GetExternalIPAddress" -> "<NewExternalIPAddress>" + EXTERNAL_IP.getHostAddress() + "</NewExternalIPAddress>";
                case "AddAnyPortMapping" -> "<NewReservedPort>" + externalPort + "</NewReservedPort>";
                case "AddPortMapping", "DeletePortMapping" -> "";
                default -> null;
            };
            if (action.equals("AddPortMapping")) {
                Matcher port = Pattern.compile("<NewExternalPort>(\\d+)</NewExternalPort>").matcher(body);
                if (port.find() && Integer.parseInt(port.group(1)) != externalPort) {
                    String fault = "<s:Fault><detail><UPnPError><errorCode>718</errorCode><errorDescription>ConflictInMappingEntry"
                            + "</errorDescription></UPnPError></detail></s:Fault>";
                    respond(exchange, 500, envelope(fault));
                    return;
                }
            }
            respond(exchange, 200, envelope("<u:" + action + "Response xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
                    + result + "</u:" + action + "Response>"));
        });
        http.start();
        Thread.ofVirtual().start(this::servePcp);
        Thread.ofVirtual().start(this::serveSsdp);
    }

    PortMapper.Gateway gateway() {
        return new PortMapper.Gateway(LOOPBACK, LOOPBACK, pcpSocket.getLocalPort(), (InetSocketAddress) ssdpSocket.getLocalSocketAddress());
    }

    private static Inet4Address ip(String address) {
        try {
            return (Inet4Address) InetAddress.getByName(address);
        }
        catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String envelope(String body) {
        return "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>" + body
                + "</s:Body></s:Envelope>";
    }

    private void respond(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
        respond(exchange, 200, body);
    }

    private void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private String rootDescription() {
        return "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><device>"
                + "<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><deviceList><device>"
                + "<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device>"
                + "<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList><service>"
                + "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
                + "<controlURL>/ctl</controlURL><SCPDURL>/scpd.xml</SCPDURL>"
                + "</service></serviceList></device></deviceList></device></deviceList></device></root>";
    }

    private String scpd() {
        String add = "<argument><name>NewRemoteHost</name><direction>in</direction></argument>"
                + "<argument><name>NewExternalPort</name><direction>in</direction></argument>"
                + "<argument><name>NewProtocol</name><direction>in</direction></argument>"
                + "<argument><name>NewInternalPort</name><direction>in</direction></argument>"
                + "<argument><name>NewInternalClient</name><direction>in</direction></argument>"
                + "<argument><name>NewEnabled</name><direction>in</direction></argument>"
                + "<argument><name>NewPortMappingDescription</name><direction>in</direction></argument>"
                + "<argument><name>NewLeaseDuration</name><direction>in</direction></argument>";
        return "<?xml version=\"1.0\"?><scpd xmlns=\"urn:schemas-upnp-org:service-1-0\"><actionList>"
                + "<action><name>GetExternalIPAddress</name><argumentList><argument><name>NewExternalIPAddress</name>"
                + "<direction>out</direction></argument></argumentList></action>"
                + "<action><name>AddPortMapping</name><argumentList>" + add + "</argumentList></action>"
                + (addAnyPortMapping? "<action><name>AddAnyPortMapping</name><argumentList>" + add + "</argumentList></action>": "")
                + "<action><name>DeletePortMapping</name><argumentList>"
                + "<argument><name>NewRemoteHost</name><direction>in</direction></argument>"
                + "<argument><name>NewExternalPort</name><direction>in</direction></argument>"
                + "<argument><name>NewProtocol</name><direction>in</direction></argument></argumentList></action>"
                + "</actionList></scpd>";
    }

    private void serveSsdp() {
        byte[] buffer = new byte[2048];
        while (!ssdpSocket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                ssdpSocket.receive(packet);
                if (!upnp) {
                    continue;
                }
                requests.add("ssdp");
                String response = "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                        + "LOCATION: http://127.0.0.1:" + http.getAddress().getPort() + "/rootDesc.xml\r\n\r\n";
                byte[] bytes = response.getBytes(StandardCharsets.US_ASCII);
                ssdpSocket.send(new DatagramPacket(bytes, bytes.length, packet.getSocketAddress()));
            }
            catch (IOException e) {
                return;
            }
        }
    }

    private void servePcp() {
        byte[] buffer = new byte[1100];
        while (!pcpSocket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                pcpSocket.receive(packet);
                ByteBuffer request = ByteBuffer.wrap(buffer, 0, packet.getLength());
                byte[] response = request.get(0) == Pcp.VERSION? pcp(request): natPmp(request);
                if (response != null) {
                    pcpSocket.send(new DatagramPacket(response, response.length, packet.getSocketAddress()));
                }
            }
            catch (IOException e) {
                return;
            }
        }
    }

    private byte[] pcp(ByteBuffer request) {
        if (!pcp) {
            return null;
        }
        int opcode = request.get(1);
        long lifetime = request.getInt(4) & 0xffffffffL;
        ByteBuffer response = ByteBuffer.allocate(opcode == Pcp.OPCODE_MAP? Pcp.MAP_SIZE: 24);
        response.put((byte) Pcp.VERSION).put((byte) (Pcp.RESPONSE | opcode)).put((byte) 0).put((byte) 0);
        if (opcode == Pcp.OPCODE_MAP) {
            int localPort = request.getShort(40) & 0xffff;
            int suggested = request.getShort(42) & 0xffff;
            requests.add("pcp map " + localPort + " suggested " + suggested + " lifetime " + lifetime);
            byte[] nonce = new byte[12];
            request.get(24, nonce);
            response.putInt((int) (lifetime == 0? 0: lifetimeSeconds)).putInt(1).put(new byte[12]);
            response.put(nonce).put((byte) Pcp.PROTOCOL_UDP).put(new byte[3]).putShort((short) localPort)
                    .putShort((short) (lifetime == 0? 0: externalPort)).put(Pcp.mapped(EXTERNAL_IP));
        }
        else {
            requests.add("pcp announce");
            response.putInt(0).putInt(1).put(new byte[12]);
        }
        return response.array();
    }

    private byte[] natPmp(ByteBuffer request) {
        if (!natPmp) {
            return null;
        }
        int opcode = request.get(1);
        if (opcode == NatPmp.OPCODE_EXTERNAL_ADDRESS) {
            requests.add("pmp external");
            return ByteBuffer.allocate(12).put((byte) 0).put((byte) (NatPmp.RESPONSE | opcode)).putShort((short) 0).putInt(1)
                    .put(EXTERNAL_IP.getAddress()).array();
        }
        int localPort = request.getShort(4) & 0xffff;
        int suggested = request.getShort(6) & 0xffff;
        long lifetime = request.getInt(8) & 0xffffffffL;
        requests.add("pmp map " + localPort + " suggested " + suggested + " lifetime " + lifetime);
        return ByteBuffer.allocate(16).put((byte) 0).put((byte) (NatPmp.RESPONSE | opcode)).putShort((short) 0).putInt(1)
                .putShort((short) localPort).putShort((short) (lifetime == 0? 0: externalPort))
                .putInt((int) (lifetime == 0? 0: lifetimeSeconds)).array();
    }

    @Override
    public void close() {
        pcpSocket.close();
        ssdpSocket.close();
        http.stop(0);
    }
}
