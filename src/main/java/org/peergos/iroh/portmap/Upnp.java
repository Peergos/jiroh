package org.peergos.iroh.portmap;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * UPnP Internet Gateway Device client: finds the gateway with SSDP and maps the port over SOAP, as iroh's portmapper
 * (through igd-next) does.
 */
final class Upnp {

    static final InetSocketAddress SSDP = new InetSocketAddress("239.255.255.250", 1900);
    private static final String SEARCH_TARGET = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
    private static final List<String> SERVICE_TYPES = List.of(
            "urn:schemas-upnp-org:service:WANPPPConnection:1",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANIPConnection:2");
    private static final List<String> DEFAULT_ADD_ARGUMENTS = List.of("NewRemoteHost", "NewExternalPort", "NewProtocol",
            "NewInternalPort", "NewInternalClient", "NewEnabled", "NewPortMappingDescription", "NewLeaseDuration");
    private static final int LEASE_SECONDS = 2 * 60 * 60;
    // As iroh: the lease is two hours, so renew after one.
    static final Duration LIFETIME = Duration.ofSeconds(LEASE_SECONDS);
    private static final String DESCRIPTION = "iroh-portmap";
    private static final int CONFLICT_IN_MAPPING_ENTRY = 718;
    private static final int SAME_PORT_VALUES_REQUIRED = 724;
    private static final int ONLY_PERMANENT_LEASES_SUPPORTED = 725;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Upnp() {}

    /** A gateway's WAN connection service. */
    record Gateway(URI control, String serviceType, Map<String, List<String>> actions) {}

    static final class SoapFault extends IOException {
        final int code;

        SoapFault(int code, String message) {
            super("UPnP error " + code + ": " + message);
            this.code = code;
        }
    }

    static Gateway search(Inet4Address local, InetSocketAddress ssdp, Duration timeout) throws IOException {
        String request = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: " + SEARCH_TARGET
                + "\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n";
        byte[] bytes = request.getBytes(StandardCharsets.US_ASCII);
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(local, 0))) {
            socket.send(new DatagramPacket(bytes, bytes.length, ssdp));
            long deadline = System.nanoTime() + timeout.toNanos();
            byte[] buffer = new byte[2048];
            IOException failure = null;
            while (true) {
                long remaining = (deadline - System.nanoTime()) / 1_000_000;
                if (remaining <= 0) {
                    throw failure != null? failure: new IOException("no UPnP gateway answered");
                }
                socket.setSoTimeout((int) remaining);
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                try {
                    socket.receive(packet);
                }
                catch (SocketTimeoutException e) {
                    continue;
                }
                String response = new String(buffer, 0, packet.getLength(), StandardCharsets.UTF_8);
                URI location = header(response, "location");
                if (location == null) {
                    continue;
                }
                try {
                    return describe(location, timeout);
                }
                catch (IOException e) {
                    failure = e;
                }
            }
        }
    }

    private static URI header(String response, String name) {
        for (String line : response.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().toLowerCase(Locale.ROOT).equals(name)) {
                try {
                    return URI.create(line.substring(colon + 1).trim());
                }
                catch (IllegalArgumentException e) {
                    return null;
                }
            }
        }
        return null;
    }

    private static final HttpClient HTTP = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(2)).build();

    private static Document get(URI uri, Duration timeout) throws IOException {
        HttpRequest request = HttpRequest.newBuilder(uri).timeout(timeout).GET().build();
        return parse(send(request).body());
    }

    private static HttpResponse<byte[]> send(HttpRequest request) throws IOException {
        try {
            return HTTP.send(request, HttpResponse.BodyHandlers.ofByteArray());
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
    }

    private static Document parse(byte[] xml) throws IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setExpandEntityReferences(false);
            return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
        }
        catch (Exception e) {
            throw new IOException("invalid UPnP XML", e);
        }
    }

    static Gateway describe(URI location, Duration timeout) throws IOException {
        Document description = get(location, timeout);
        NodeList services = description.getElementsByTagNameNS("*", "service");
        for (int i = 0; i < services.getLength(); i++) {
            Element service = (Element) services.item(i);
            String type = child(service, "serviceType");
            if (!SERVICE_TYPES.contains(type)) {
                continue;
            }
            String control = child(service, "controlURL");
            String scpd = child(service, "SCPDURL");
            if (control == null) {
                continue;
            }
            Map<String, List<String>> actions = Map.of();
            if (scpd != null) {
                try {
                    actions = actions(get(location.resolve(scpd), timeout));
                }
                catch (IOException e) {
                    // The default argument order is used.
                }
            }
            return new Gateway(location.resolve(control), type, actions);
        }
        throw new IOException("no WAN connection service at " + location);
    }

    private static String child(Element element, String name) {
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element child && name.equals(child.getLocalName())) {
                return child.getTextContent().trim();
            }
        }
        return null;
    }

    private static Map<String, List<String>> actions(Document scpd) {
        Map<String, List<String>> actions = new LinkedHashMap<>();
        NodeList list = scpd.getElementsByTagNameNS("*", "action");
        for (int i = 0; i < list.getLength(); i++) {
            Element action = (Element) list.item(i);
            String name = child(action, "name");
            List<String> in = new ArrayList<>();
            NodeList arguments = action.getElementsByTagNameNS("*", "argument");
            for (int j = 0; j < arguments.getLength(); j++) {
                Element argument = (Element) arguments.item(j);
                if ("in".equals(child(argument, "direction"))) {
                    in.add(child(argument, "name"));
                }
            }
            actions.put(name, in);
        }
        return actions;
    }

    /** Calls an action; returns the response's arguments. */
    static Map<String, String> call(Gateway gateway, String action, Map<String, String> arguments, Duration timeout) throws IOException {
        StringBuilder body = new StringBuilder("<?xml version=\"1.0\"?>\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                + "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:" + action + " xmlns:u=\""
                + gateway.serviceType() + "\">");
        List<String> order = gateway.actions().getOrDefault(action, new ArrayList<>(arguments.keySet()));
        for (String name : order) {
            String value = arguments.get(name);
            if (value != null) {
                body.append('<').append(name).append('>').append(escape(value)).append("</").append(name).append('>');
            }
        }
        body.append("</u:").append(action).append("></s:Body></s:Envelope>");
        HttpRequest request = HttpRequest.newBuilder(gateway.control()).timeout(timeout)
                .header("Content-Type", "text/xml; charset=\"utf-8\"")
                .header("SOAPAction", "\"" + gateway.serviceType() + "#" + action + "\"")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build();
        HttpResponse<byte[]> response = send(request);
        Document document = parse(response.body());
        NodeList errors = document.getElementsByTagNameNS("*", "errorCode");
        if (response.statusCode() != 200 || errors.getLength() > 0) {
            int code = errors.getLength() > 0? Integer.parseInt(errors.item(0).getTextContent().trim()): -1;
            NodeList descriptions = document.getElementsByTagNameNS("*", "errorDescription");
            throw new SoapFault(code, descriptions.getLength() > 0? descriptions.item(0).getTextContent().trim(): "HTTP " + response.statusCode());
        }
        Map<String, String> result = new LinkedHashMap<>();
        NodeList responses = document.getElementsByTagNameNS("*", action + "Response");
        if (responses.getLength() > 0) {
            for (Node node = responses.item(0).getFirstChild(); node != null; node = node.getNextSibling()) {
                if (node instanceof Element element) {
                    result.put(element.getLocalName(), element.getTextContent().trim());
                }
            }
        }
        return result;
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static Map<String, String> portArguments(int externalPort, Inet4Address local, int localPort, int leaseSeconds) {
        Map<String, String> arguments = new LinkedHashMap<>();
        arguments.put("NewRemoteHost", "");
        arguments.put("NewExternalPort", Integer.toString(externalPort));
        arguments.put("NewProtocol", "UDP");
        arguments.put("NewInternalPort", Integer.toString(localPort));
        arguments.put("NewInternalClient", local.getHostAddress());
        arguments.put("NewEnabled", "1");
        arguments.put("NewPortMappingDescription", DESCRIPTION);
        arguments.put("NewLeaseDuration", Integer.toString(leaseSeconds));
        return arguments;
    }

    private static void addPort(Gateway gateway, int externalPort, Inet4Address local, int localPort, Duration timeout) throws IOException {
        Gateway withOrder = gateway.actions().containsKey("AddPortMapping")? gateway:
                new Gateway(gateway.control(), gateway.serviceType(), Map.of("AddPortMapping", DEFAULT_ADD_ARGUMENTS));
        try {
            call(withOrder, "AddPortMapping", portArguments(externalPort, local, localPort, LEASE_SECONDS), timeout);
        }
        catch (SoapFault fault) {
            if (fault.code != ONLY_PERMANENT_LEASES_SUPPORTED) {
                throw fault;
            }
            call(withOrder, "AddPortMapping", portArguments(externalPort, local, localPort, 0), timeout);
        }
    }

    private static int randomPort() {
        return 1024 + RANDOM.nextInt(65536 - 1024);
    }

    /** Maps the local port, on the preferred external port if possible, else on any. */
    static Mapping map(Inet4Address local, int localPort, Gateway gateway, Integer preferredExternalPort, Duration timeout) throws IOException {
        String ip = call(gateway, "GetExternalIPAddress", Map.of(), timeout).get("NewExternalIPAddress");
        InetAddress externalIp;
        try {
            externalIp = InetAddress.getByName(ip);
        }
        catch (RuntimeException | IOException e) {
            throw new IOException("invalid external address " + ip);
        }
        if (!(externalIp instanceof Inet4Address) || externalIp.isAnyLocalAddress()) {
            throw new IOException("no IPv4 external address: " + ip);
        }
        int externalPort = -1;
        if (preferredExternalPort != null) {
            try {
                addPort(gateway, preferredExternalPort, local, localPort, timeout);
                externalPort = preferredExternalPort;
            }
            catch (IOException e) {
                // Any port will do.
            }
        }
        if (externalPort < 0 && gateway.actions().containsKey("AddAnyPortMapping")) {
            Map<String, String> result = call(gateway, "AddAnyPortMapping", portArguments(randomPort(), local, localPort, LEASE_SECONDS), timeout);
            externalPort = Integer.parseInt(result.getOrDefault("NewReservedPort", "0"));
        }
        else if (externalPort < 0) {
            for (int attempt = 0; attempt < 20 && externalPort < 0; attempt++) {
                int port = randomPort();
                try {
                    addPort(gateway, port, local, localPort, timeout);
                    externalPort = port;
                }
                catch (SoapFault fault) {
                    if (fault.code == SAME_PORT_VALUES_REQUIRED) {
                        addPort(gateway, localPort, local, localPort, timeout);
                        externalPort = localPort;
                    }
                    else if (fault.code != CONFLICT_IN_MAPPING_ENTRY) {
                        throw fault;
                    }
                }
            }
        }
        if (externalPort <= 0) {
            throw new IOException("no UPnP mapping");
        }
        int port = externalPort;
        return new Mapping(Mapping.Protocol.UPNP, new InetSocketAddress(externalIp, port), LIFETIME, () -> {
            Map<String, String> arguments = new LinkedHashMap<>();
            arguments.put("NewRemoteHost", "");
            arguments.put("NewExternalPort", Integer.toString(port));
            arguments.put("NewProtocol", "UDP");
            call(gateway, "DeletePortMapping", arguments, timeout);
        });
    }
}
