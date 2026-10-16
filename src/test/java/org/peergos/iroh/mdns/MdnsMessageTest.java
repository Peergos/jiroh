package org.peergos.iroh.mdns;

import org.junit.jupiter.api.Test;
import org.peergos.iroh.EndpointId;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MdnsMessageTest {

    @Test
    void endpointIdLabelShouldBeLowercaseUnpaddedBase32() {
        EndpointId id = EndpointId.fromHex("b5b38f1984a33e314c0d1c78f0f02c7b5f7f08adf74fe0eb58c243eb9dcfc7e6");
        // data_encoding::BASE32_NOPAD, lowercased, as iroh-mdns-address-lookup names the instance
        assertEquals("wwzy6gmeum7dctandr4pb4bmpnpx6cfn65h6b22yyjb6xhopy7ta", MdnsAddressLookup.base32(id.toBytes()));
        assertEquals(id, MdnsAddressLookup.parseId("wwzy6gmeum7dctandr4pb4bmpnpx6cfn65h6b22yyjb6xhopy7ta"));
        assertEquals(id, MdnsAddressLookup.parseId("WWZY6GMEUM7DCTANDR4PB4BMPNPX6CFN65H6B22YYJB6XHOPY7TA"));
        assertEquals(id, MdnsAddressLookup.parseId(id.toHex()));
        assertNull(MdnsAddressLookup.parseId("peer_id42"));
    }

    @Test
    void responseShouldRoundTrip() throws Exception {
        String instance = "abc._irohv1._udp.local";
        List<MdnsMessage.Record> answers = List.of(
                new MdnsMessage.Record(instance, MdnsMessage.CLASS_IN, 0, new MdnsMessage.Srv(4433, "abc-4433.local")),
                new MdnsMessage.Record(instance, MdnsMessage.CLASS_IN, 0, new MdnsMessage.Txt(List.of("relay=https://relay.example/"))));
        List<MdnsMessage.Record> additionals = List.of(
                new MdnsMessage.Record("abc-4433.local", MdnsMessage.CLASS_IN, 0, new MdnsMessage.Address(InetAddress.getByName("192.168.1.2"))),
                new MdnsMessage.Record("abc-4433.local", MdnsMessage.CLASS_IN, 0, new MdnsMessage.Address(InetAddress.getByName("fd00::1"))));
        byte[] packet = MdnsMessage.response(answers, additionals);
        MdnsMessage.Message decoded = MdnsMessage.decode(packet);
        assertTrue(decoded.response());
        assertEquals(answers, decoded.answers());
        assertEquals(additionals, decoded.additionals());
        // The A records' names are compressed pointers into the SRV target.
        assertTrue(packet.length < 160, "packet of " + packet.length + " bytes");
    }

    @Test
    void queryShouldAskForThePtrOfTheService() {
        MdnsMessage.Message decoded = MdnsMessage.decode(MdnsMessage.query("_irohv1._udp.local"));
        assertFalse(decoded.response());
        assertEquals(List.of(new MdnsMessage.Question("_irohv1._udp.local", MdnsMessage.TYPE_PTR, MdnsMessage.CLASS_IN)),
                decoded.questions());
    }
}
