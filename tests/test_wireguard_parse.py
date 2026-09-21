"""parse_dump() must extract the public key (not the private key) and
must support both `wg show <iface> dump` and `wg show all dump` output."""
import unittest

from pinoc.integrations.wireguard import parse_dump


class ParseDumpAllInterfacesTest(unittest.TestCase):
    def test_public_key_short_uses_the_public_key_field(self):
        # interface, private-key, public-key, listen-port, fwmark
        text = "wg0\tPRIVATEKEYAAAA\tPUBLICKEYBBBB\t51820\toff"
        interfaces = parse_dump(text, now=100)
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0]["interface"], "wg0")
        self.assertEqual(interfaces[0]["public_key_short"], "PUBLICKE")
        self.assertEqual(interfaces[0]["listen_port"], 51820)
        self.assertEqual(interfaces[0]["fwmark"], "off")

    def test_private_key_never_appears_in_the_result(self):
        text = "wg0\tSUPERSECRETPRIVATE\tPUBLICKEYBBBB\t51820\toff"
        interfaces = parse_dump(text, now=100)
        self.assertNotIn("SUPERSECRETPRIVATE", str(interfaces))

    def test_peer_lines_use_the_correct_offset(self):
        text = ("wg0\tPRIVATEKEYAAAA\tPUBLICKEYBBBB\t51820\toff\n"
                "wg0\tPEERPUBKEY\tpsk\thost:51820\t10.0.0.0/24\t100\t12\t13\t25")
        interfaces = parse_dump(text, {"PEERPUBKEY": "office"}, required=["PEERPUBKEY"], now=114)
        peer = interfaces[0]["peers"][0]
        self.assertEqual(peer["public_key"], "PEERPUBKEY")
        self.assertEqual(peer["friendly_name"], "office")
        self.assertEqual(peer["endpoint"], "host:51820")
        self.assertEqual(peer["allowed_ips"], ["10.0.0.0/24"])
        self.assertEqual(peer["latest_handshake_seconds"], 14)
        self.assertEqual(peer["rx_bytes"], 12)
        self.assertEqual(peer["tx_bytes"], 13)
        self.assertEqual(peer["persistent_keepalive"], 25)
        self.assertTrue(peer["required"])

    def test_multiple_interfaces(self):
        text = ("wg0\tPRIVATEA\tPUBLICA\t51820\toff\n"
                "wg1\tPRIVATEB\tPUBLICB\t51821\toff")
        interfaces = parse_dump(text, now=100)
        self.assertEqual([i["interface"] for i in interfaces], ["wg0", "wg1"])
        self.assertEqual([i["public_key_short"] for i in interfaces], ["PUBLICA", "PUBLICB"])


class ParseDumpSingleInterfaceTest(unittest.TestCase):
    def test_public_key_short_uses_the_public_key_field(self):
        # single-interface dump has no interface-name column:
        # private-key, public-key, listen-port, fwmark
        text = "PRIVATEKEYAAAA\tPUBLICKEYBBBB\t51820\toff"
        interfaces = parse_dump(text, now=100)
        self.assertEqual(len(interfaces), 1)
        self.assertIsNone(interfaces[0]["interface"])
        self.assertEqual(interfaces[0]["public_key_short"], "PUBLICKE")

    def test_peer_lines_use_the_correct_offset(self):
        text = ("PRIVATEKEYAAAA\tPUBLICKEYBBBB\t51820\toff\n"
                "PEERPUBKEY\tpsk\thost:51820\t10.0.0.0/24\t100\t12\t13\t25")
        interfaces = parse_dump(text, {"PEERPUBKEY": "office"}, required=["PEERPUBKEY"], now=114)
        peer = interfaces[0]["peers"][0]
        self.assertEqual(peer["public_key"], "PEERPUBKEY")
        self.assertEqual(peer["latest_handshake_seconds"], 14)
        self.assertEqual(peer["rx_bytes"], 12)
        self.assertEqual(peer["tx_bytes"], 13)


if __name__ == "__main__":
    unittest.main()
