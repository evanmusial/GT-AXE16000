import unittest

from asus_exporter.parsers import (
    parse_conntrack_summary,
    parse_dhcp_leases,
    parse_arp_table,
    parse_loadavg,
    parse_meminfo,
    parse_net_dev,
    parse_protocol_table,
    parse_sections,
    parse_snmp6,
    parse_uptime,
    parse_wifi_networks,
    snake_case,
)


class ParserTests(unittest.TestCase):
    def test_parse_net_dev(self):
        text = """
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 2973000992692 2498039352 0 1436066 0 0 0 3410970 453727884131 956880022 0 293 0 0 0 0
    lo: 100 2 0 0 0 0 0 0 100 2 0 0 0 0 0 0
"""
        parsed = parse_net_dev(text)
        self.assertEqual(parsed["eth0"]["receive_bytes"], 2973000992692)
        self.assertEqual(parsed["eth0"]["transmit_bytes"], 453727884131)
        self.assertEqual(parsed["eth0"]["receive_drop"], 1436066)
        self.assertEqual(parsed["eth0"]["transmit_drop"], 293)
        self.assertEqual(parsed["lo"]["receive_packets"], 2)

    def test_parse_protocol_table(self):
        text = """
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab RetransSegs
Tcp: 1 200 120000 -1 10 11 12 13 3 99
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
Udp: 100 2 3 90 4 5
"""
        parsed = parse_protocol_table(text)
        self.assertEqual(parsed[("Tcp", "CurrEstab")], 3)
        self.assertEqual(parsed[("Tcp", "RetransSegs")], 99)
        self.assertEqual(parsed[("Udp", "RcvbufErrors")], 4)

    def test_parse_snmp6(self):
        parsed = parse_snmp6(
            """
Ip6InOctets                     	23123514891
Ip6OutOctets                    	13484283210
Udp6InDatagrams                 	5099763
"""
        )
        self.assertEqual(parsed["Ip6InOctets"], 23123514891)
        self.assertEqual(parsed["Udp6InDatagrams"], 5099763)

    def test_parse_health(self):
        self.assertEqual(parse_uptime("123.45 999.00"), 123.45)
        self.assertEqual(parse_loadavg("0.10 0.20 0.30 1/100 42"), (0.10, 0.20, 0.30))
        meminfo = parse_meminfo(
            """
MemTotal:        1024 kB
MemFree:          64 kB
Cached:           10 kB
"""
        )
        self.assertEqual(meminfo["MemTotal"], 1048576)
        self.assertEqual(meminfo["Cached"], 10240)

    def test_parse_dhcp_leases(self):
        leases = parse_dhcp_leases(
            "1760000000 aa:bb:cc:dd:ee:ff 10.1.10.50 laptop 01:aa\n"
            "1760000001 11:22:33:44:55:66 10.1.10.51 * *\n"
        )
        self.assertEqual(len(leases), 2)
        self.assertEqual(leases[0].hostname, "laptop")
        self.assertEqual(leases[1].hostname, "")
        self.assertEqual(leases[1].client_id, "")

    def test_parse_arp_table(self):
        entries = parse_arp_table(
            """
Address                  HWtype  HWaddress           Flags Mask            Iface
10.1.10.50               ether   aa:bb:cc:dd:ee:ff   C                     br0
10.1.10.51               ether   (incomplete)                              br0
192.168.1.254            ether   11:22:33:44:55:66   C                     eth0
? (10.1.10.60) at 22:33:44:55:66:77 [ether]  on br0
? (10.1.10.61) at <incomplete>  on br0
"""
        )
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0].ip, "10.1.10.50")
        self.assertEqual(entries[0].mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(entries[0].interface, "br0")
        self.assertEqual(entries[1].interface, "eth0")
        self.assertEqual(entries[2].ip, "10.1.10.60")
        self.assertEqual(entries[2].interface, "br0")

    def test_parse_conntrack_summary(self):
        entries = parse_conntrack_summary(
            "ipv4\ttcp\tESTABLISHED\tASSURED\t12\n"
            "ipv6\tudp\tnone\tnone\t3\n"
            "ipv4     2 tcp      6 112 TIME_WAIT src=1.1.1.1 dst=2.2.2.2 "
            "sport=123 dport=443 [ASSURED] use=2\n"
        )
        indexed = {
            (entry.ip_stack, entry.protocol, entry.state, entry.status): entry.count
            for entry in entries
        }
        self.assertEqual(indexed[("ipv4", "tcp", "established", "assured")], 12)
        self.assertEqual(indexed[("ipv6", "udp", "none", "none")], 3)
        self.assertEqual(indexed[("ipv4", "tcp", "time_wait", "assured")], 1)

    def test_parse_wifi_networks(self):
        networks = parse_wifi_networks(
            "wl0\teth7\tHome WiFi\t1\t1\t0\t1\tbr0\n"
            "wl3.1\twl3.1\tGuest\t1\t1\t0\t1\tbr52\n"
        )
        self.assertEqual(len(networks), 2)
        self.assertEqual(networks[0].ssid, "Home WiFi")
        self.assertEqual(networks[1].bridge, "br52")

    def test_parse_sections(self):
        sections = parse_sections(
            """
noise
__ASUS_EXPORTER_BEGIN__ proc_net_dev
hello
__ASUS_EXPORTER_END__ proc_net_dev
"""
        )
        self.assertEqual(sections["proc_net_dev"], "hello")

    def test_snake_case(self):
        self.assertEqual(snake_case("RetransSegs"), "retrans_segs")
        self.assertEqual(snake_case("RcvbufErrors"), "rcvbuf_errors")
        self.assertEqual(snake_case("InNoECTPkts"), "in_no_ect_pkts")


if __name__ == "__main__":
    unittest.main()
