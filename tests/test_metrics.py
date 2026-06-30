import unittest

from asus_exporter.config import ExporterConfig
from asus_exporter.metrics import build_router_samples, render_prometheus, Sample


class MetricTests(unittest.TestCase):
    def test_build_router_samples(self):
        config = ExporterConfig(wan_interface="eth0")
        sections = {
            "proc_net_dev": (
                "Inter-| Receive | Transmit\n"
                " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
                " eth0: 1000 10 0 1 0 0 0 0 2000 20 0 2 0 0 0 0\n"
            ),
            "proc_uptime": "123.0 456.0\n",
            "proc_loadavg": "0.01 0.02 0.03 1/2 3\n",
            "proc_meminfo": "MemTotal: 1024 kB\nMemFree: 512 kB\nCached: 10 kB\n",
            "conntrack_count": "42\n",
            "conntrack_max": "1024\n",
            "conntrack_summary": (
                "ipv4\ttcp\tESTABLISHED\tASSURED\t12\n"
                "ipv6\tudp\tnone\tnone\t3\n"
            ),
            "dhcp_leases": "1760000000 aa:bb:cc:dd:ee:ff 10.1.10.50 laptop 01:aa\n",
            "arp_table": (
                "Address                  HWtype  HWaddress           Flags Mask            Iface\n"
                "10.1.10.50               ether   aa:bb:cc:dd:ee:ff   C                     br0\n"
                "10.1.10.60               ether   22:33:44:55:66:77   C                     br0\n"
                "192.168.1.254            ether   11:22:33:44:55:66   C                     eth0\n"
            ),
            "wifi_networks": "wl0\teth7\tHome WiFi\t1\t1\t0\t1\tbr0\n",
            "proc_net_snmp": (
                "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens CurrEstab RetransSegs InSegs OutSegs\n"
                "Tcp: 1 200 120000 -1 10 3 99 1000 900\n"
                "Udp: InDatagrams OutDatagrams\n"
                "Udp: 50 40\n"
            ),
            "proc_net_netstat": (
                "IpExt: InOctets OutOctets\n"
                "IpExt: 123456 654321\n"
            ),
            "proc_net_snmp6": (
                "Ip6InOctets 100\n"
                "Ip6OutOctets 200\n"
                "Udp6InDatagrams 10\n"
                "Udp6OutDatagrams 20\n"
            ),
        }
        output = render_prometheus(build_router_samples(sections, config))
        self.assertIn(
            'asus_netdev_receive_bytes_total{interface="eth0",role="wan",router="gt_axe16000"} 1000',
            output,
        )
        self.assertIn('asus_uptime_seconds{router="gt_axe16000"} 123', output)
        self.assertIn('asus_conntrack_entries{router="gt_axe16000"} 42', output)
        self.assertIn(
            'asus_conntrack_flows{ip_stack="ipv4",protocol="tcp",router="gt_axe16000",state="established",status="assured"} 12',
            output,
        )
        self.assertIn(
            'asus_conntrack_flows{ip_stack="ipv6",protocol="udp",router="gt_axe16000",state="none",status="none"} 3',
            output,
        )
        self.assertIn('asus_snmp_tcp_curr_estab{router="gt_axe16000"} 3', output)
        self.assertIn('asus_snmp_tcp_retrans_segs_total{router="gt_axe16000"} 99', output)
        self.assertIn(
            'asus_ip_stack_receive_octets_total{ip_stack="ipv4",router="gt_axe16000"} 123456',
            output,
        )
        self.assertIn(
            'asus_ip_stack_transmit_octets_total{ip_stack="ipv6",router="gt_axe16000"} 200',
            output,
        )
        self.assertIn(
            'asus_transport_receive_packets_total{ip_stack="ipv4",protocol="tcp",router="gt_axe16000"} 1000',
            output,
        )
        self.assertIn(
            'asus_transport_transmit_packets_total{ip_stack="ipv6",protocol="udp",router="gt_axe16000"} 20',
            output,
        )
        self.assertIn('asus_snmp6_ip6_in_octets_total{router="gt_axe16000"} 100', output)
        self.assertIn(
            'asus_wifi_network_info{bridge="br0",broadcast="1",bss_enabled="1",enabled="1",interface="eth7",prefix="wl0",present="1",radio_enabled="1",router="gt_axe16000",ssid="Home WiFi"} 1',
            output,
        )
        self.assertIn(
            'asus_dhcp_lease_info{client_id="01:aa",hostname="laptop",ip="10.1.10.50",mac="aa:bb:cc:dd:ee:ff",router="gt_axe16000"} 1',
            output,
        )
        self.assertIn('asus_arp_entries{router="gt_axe16000"} 2', output)
        self.assertIn('asus_static_ip_assignments_active{router="gt_axe16000"} 1', output)
        self.assertIn(
            'asus_static_ip_assignments_active_by_interface{interface="br0",router="gt_axe16000"} 1',
            output,
        )

    def test_label_escaping(self):
        output = render_prometheus(
            [
                Sample(
                    "test_metric",
                    1,
                    labels={"quoted": 'a"b', "slash": "a\\b"},
                    help_text="line one\nline two",
                )
            ]
        )
        self.assertIn("# HELP test_metric line one\\nline two", output)
        self.assertIn('quoted="a\\"b"', output)
        self.assertIn('slash="a\\\\b"', output)


if __name__ == "__main__":
    unittest.main()
