# ASUS GT-AXE16000 Prometheus Exporter

Python Prometheus exporter for an ASUS ROG Rapture GT-AXE16000 router. The
exporter runs on a Linux host, polls the router over SSH, and exposes metrics at
`/metrics` for Prometheus/Grafana.

The router is treated as a read-only telemetry source. Nothing is installed on
the router and v1 does not create firewall or accounting rules.

The default scrape cadence is once per minute, which is enough for a broad
traffic and health overview without chasing high-resolution packet detail.

## Defaults

```text
ASUS_ROUTER_HOST=10.1.10.1
ASUS_ROUTER_PORT=22122
ASUS_ROUTER_USER=admin
ASUS_ROUTER_LABEL=gt_axe16000
ASUS_WAN_INTERFACE=
ASUS_SSH_USER_KNOWN_HOSTS_FILE=
ASUS_EXPORTER_BIND_ADDRESS=127.0.0.1
ASUS_EXPORTER_PORT=9818
ASUS_EXPORTER_SCRAPE_INTERVAL_SECONDS=60
```

If the service user needs an explicit SSH key, set:

```text
ASUS_ROUTER_IDENTITY_FILE=/home/asus-exporter/.ssh/asus_gt_axe16000
```

On `carrot` with Ubuntu 24.04, use the included systemd unit as the deployment
template. It sets `ASUS_SSH_USER_KNOWN_HOSTS_FILE=/var/lib/asus-router-exporter/known_hosts`
so SSH can remember the router host key even with systemd hardening enabled.

## Local Run

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m asus_exporter.exporter
```

Then scrape:

```bash
curl http://127.0.0.1:9818/metrics
```

For a single scrape without starting the HTTP server:

```bash
python -m asus_exporter.exporter --once
```

## Recon

Collect a read-only router snapshot before choosing the WAN interface:

```bash
python scripts/recon.py --output recon-$(date -u +%Y%m%dT%H%M%SZ).txt
```

The recon command gathers:

- WAN-related `nvram` values.
- `ip route`, `ip -br addr`, and `brctl show`.
- `/proc/net/dev`, `/proc/net/snmp`, and `/proc/net/netstat`.
- uptime, load, memory, conntrack, ARP, DHCP leases, and Wi-Fi command probes.

To identify the WAN interface, compare `/proc/net/dev` counters before and
after a controlled WAN speed test from a LAN client. Once confirmed, set
`ASUS_WAN_INTERFACE` in the systemd service. The exporter will preserve the raw
`interface` label and add `role="wan"` to that interface.

## Metrics

The initial exporter covers:

- Interface counters from `/proc/net/dev`.
- Router uptime and load.
- Memory totals/free/available/buffers/cache.
- Conntrack current/max entries.
- Conntrack flow counts by IP stack, protocol, TCP state, and conntrack status.
- DHCP lease count and lease metadata.
- Active static-IP clients inferred from ARP entries on non-WAN interfaces
  whose IPs are not present in current DHCP leases.
- Wi-Fi network metadata from `nvram`, including interface, SSID, bridge,
  enabled/broadcast state, and whether the interface exists.
- Protocol counters from `/proc/net/snmp`, `/proc/net/netstat`, and
  `/proc/net/snmp6`.
- Normalized IPv4/IPv6 IP-layer octet counters where exposed by the router.
- Best-effort WAN byte hints by IPv4/IPv6 stack from Broadcom flow-cache
  active-flow deltas. These are diagnostic and are not additive WAN totals.
- Normalized transport packet counters for TCP segments and UDP datagrams
  where exposed by the router.
- Exporter self-metrics for scrape success, duration, last success timestamp,
  and SSH error count.

Static-IP counts are active-client counts, not an inventory of offline static
assignments. A manually configured device must have a current ARP entry for the
router to see it.

Useful PromQL examples:

```promql
irate(asus_netdev_receive_bytes_total{router="gt_axe16000",interface="eth0"}[3m]) * 8
irate(asus_netdev_transmit_bytes_total{router="gt_axe16000",interface="eth0"}[3m]) * 8
increase(asus_netdev_receive_bytes_total{router="gt_axe16000",interface="eth0"}[1d])
asus_conntrack_entries{router="gt_axe16000"} / asus_conntrack_entries_max{router="gt_axe16000"} * 100
rate(asus_snmp_tcp_retrans_segs_total{router="gt_axe16000"}[3m])
asus_static_ip_assignments_active{router="gt_axe16000"}
increase(asus_netdev_receive_bytes_total{router="gt_axe16000",role="wan"}[1d])
increase(asus_netdev_receive_bytes_total{router="gt_axe16000",role="wan"}[7d])
increase(asus_netdev_receive_bytes_total{router="gt_axe16000",role="wan"}[30d])
asus_netdev_receive_bytes_total{router="gt_axe16000",role="wan"}
increase(asus_netdev_transmit_bytes_total{router="gt_axe16000",role="wan"}[1d])
increase(asus_netdev_transmit_bytes_total{router="gt_axe16000",role="wan"}[7d])
increase(asus_netdev_transmit_bytes_total{router="gt_axe16000",role="wan"}[30d])
asus_netdev_transmit_bytes_total{router="gt_axe16000",role="wan"}
sum by (ip_stack, protocol, state) (asus_conntrack_flows{router="gt_axe16000"})
irate(asus_ip_stack_receive_octets_total{router="gt_axe16000"}[3m]) * 8
sum by (ip_stack) (irate(asus_fcache_wan_receive_bytes_total{router="gt_axe16000"}[3m])) * 8
sum by (ip_stack) (irate(asus_fcache_wan_transmit_bytes_total{router="gt_axe16000"}[3m])) * 8
irate(asus_transport_receive_packets_total{router="gt_axe16000"}[3m])
(irate(asus_netdev_receive_bytes_total{router="gt_axe16000"}[3m]) * 8)
  * on(router, interface) group_left(ssid, prefix, bridge)
    asus_wifi_network_info{router="gt_axe16000",enabled="1",present="1"}
```

The exporter is normally scraped every 60 seconds. Prometheus counter functions
need at least two samples in the lookback range, so a 1-minute `rate()` window
will often graph no data. Use a 3-minute lookback for live panels; `irate()`
still reports the newest scrape-to-scrape delta while leaving enough room for
normal scrape jitter.

WAN byte totals use the `/proc/net/dev` counters. `increase(...[1d])`,
`increase(...[7d])`, and `increase(...[30d])` provide rolling daily, weekly,
and 30-day totals. The raw WAN byte counter is effectively "since interface
counter reset," which normally corresponds to router/interface reboot. Longer
windows require enough Prometheus retention and scrape history.

The normalized `asus_ip_stack_*` counters come from router kernel IP-layer
tables. They do not necessarily add up to WAN interface throughput on this
Broadcom platform because hardware acceleration can update interface counters
while bypassing the normal Linux IP accounting path. Use
`asus_netdev_*{role="wan"}` for authoritative WAN totals. Use
`asus_fcache_wan_*` only as a read-only diagnostic hint about active flow-cache
stack mix. On observed GT-AXE16000 firmware, `/proc/fcache/nflist`
`TotalBytes` undercounts hardware-hit byte volume, and Broadcom `fc flwstats`
can count hardware bytes by stack but could not be safely filtered to `eth0`.
That means an exact additive IPv4/IPv6 WAN split is not available from current
read-only counters. Getting one would require changing router accounting, such
as disabling acceleration for validation, adding firewall/accounting rules, or
measuring at another choke point.

Read-only TCP/UDP byte throughput is not generally available from stock router
kernel counters. The exporter therefore exposes byte throughput by interface
and by IP stack, plus TCP segment and UDP datagram rates by protocol where the
router exposes those counters. True byte accounting by TCP/UDP port or protocol
would require router-side firewall/accounting rules and can be distorted by
hardware acceleration.

## Prometheus and Grafana

- `prometheus/asus-router-exporter.yml` contains a scrape config snippet.
- `grafana/asus-gt-axe16000-dashboard.json` contains a starter dashboard.
- `systemd/asus-router-exporter.service` contains a service template for
  `/opt/asus-router-exporter`.

Example Ubuntu 24.04 deployment shape on `carrot`:

```bash
sudo apt install python3-venv openssh-client
sudo useradd --system --home /home/asus-exporter --create-home --shell /usr/sbin/nologin asus-exporter
sudo mkdir -p /opt
sudo cp -a /path/to/GT-AXE16000 /opt/asus-router-exporter
sudo chown -R asus-exporter:asus-exporter /opt/asus-router-exporter
sudo -u asus-exporter python3 -m venv /opt/asus-router-exporter/.venv
sudo -u asus-exporter /opt/asus-router-exporter/.venv/bin/python -m pip install /opt/asus-router-exporter
sudo install -m 0644 systemd/asus-router-exporter.service /etc/systemd/system/asus-router-exporter.service
sudo systemctl daemon-reload
sudo systemctl enable --now asus-router-exporter
```

Adjust `/path/to/GT-AXE16000` if you clone directly on `carrot` or deploy with
another copy/sync method.

## Phase 2

Per-client bandwidth is intentionally left out of v1. On stock ASUS/Broadcom
firmware it generally requires router-side `iptables` accounting rules and may
undercount traffic when hardware acceleration bypasses Linux netfilter. Add it
only after the WAN/interface totals are validated.

## Tests

```bash
python -m unittest discover -s tests -p 'test_*.py'
```
