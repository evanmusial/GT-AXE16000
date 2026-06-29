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
- DHCP lease count and lease metadata.
- Protocol counters from `/proc/net/snmp` and `/proc/net/netstat`.
- Exporter self-metrics for scrape success, duration, last success timestamp,
  and SSH error count.

Useful PromQL examples:

```promql
rate(asus_netdev_receive_bytes_total{router="gt_axe16000",interface="eth0"}[5m]) * 8
rate(asus_netdev_transmit_bytes_total{router="gt_axe16000",interface="eth0"}[5m]) * 8
increase(asus_netdev_receive_bytes_total{router="gt_axe16000",interface="eth0"}[1d])
asus_conntrack_entries{router="gt_axe16000"} / asus_conntrack_entries_max{router="gt_axe16000"} * 100
rate(asus_snmp_tcp_retrans_segs_total{router="gt_axe16000"}[5m])
```

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
