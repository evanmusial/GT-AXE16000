"""HTTP Prometheus exporter for ASUS router telemetry."""

from __future__ import annotations

import argparse
from collections import Counter
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
from urllib.parse import urlparse

from . import __version__
from .config import ExporterConfig
from .metrics import (
    build_exporter_samples,
    build_fcache_wan_samples,
    build_router_samples,
    render_prometheus,
)
from .parsers import FcacheFlow, parse_fcache_nflist, parse_sections
from .router_ssh import RouterSSH, RouterSSHError


METRIC_SNAPSHOT_SCRIPT = r"""
set +e
emit_section() {
  name="$1"
  shift
  printf '\n__ASUS_EXPORTER_BEGIN__ %s\n' "$name"
  "$@" 2>/dev/null || true
  printf '\n__ASUS_EXPORTER_END__ %s\n' "$name"
}

emit_conntrack_file() {
  name="$1"
  first="$2"
  second="$3"
  printf '\n__ASUS_EXPORTER_BEGIN__ %s\n' "$name"
  if [ -r "$first" ]; then
    cat "$first" 2>/dev/null
  elif [ -r "$second" ]; then
    cat "$second" 2>/dev/null
  fi
  printf '\n__ASUS_EXPORTER_END__ %s\n' "$name"
}

emit_dhcp_leases() {
  printf '\n__ASUS_EXPORTER_BEGIN__ dhcp_leases\n'
  for leases_file in \
    /tmp/dhcp.leases \
    /var/lib/misc/dnsmasq.leases \
    /tmp/var/lib/misc/dnsmasq.leases \
    /var/lib/misc/dnsmasq/dnsmasq.leases \
    /tmp/dnsmasq.leases
  do
    if [ -s "$leases_file" ]; then
      cat "$leases_file" 2>/dev/null || true
      break
    fi
  done
  printf '\n__ASUS_EXPORTER_END__ dhcp_leases\n'
}

emit_conntrack_summary() {
  printf '\n__ASUS_EXPORTER_BEGIN__ conntrack_summary\n'
  conntrack_file=""
  if [ -r /proc/net/nf_conntrack ]; then
    conntrack_file=/proc/net/nf_conntrack
  elif [ -r /proc/net/ip_conntrack ]; then
    conntrack_file=/proc/net/ip_conntrack
  fi
  if [ -n "$conntrack_file" ]; then
    awk '
      {
        stack = $1
        proto = $3
        state = "none"
        status = "none"
        if (proto == "tcp" && NF >= 6 && $6 !~ /=/ && $6 !~ /^\[/) {
          state = $6
        }
        for (i = 1; i <= NF; i++) {
          token = $i
          gsub(/^\[/, "", token)
          gsub(/\]$/, "", token)
          if (token == "ASSURED") {
            status = token
            break
          }
          if (token == "UNREPLIED") {
            status = token
            break
          }
          if (token == "EXPECTED") {
            status = token
            break
          }
          if (token == "SEEN_REPLY") {
            status = token
            break
          }
          if (token == "CONFIRMED") {
            status = token
            break
          }
        }
        counts[stack "\t" proto "\t" state "\t" status]++
      }
      END {
        for (key in counts) {
          print key "\t" counts[key]
        }
      }
    ' "$conntrack_file" 2>/dev/null || true
  fi
  printf '\n__ASUS_EXPORTER_END__ conntrack_summary\n'
}

emit_wifi_networks() {
  printf '\n__ASUS_EXPORTER_BEGIN__ wifi_networks\n'
  for prefix in \
    wl0 wl1 wl2 wl3 \
    wl0.1 wl0.2 wl0.3 \
    wl1.1 wl1.2 wl1.3 \
    wl2.1 wl2.2 wl2.3 \
    wl3.1 wl3.2 wl3.3
  do
    ifname=$(nvram get "${prefix}_ifname" 2>/dev/null)
    ssid=$(nvram get "${prefix}_ssid" 2>/dev/null)
    bss_enabled=$(nvram get "${prefix}_bss_enabled" 2>/dev/null)
    radio_enabled=$(nvram get "${prefix}_radio" 2>/dev/null)
    closed=$(nvram get "${prefix}_closed" 2>/dev/null)
    if [ -z "$ifname$ssid$bss_enabled$radio_enabled$closed" ]; then
      continue
    fi

    present=0
    if [ -n "$ifname" ] && [ -d "/sys/class/net/$ifname" ]; then
      present=1
    fi

    bridge=""
    if [ -n "$ifname" ]; then
      for bridge_path in /sys/class/net/br*/brif/"$ifname"; do
        if [ -e "$bridge_path" ]; then
          bridge=${bridge_path#/sys/class/net/}
          bridge=${bridge%%/brif/*}
          break
        fi
      done
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$prefix" "$ifname" "$ssid" "${bss_enabled:-0}" \
      "${radio_enabled:-0}" "${closed:-0}" "$present" "$bridge"
  done
  printf '\n__ASUS_EXPORTER_END__ wifi_networks\n'
}

emit_section proc_net_dev cat /proc/net/dev
emit_section proc_net_snmp cat /proc/net/snmp
emit_section proc_net_netstat cat /proc/net/netstat
emit_section proc_net_snmp6 cat /proc/net/snmp6
emit_section proc_uptime cat /proc/uptime
emit_section proc_loadavg cat /proc/loadavg
emit_section proc_meminfo cat /proc/meminfo
emit_conntrack_file conntrack_count /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/ipv4/netfilter/ip_conntrack_count
emit_conntrack_file conntrack_max /proc/sys/net/netfilter/nf_conntrack_max /proc/sys/net/ipv4/netfilter/ip_conntrack_max
emit_conntrack_summary
emit_dhcp_leases
emit_section arp_table arp -n
emit_wifi_networks
emit_section fcache_nflist cat /proc/fcache/nflist
"""


class ExporterState:
    def __init__(self, config: ExporterConfig, router: RouterSSH) -> None:
        self.config = config
        self.router = router
        self.lock = threading.Lock()
        self.last_attempt_monotonic = 0.0
        self.last_scrape_success = False
        self.last_scrape_duration_seconds = 0.0
        self.last_success_timestamp_seconds: float | None = None
        self.ssh_errors_total = 0
        self.cached_router_samples = []
        self.fcache_previous: dict[str, FcacheFlow] = {}
        self.fcache_wan_counters: Counter[tuple[str, str]] = Counter()

    def metrics_text(self, force: bool = False) -> str:
        with self.lock:
            now = time.monotonic()
            if force or now - self.last_attempt_monotonic >= self.config.scrape_interval_seconds:
                self._refresh_locked()
            exporter_samples = build_exporter_samples(
                self.config,
                scrape_success=self.last_scrape_success,
                scrape_duration_seconds=self.last_scrape_duration_seconds,
                last_success_timestamp_seconds=self.last_success_timestamp_seconds,
                ssh_errors_total=self.ssh_errors_total,
            )
            return render_prometheus([*self.cached_router_samples, *exporter_samples])

    def _refresh_locked(self) -> None:
        self.last_attempt_monotonic = time.monotonic()
        started = time.monotonic()
        try:
            raw_output = self.router.run_script(METRIC_SNAPSHOT_SCRIPT)
            sections = parse_sections(raw_output)
            self._update_fcache_wan_counters(sections)
            self.cached_router_samples = [
                *build_router_samples(sections, self.config),
                *build_fcache_wan_samples(self.config, self.fcache_wan_counters),
            ]
            self.last_scrape_success = True
            self.last_success_timestamp_seconds = time.time()
        except RouterSSHError:
            self.last_scrape_success = False
            self.ssh_errors_total += 1
        finally:
            self.last_scrape_duration_seconds = time.monotonic() - started

    def _update_fcache_wan_counters(self, sections: dict[str, str]) -> None:
        wan_interface = self.config.wan_interface
        if not wan_interface:
            self.fcache_previous = {}
            return

        current: dict[str, FcacheFlow] = {}
        for flow in parse_fcache_nflist(sections.get("fcache_nflist", "")):
            if flow.rx_dev != wan_interface and flow.tx_dev != wan_interface:
                continue
            previous = self.fcache_previous.get(flow.flow_key)
            if previous is not None and flow.total_bytes >= previous.total_bytes:
                delta = flow.total_bytes - previous.total_bytes
                if delta > 0:
                    if flow.rx_dev == wan_interface:
                        self.fcache_wan_counters[("receive", flow.ip_stack)] += delta
                    if flow.tx_dev == wan_interface:
                        self.fcache_wan_counters[("transmit", flow.ip_stack)] += delta
            current[flow.flow_key] = flow
        self.fcache_previous = current


class MetricsHandler(BaseHTTPRequestHandler):
    server_version = f"ASUSRouterExporter/{__version__}"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/metrics":
            self._write_metrics()
            return
        if path in {"/", "/-/healthy"}:
            self._write_text(HTTPStatus.OK, "ok\n")
            return
        self._write_text(HTTPStatus.NOT_FOUND, "not found\n")

    def _write_metrics(self) -> None:
        state: ExporterState = self.server.exporter_state  # type: ignore[attr-defined]
        body = state.metrics_text().encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_text(self, status: HTTPStatus, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(config: ExporterConfig) -> None:
    router = RouterSSH(config)
    state = ExporterState(config, router)
    server = ThreadingHTTPServer((config.bind_address, config.listen_port), MetricsHandler)
    server.exporter_state = state  # type: ignore[attr-defined]
    print(
        f"asus-router-exporter listening on "
        f"http://{config.bind_address}:{config.listen_port}/metrics",
        flush=True,
    )
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ASUS GT-AXE16000 Prometheus exporter")
    parser.add_argument("--once", action="store_true", help="print one metrics scrape and exit")
    parser.add_argument("--bind-address", help="override ASUS_EXPORTER_BIND_ADDRESS")
    parser.add_argument("--port", type=int, help="override ASUS_EXPORTER_PORT")
    args = parser.parse_args(argv)

    config = ExporterConfig.from_env()
    if args.bind_address:
        config = _replace_config(config, bind_address=args.bind_address)
    if args.port:
        config = _replace_config(config, listen_port=args.port)

    if args.once:
        state = ExporterState(config, RouterSSH(config))
        print(state.metrics_text(force=True), end="")
        return 0 if state.last_scrape_success else 1

    serve(config)
    return 0


def _replace_config(config: ExporterConfig, **changes: object) -> ExporterConfig:
    values = config.__dict__.copy()
    values.update(changes)
    return ExporterConfig(**values)


if __name__ == "__main__":
    raise SystemExit(main())
