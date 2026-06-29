"""HTTP Prometheus exporter for ASUS router telemetry."""

from __future__ import annotations

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
from urllib.parse import urlparse

from . import __version__
from .config import ExporterConfig
from .metrics import build_exporter_samples, build_router_samples, render_prometheus
from .parsers import parse_sections
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

emit_section proc_net_dev cat /proc/net/dev
emit_section proc_net_snmp cat /proc/net/snmp
emit_section proc_net_netstat cat /proc/net/netstat
emit_section proc_uptime cat /proc/uptime
emit_section proc_loadavg cat /proc/loadavg
emit_section proc_meminfo cat /proc/meminfo
emit_conntrack_file conntrack_count /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/ipv4/netfilter/ip_conntrack_count
emit_conntrack_file conntrack_max /proc/sys/net/netfilter/nf_conntrack_max /proc/sys/net/ipv4/netfilter/ip_conntrack_max
emit_dhcp_leases
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
            self.cached_router_samples = build_router_samples(sections, self.config)
            self.last_scrape_success = True
            self.last_success_timestamp_seconds = time.time()
        except RouterSSHError:
            self.last_scrape_success = False
            self.ssh_errors_total += 1
        finally:
            self.last_scrape_duration_seconds = time.monotonic() - started


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
