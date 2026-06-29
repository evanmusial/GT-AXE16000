"""Prometheus metric construction and rendering."""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import Counter
import math
import time
from typing import Iterable

from .config import ExporterConfig
from .parsers import (
    ArpEntry,
    parse_dhcp_leases,
    parse_arp_table,
    parse_int,
    parse_loadavg,
    parse_meminfo,
    parse_net_dev,
    parse_protocol_table,
    parse_uptime,
    snake_case,
)


@dataclass(frozen=True)
class Sample:
    name: str
    value: int | float
    labels: dict[str, str] = field(default_factory=dict)
    metric_type: str = "gauge"
    help_text: str = ""


class MetricBuilder:
    def __init__(self) -> None:
        self.samples: list[Sample] = []

    def add(
        self,
        name: str,
        value: int | float | None,
        labels: dict[str, str] | None = None,
        metric_type: str = "gauge",
        help_text: str = "",
    ) -> None:
        if value is None:
            return
        self.samples.append(
            Sample(
                name=name,
                value=value,
                labels=labels or {},
                metric_type=metric_type,
                help_text=help_text,
            )
        )


NETDEV_METRICS: dict[str, tuple[str, str]] = {
    "receive_bytes": ("asus_netdev_receive_bytes_total", "counter"),
    "receive_packets": ("asus_netdev_receive_packets_total", "counter"),
    "receive_errs": ("asus_netdev_receive_errs_total", "counter"),
    "receive_drop": ("asus_netdev_receive_drop_total", "counter"),
    "receive_fifo": ("asus_netdev_receive_fifo_total", "counter"),
    "receive_frame": ("asus_netdev_receive_frame_total", "counter"),
    "receive_compressed": ("asus_netdev_receive_compressed_total", "counter"),
    "receive_multicast": ("asus_netdev_receive_multicast_total", "counter"),
    "transmit_bytes": ("asus_netdev_transmit_bytes_total", "counter"),
    "transmit_packets": ("asus_netdev_transmit_packets_total", "counter"),
    "transmit_errs": ("asus_netdev_transmit_errs_total", "counter"),
    "transmit_drop": ("asus_netdev_transmit_drop_total", "counter"),
    "transmit_fifo": ("asus_netdev_transmit_fifo_total", "counter"),
    "transmit_colls": ("asus_netdev_transmit_colls_total", "counter"),
    "transmit_carrier": ("asus_netdev_transmit_carrier_total", "counter"),
    "transmit_compressed": ("asus_netdev_transmit_compressed_total", "counter"),
}

MEMINFO_METRICS = {
    "MemTotal": "asus_memory_mem_total_bytes",
    "MemFree": "asus_memory_mem_free_bytes",
    "MemAvailable": "asus_memory_mem_available_bytes",
    "Buffers": "asus_memory_buffers_bytes",
    "Cached": "asus_memory_cached_bytes",
}

SNMP_GAUGES = {
    ("ip", "forwarding"),
    ("ip", "default_ttl"),
    ("tcp", "rto_algorithm"),
    ("tcp", "rto_min"),
    ("tcp", "rto_max"),
    ("tcp", "max_conn"),
    ("tcp", "curr_estab"),
}


def build_router_samples(sections: dict[str, str], config: ExporterConfig) -> list[Sample]:
    builder = MetricBuilder()
    base_labels = {"router": config.router_label}

    for interface, values in parse_net_dev(sections.get("proc_net_dev", "")).items():
        role = "wan" if config.wan_interface and interface == config.wan_interface else "interface"
        labels = {**base_labels, "interface": interface, "role": role}
        for source_name, value in values.items():
            metric_name, metric_type = NETDEV_METRICS[source_name]
            builder.add(
                metric_name,
                value,
                labels=labels,
                metric_type=metric_type,
                help_text=f"Router network device {source_name.replace('_', ' ')}.",
            )

    uptime = parse_uptime(sections.get("proc_uptime", ""))
    builder.add(
        "asus_uptime_seconds",
        uptime,
        labels=base_labels,
        help_text="Router uptime in seconds.",
    )

    loadavg = parse_loadavg(sections.get("proc_loadavg", ""))
    if loadavg is not None:
        load1, load5, load15 = loadavg
        builder.add("asus_load1", load1, labels=base_labels, help_text="Router 1 minute load.")
        builder.add("asus_load5", load5, labels=base_labels, help_text="Router 5 minute load.")
        builder.add("asus_load15", load15, labels=base_labels, help_text="Router 15 minute load.")

    meminfo = parse_meminfo(sections.get("proc_meminfo", ""))
    for source_key, metric_name in MEMINFO_METRICS.items():
        builder.add(
            metric_name,
            meminfo.get(source_key),
            labels=base_labels,
            help_text=f"Router memory {source_key} in bytes.",
        )

    builder.add(
        "asus_conntrack_entries",
        parse_int(sections.get("conntrack_count", "")),
        labels=base_labels,
        help_text="Current conntrack entry count.",
    )
    builder.add(
        "asus_conntrack_entries_max",
        parse_int(sections.get("conntrack_max", "")),
        labels=base_labels,
        help_text="Maximum conntrack entry count.",
    )

    leases = parse_dhcp_leases(sections.get("dhcp_leases", ""))
    lease_ips = {lease.ip for lease in leases}
    builder.add(
        "asus_dhcp_leases",
        len(leases),
        labels=base_labels,
        help_text="Number of current DHCP leases.",
    )
    for lease in leases:
        builder.add(
            "asus_dhcp_lease_info",
            1,
            labels={
                **base_labels,
                "ip": lease.ip,
                "mac": lease.mac,
                "hostname": lease.hostname,
                "client_id": lease.client_id,
            },
            help_text="DHCP lease metadata. Value is always 1.",
        )

    arp_entries = parse_arp_table(sections.get("arp_table", ""))
    lan_arp_entries = _lan_arp_entries(arp_entries, config)
    static_entries = [entry for entry in lan_arp_entries if entry.ip not in lease_ips]
    builder.add(
        "asus_arp_entries",
        len(lan_arp_entries),
        labels=base_labels,
        help_text="Complete ARP entries on non-WAN interfaces.",
    )
    builder.add(
        "asus_static_ip_assignments_active",
        len(static_entries),
        labels=base_labels,
        help_text=(
            "Active non-DHCP clients inferred from complete ARP entries on "
            "non-WAN interfaces whose IPs are absent from current DHCP leases."
        ),
    )
    for interface, count in sorted(Counter(entry.interface for entry in static_entries).items()):
        builder.add(
            "asus_static_ip_assignments_active_by_interface",
            count,
            labels={**base_labels, "interface": interface},
            help_text="Active inferred non-DHCP clients by router interface.",
        )

    _add_protocol_samples(
        builder,
        sections.get("proc_net_snmp", ""),
        base_labels,
        prefix="asus_snmp",
        help_source="/proc/net/snmp",
    )
    _add_protocol_samples(
        builder,
        sections.get("proc_net_netstat", ""),
        base_labels,
        prefix="asus_netstat",
        help_source="/proc/net/netstat",
    )

    return builder.samples


def _lan_arp_entries(entries: list[ArpEntry], config: ExporterConfig) -> list[ArpEntry]:
    if not config.wan_interface:
        return entries
    return [entry for entry in entries if entry.interface != config.wan_interface]


def build_exporter_samples(
    config: ExporterConfig,
    scrape_success: bool,
    scrape_duration_seconds: float,
    last_success_timestamp_seconds: float | None,
    ssh_errors_total: int,
) -> list[Sample]:
    labels = {"router": config.router_label}
    timestamp = last_success_timestamp_seconds or 0
    return [
        Sample(
            "asus_exporter_scrape_success",
            1 if scrape_success else 0,
            labels=labels,
            help_text="Whether the last router scrape succeeded.",
        ),
        Sample(
            "asus_exporter_scrape_duration_seconds",
            scrape_duration_seconds,
            labels=labels,
            help_text="Duration of the last router scrape in seconds.",
        ),
        Sample(
            "asus_exporter_last_scrape_timestamp_seconds",
            timestamp,
            labels=labels,
            help_text="Unix timestamp of the last successful router scrape.",
        ),
        Sample(
            "asus_exporter_ssh_errors_total",
            ssh_errors_total,
            labels=labels,
            metric_type="counter",
            help_text="Number of SSH scrape failures since exporter start.",
        ),
    ]


def _add_protocol_samples(
    builder: MetricBuilder,
    text: str,
    base_labels: dict[str, str],
    prefix: str,
    help_source: str,
) -> None:
    for (family, field), value in parse_protocol_table(text).items():
        family_name = snake_case(family)
        field_name = snake_case(field)
        is_gauge = prefix == "asus_snmp" and (family_name, field_name) in SNMP_GAUGES
        suffix = "" if is_gauge else "_total"
        builder.add(
            f"{prefix}_{family_name}_{field_name}{suffix}",
            value,
            labels=base_labels,
            metric_type="gauge" if is_gauge else "counter",
            help_text=f"Router {help_source} {family} {field}.",
        )


def render_prometheus(samples: Iterable[Sample]) -> str:
    lines: list[str] = []
    seen: set[str] = set()
    for sample in samples:
        if sample.name not in seen:
            help_text = sample.help_text or sample.name
            lines.append(f"# HELP {sample.name} {_escape_help(help_text)}")
            lines.append(f"# TYPE {sample.name} {sample.metric_type}")
            seen.add(sample.name)
        lines.append(_render_sample(sample))
    lines.append("")
    return "\n".join(lines)


def _render_sample(sample: Sample) -> str:
    labels = _render_labels(sample.labels)
    return f"{sample.name}{labels} {_format_value(sample.value)}"


def _render_labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    rendered = ",".join(
        f'{key}="{_escape_label_value(value)}"' for key, value in sorted(labels.items())
    )
    return f"{{{rendered}}}"


def _escape_help(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n")


def _escape_label_value(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _format_value(value: int | float) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    return f"{value:.17g}"


def now_seconds() -> float:
    return time.time()
