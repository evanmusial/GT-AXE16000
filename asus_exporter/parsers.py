"""Parsers for Linux/ASUS router command output."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re


NETDEV_RECEIVE_FIELDS = (
    "bytes",
    "packets",
    "errs",
    "drop",
    "fifo",
    "frame",
    "compressed",
    "multicast",
)
NETDEV_TRANSMIT_FIELDS = (
    "bytes",
    "packets",
    "errs",
    "drop",
    "fifo",
    "colls",
    "carrier",
    "compressed",
)


@dataclass(frozen=True)
class DhcpLease:
    expiry_epoch: str
    mac: str
    ip: str
    hostname: str
    client_id: str


@dataclass(frozen=True)
class ArpEntry:
    ip: str
    mac: str
    interface: str
    flags: str


@dataclass(frozen=True)
class ConntrackFlowCount:
    ip_stack: str
    protocol: str
    state: str
    status: str
    count: int


@dataclass(frozen=True)
class WifiNetwork:
    prefix: str
    interface: str
    ssid: str
    bss_enabled: str
    radio_enabled: str
    closed: str
    present: str
    bridge: str


@dataclass(frozen=True)
class FcacheFlow:
    flow_key: str
    ip_stack: str
    rx_dev: str
    tx_dev: str
    total_bytes: int


BEGIN_RE = re.compile(r"^__ASUS_EXPORTER_BEGIN__\s+([A-Za-z0-9_.:-]+)\s*$")
END_RE = re.compile(r"^__ASUS_EXPORTER_END__\s+([A-Za-z0-9_.:-]+)\s*$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
FCACHE_TUPLE_RE = re.compile(r"<([^>]*)>")
BUSYBOX_ARP_RE = re.compile(
    r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+"
    r"(?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+.*\s+on\s+(?P<iface>\S+)"
)


def parse_sections(output: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in output.splitlines():
        begin = BEGIN_RE.match(line)
        if begin:
            current = begin.group(1)
            sections.setdefault(current, [])
            continue

        end = END_RE.match(line)
        if end:
            current = None
            continue

        if current is not None:
            sections[current].append(line)

    return {name: "\n".join(lines).strip("\n") for name, lines in sections.items()}


def parse_net_dev(text: str) -> dict[str, dict[str, int]]:
    interfaces: dict[str, dict[str, int]] = {}
    for raw_line in text.splitlines():
        if ":" not in raw_line:
            continue
        name, raw_values = raw_line.split(":", 1)
        interface = name.strip()
        values = raw_values.split()
        if len(values) < 16:
            continue
        try:
            numbers = [int(value) for value in values[:16]]
        except ValueError:
            continue

        metrics: dict[str, int] = {}
        for index, field in enumerate(NETDEV_RECEIVE_FIELDS):
            metrics[f"receive_{field}"] = numbers[index]
        for index, field in enumerate(NETDEV_TRANSMIT_FIELDS, start=8):
            metrics[f"transmit_{field}"] = numbers[index]
        interfaces[interface] = metrics
    return interfaces


def parse_protocol_table(text: str) -> dict[tuple[str, str], int]:
    rows: dict[tuple[str, str], int] = {}
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    index = 0
    while index + 1 < len(lines):
        header = lines[index]
        values = lines[index + 1]
        index += 2
        if ":" not in header or ":" not in values:
            continue
        header_family, header_fields = header.split(":", 1)
        values_family, raw_values = values.split(":", 1)
        if header_family != values_family:
            continue
        fields = header_fields.split()
        value_parts = raw_values.split()
        for field, value in zip(fields, value_parts):
            try:
                rows[(header_family, field)] = int(value)
            except ValueError:
                continue
    return rows


def parse_snmp6(text: str) -> dict[str, int]:
    rows: dict[str, int] = {}
    for raw_line in text.splitlines():
        parts = raw_line.split()
        if len(parts) != 2:
            continue
        try:
            rows[parts[0]] = int(parts[1])
        except ValueError:
            continue
    return rows


def parse_uptime(text: str) -> float | None:
    parts = text.split()
    if not parts:
        return None
    try:
        return float(parts[0])
    except ValueError:
        return None


def parse_loadavg(text: str) -> tuple[float, float, float] | None:
    parts = text.split()
    if len(parts) < 3:
        return None
    try:
        return float(parts[0]), float(parts[1]), float(parts[2])
    except ValueError:
        return None


def parse_meminfo(text: str) -> dict[str, int]:
    metrics: dict[str, int] = {}
    for raw_line in text.splitlines():
        if ":" not in raw_line:
            continue
        key, raw_value = raw_line.split(":", 1)
        parts = raw_value.split()
        if not parts:
            continue
        try:
            value = int(parts[0])
        except ValueError:
            continue
        multiplier = 1024 if len(parts) > 1 and parts[1].lower() == "kb" else 1
        metrics[key] = value * multiplier
    return metrics


def parse_int(text: str) -> int | None:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return int(stripped.split()[0])
    except (ValueError, IndexError):
        return None


def parse_dhcp_leases(text: str) -> list[DhcpLease]:
    leases: list[DhcpLease] = []
    for raw_line in text.splitlines():
        parts = raw_line.split()
        if len(parts) < 4:
            continue
        expiry_epoch, mac, ip, hostname = parts[:4]
        client_id = parts[4] if len(parts) > 4 else ""
        leases.append(
            DhcpLease(
                expiry_epoch=expiry_epoch,
                mac=mac,
                ip=ip,
                hostname="" if hostname == "*" else hostname,
                client_id="" if client_id == "*" else client_id,
            )
        )
    return leases


def parse_arp_table(text: str) -> list[ArpEntry]:
    entries: list[ArpEntry] = []
    for raw_line in text.splitlines():
        busybox_match = BUSYBOX_ARP_RE.search(raw_line)
        if busybox_match:
            entries.append(
                ArpEntry(
                    ip=busybox_match.group("ip"),
                    mac=busybox_match.group("mac").lower(),
                    interface=busybox_match.group("iface"),
                    flags="",
                )
            )
            continue

        parts = raw_line.split()
        if len(parts) < 4 or not IPV4_RE.match(parts[0]):
            continue

        mac = next((part.lower() for part in parts if MAC_RE.match(part)), "")
        if not mac or mac == "00:00:00:00:00:00":
            continue

        interface = parts[-1]
        flags = ""
        for part in parts[1:]:
            if part.startswith("0x") or part in {"C", "M", "CM", "PERM"}:
                flags = part
                break

        entries.append(ArpEntry(ip=parts[0], mac=mac, interface=interface, flags=flags))
    return entries


def parse_conntrack_summary(text: str) -> list[ConntrackFlowCount]:
    counts: Counter[tuple[str, str, str, str]] = Counter()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        summary = _parse_conntrack_summary_line(line)
        if summary is not None:
            key, count = summary
            counts[key] += count
            continue

        raw_key = _parse_conntrack_raw_line(line)
        if raw_key is not None:
            counts[raw_key] += 1

    return [
        ConntrackFlowCount(
            ip_stack=ip_stack,
            protocol=protocol,
            state=state,
            status=status,
            count=count,
        )
        for (ip_stack, protocol, state, status), count in sorted(counts.items())
    ]


def _parse_conntrack_summary_line(line: str) -> tuple[tuple[str, str, str, str], int] | None:
    parts = line.split("\t")
    if len(parts) != 5:
        return None
    try:
        count = int(parts[4])
    except ValueError:
        return None
    return (
        (
            _conntrack_label(parts[0]),
            _conntrack_label(parts[1]),
            _conntrack_label(parts[2] or "none"),
            _conntrack_label(parts[3] or "none"),
        ),
        count,
    )


def _parse_conntrack_raw_line(line: str) -> tuple[str, str, str, str] | None:
    parts = line.split()
    if len(parts) < 3:
        return None

    ip_stack = _conntrack_label(parts[0])
    protocol = _conntrack_label(parts[2])
    state = "none"
    status = "none"

    if protocol == "tcp" and len(parts) > 5:
        candidate = parts[5]
        if "=" not in candidate and not candidate.startswith("["):
            state = _conntrack_label(candidate)

    for part in parts:
        token = part.strip("[]")
        normalized = _conntrack_label(token)
        if normalized in {"assured", "unreplied", "expected", "seen_reply", "confirmed"}:
            status = normalized
            break

    return ip_stack, protocol, state, status


def _conntrack_label(value: str) -> str:
    normalized = snake_case(value)
    return normalized or "unknown"


def parse_wifi_networks(text: str) -> list[WifiNetwork]:
    networks: list[WifiNetwork] = []
    for raw_line in text.splitlines():
        parts = raw_line.split("\t")
        if len(parts) != 8:
            continue
        prefix, interface, ssid, bss_enabled, radio_enabled, closed, present, bridge = parts
        if not prefix:
            continue
        networks.append(
            WifiNetwork(
                prefix=prefix,
                interface=interface,
                ssid=ssid,
                bss_enabled=bss_enabled,
                radio_enabled=radio_enabled,
                closed=closed,
                present=present,
                bridge=bridge,
            )
        )
    return networks


def parse_fcache_nflist(text: str) -> list[FcacheFlow]:
    flows: list[FcacheFlow] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("id ") or line.startswith("--------"):
            continue

        parts = line.split()
        if len(parts) < 12:
            continue
        try:
            int(parts[0])
            total_bytes = int(parts[6])
        except ValueError:
            continue

        tuple_parts = FCACHE_TUPLE_RE.findall(line)
        ip_stack = _fcache_ip_stack(tuple_parts)
        if ip_stack is None:
            continue

        rx_dev = parts[-6]
        tx_dev = parts[-5]
        flow_key = "|".join((parts[0], ip_stack, rx_dev, tx_dev, *tuple_parts[:2]))
        flows.append(
            FcacheFlow(
                flow_key=flow_key,
                ip_stack=ip_stack,
                rx_dev=rx_dev,
                tx_dev=tx_dev,
                total_bytes=total_bytes,
            )
        )
    return flows


def _fcache_ip_stack(tuple_parts: list[str]) -> str | None:
    for tuple_part in tuple_parts[:2]:
        if "." in tuple_part:
            return "ipv4"
        if ":" in tuple_part:
            return "ipv6"
    return None


_FIRST_CAP_RE = re.compile("(.)([A-Z][a-z]+)")
_SECOND_CAP_RE = re.compile("([a-z0-9])([A-Z])")
_NON_IDENTIFIER_RE = re.compile("[^a-zA-Z0-9_]")
_MULTI_UNDERSCORE_RE = re.compile("_+")


def snake_case(value: str) -> str:
    value = _FIRST_CAP_RE.sub(r"\1_\2", value)
    value = _SECOND_CAP_RE.sub(r"\1_\2", value)
    value = _NON_IDENTIFIER_RE.sub("_", value)
    value = _MULTI_UNDERSCORE_RE.sub("_", value).strip("_").lower()
    if not value:
        return "unknown"
    if value[0].isdigit():
        return f"field_{value}"
    return value
