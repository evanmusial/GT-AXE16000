"""Parsers for Linux/ASUS router command output."""

from __future__ import annotations

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


BEGIN_RE = re.compile(r"^__ASUS_EXPORTER_BEGIN__\s+([A-Za-z0-9_.:-]+)\s*$")
END_RE = re.compile(r"^__ASUS_EXPORTER_END__\s+([A-Za-z0-9_.:-]+)\s*$")


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
