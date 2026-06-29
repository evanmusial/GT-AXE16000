"""Configuration helpers for the ASUS router exporter."""

from __future__ import annotations

from dataclasses import dataclass
import os


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {value!r}") from exc


@dataclass(frozen=True)
class ExporterConfig:
    router_host: str = "10.1.10.1"
    router_port: int = 22122
    router_user: str = "admin"
    router_label: str = "gt_axe16000"
    wan_interface: str = ""
    identity_file: str = ""
    user_known_hosts_file: str = ""
    ssh_connect_timeout: int = 5
    ssh_command_timeout: int = 12
    ssh_strict_host_key_checking: str = "accept-new"
    bind_address: str = "127.0.0.1"
    listen_port: int = 9818
    scrape_interval_seconds: float = 60.0

    @classmethod
    def from_env(cls) -> "ExporterConfig":
        return cls(
            router_host=os.getenv("ASUS_ROUTER_HOST", cls.router_host),
            router_port=_env_int("ASUS_ROUTER_PORT", cls.router_port),
            router_user=os.getenv("ASUS_ROUTER_USER", cls.router_user),
            router_label=os.getenv("ASUS_ROUTER_LABEL", cls.router_label),
            wan_interface=os.getenv("ASUS_WAN_INTERFACE", cls.wan_interface),
            identity_file=os.getenv("ASUS_ROUTER_IDENTITY_FILE", cls.identity_file),
            user_known_hosts_file=os.getenv(
                "ASUS_SSH_USER_KNOWN_HOSTS_FILE",
                cls.user_known_hosts_file,
            ),
            ssh_connect_timeout=_env_int(
                "ASUS_SSH_CONNECT_TIMEOUT_SECONDS", cls.ssh_connect_timeout
            ),
            ssh_command_timeout=_env_int(
                "ASUS_SSH_COMMAND_TIMEOUT_SECONDS", cls.ssh_command_timeout
            ),
            ssh_strict_host_key_checking=os.getenv(
                "ASUS_SSH_STRICT_HOST_KEY_CHECKING",
                cls.ssh_strict_host_key_checking,
            ),
            bind_address=os.getenv("ASUS_EXPORTER_BIND_ADDRESS", cls.bind_address),
            listen_port=_env_int("ASUS_EXPORTER_PORT", cls.listen_port),
            scrape_interval_seconds=_env_float(
                "ASUS_EXPORTER_SCRAPE_INTERVAL_SECONDS",
                cls.scrape_interval_seconds,
            ),
        )

    @property
    def router_target(self) -> str:
        return f"{self.router_user}@{self.router_host}"
