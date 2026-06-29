"""SSH execution for read-only router telemetry collection."""

from __future__ import annotations

from dataclasses import dataclass
import subprocess

from .config import ExporterConfig


class RouterSSHError(RuntimeError):
    """Raised when the router cannot be queried over SSH."""


@dataclass(frozen=True)
class RouterSSH:
    config: ExporterConfig

    def base_command(self) -> list[str]:
        command = [
            "ssh",
            "-p",
            str(self.config.router_port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.config.ssh_connect_timeout}",
            "-o",
            f"StrictHostKeyChecking={self.config.ssh_strict_host_key_checking}",
            "-o",
            "LogLevel=ERROR",
        ]
        if self.config.identity_file:
            command.extend(["-i", self.config.identity_file])
        if self.config.user_known_hosts_file:
            command.extend(["-o", f"UserKnownHostsFile={self.config.user_known_hosts_file}"])
        command.append(self.config.router_target)
        return command

    def run_script(self, script: str, timeout: int | None = None) -> str:
        command = self.base_command() + ["sh", "-s"]
        try:
            completed = subprocess.run(
                command,
                input=script,
                text=True,
                capture_output=True,
                timeout=timeout or self.config.ssh_command_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RouterSSHError(
                f"SSH command timed out after {timeout or self.config.ssh_command_timeout}s"
            ) from exc
        except OSError as exc:
            raise RouterSSHError(f"Unable to start ssh: {exc}") from exc

        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            detail = f": {stderr}" if stderr else ""
            raise RouterSSHError(f"SSH command failed with exit {completed.returncode}{detail}")
        return completed.stdout
