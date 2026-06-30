"""Read-only router reconnaissance helper."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone

from .config import ExporterConfig
from .router_ssh import RouterSSH, RouterSSHError


RECON_SCRIPT = r"""
set +e
run_section() {
  name="$1"
  shift
  printf '\n===== %s =====\n' "$name"
  printf '$ %s\n' "$*"
  "$@" 2>&1 || true
}

printf 'ASUS GT-AXE16000 read-only recon\n'
printf 'timestamp_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
run_section nvram_wan_ifnames sh -c 'for key in wan0_ifname wan_ifname wan0_gw_ifname wan_ifnames wans_dualwan ctf_disable runner_disable qos_enable; do value=$(nvram get "$key" 2>/dev/null); printf "%s=%s\n" "$key" "$value"; done'
run_section ip_route ip route
run_section ip_br_addr ip -br addr
run_section brctl_show brctl show
run_section proc_net_dev cat /proc/net/dev
run_section proc_net_snmp cat /proc/net/snmp
run_section proc_net_netstat cat /proc/net/netstat
run_section proc_net_snmp6 cat /proc/net/snmp6
run_section proc_uptime cat /proc/uptime
run_section proc_loadavg cat /proc/loadavg
run_section proc_meminfo cat /proc/meminfo
run_section sockstat cat /proc/net/sockstat
run_section sockstat6 cat /proc/net/sockstat6
run_section softnet_stat cat /proc/net/softnet_stat
run_section conntrack_count sh -c 'cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || cat /proc/sys/net/ipv4/netfilter/ip_conntrack_count 2>/dev/null || true'
run_section conntrack_max sh -c 'cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || cat /proc/sys/net/ipv4/netfilter/ip_conntrack_max 2>/dev/null || true'
run_section arp arp -n
run_section dhcp_leases cat /tmp/dhcp.leases
run_section flow_cache_status fc status
for radio in wl0 wl1 wl2 wl3; do
  run_section "wifi_${radio}_assoclist" wl -i "$radio" assoclist
  run_section "wifi_${radio}_chanim_state" wl -i "$radio" chanim_state
  run_section "wifi_${radio}_interference" wl -i "$radio" interference
  run_section "wifi_${radio}_noise" wl -i "$radio" noise
done
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect a read-only ASUS router recon snapshot over SSH."
    )
    parser.add_argument(
        "--output",
        help="write output to this file instead of stdout",
    )
    args = parser.parse_args(argv)

    config = ExporterConfig.from_env()
    router = RouterSSH(config)
    header = (
        f"# Local collector timestamp UTC: {datetime.now(timezone.utc).isoformat()}\n"
        f"# Router target: {config.router_target}:{config.router_port}\n"
        "# This snapshot runs read-only commands only.\n"
    )
    try:
        output = header + router.run_script(RECON_SCRIPT, timeout=max(20, config.ssh_command_timeout))
    except RouterSSHError as exc:
        print(f"recon failed: {exc}")
        return 1

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="" if output.endswith("\n") else "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
