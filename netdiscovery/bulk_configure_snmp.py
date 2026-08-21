#!/usr/bin/env python3
"""Bulk-push a read-only SNMP v2c community (+ source ACL) to a list of
Cisco IOS/IOS-XE switches over SSH, so discover_live.py can actually reach
them -- built for the case where discover_live.py finds a switch as an
LLDP/CDP neighbor but it never answers SNMP because nobody's enabled it
there yet.

    python bulk_configure_snmp.py --hosts-file switches.txt \
        --ssh-user admin --community public --allow-ip 192.168.102.6

Defaults to --dry-run: prints exactly what WOULD be pushed to every
switch and touches nothing. Pass --apply to actually push -- and always
test against one switch first (--hosts 10.0.0.1) before running against
dozens/hundreds of them; a bad ACL number or typo is far cheaper to find
on one switch than on eighty.

Credentials are never hardcoded, logged, or echoed: the SSH password and
enable password are prompted interactively (getpass) unless supplied via
the NETDISCOVERY_SSH_PASSWORD / NETDISCOVERY_ENABLE_PASSWORD environment
variables.

Idempotent and additive-only: skips a switch whose running-config already
has the exact community+ACL line this would push, and the ACL command
only ever *adds* a permit entry -- it never removes or replaces existing
ACL content, so re-running this (or running it against a switch that
already has an unrelated ACL at the same number) can't destroy what's
already there.

To roll back by hand on a switch: `no access-list <n> permit host <ip>`
and `no snmp-server community <community> RO [<n>]` in config mode.

Requires `pip install netmiko` -- deliberately NOT in requirements.txt:
this is an operational config-push tool, not part of the read-only
discovery engine, and pulling in an SSH automation library by default for
a discovery POC would be a strange default.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


def build_commands(community: str, allow_ip: Optional[str], acl_number: int) -> list[str]:
    """IOS config-mode commands to enable read-only SNMP, optionally
    restricted to `allow_ip` via a numbered standard ACL."""
    if allow_ip:
        return [
            f"access-list {acl_number} permit host {allow_ip}",
            f"snmp-server community {community} RO {acl_number}",
        ]
    return [f"snmp-server community {community} RO"]


def already_configured(running_config: str, community: str,
                        allow_ip: Optional[str], acl_number: int) -> bool:
    """True if `running_config` already has the exact SNMP community line
    this run would push (so we skip it instead of pushing a duplicate).
    Doesn't require the ACL permit line to already be there too -- IOS
    silently no-ops a duplicate `access-list ... permit host ...` line
    anyway, so that part is safe to just always (re-)send when needed."""
    if allow_ip:
        target = f"snmp-server community {community} RO {acl_number}"
    else:
        target = f"snmp-server community {community} RO"
    return any(line.strip() == target for line in running_config.splitlines())


def read_hosts(hosts: Optional[list[str]], hosts_file: Optional[str]) -> list[str]:
    result: list[str] = list(hosts or [])
    if hosts_file:
        with open(hosts_file, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    result.append(line)
    # de-dupe, keep order
    seen: set[str] = set()
    out = []
    for h in result:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def configure_host(
    host: str, args: argparse.Namespace,
    ssh_password: str, enable_password: str,
) -> tuple[str, str, str]:
    """Returns (host, status, message). status is one of:
    "ok" (pushed), "skip" (already configured), "dry-run" (preview only),
    "error" (connection/auth/command failure -- never raises)."""
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

    commands = build_commands(args.community, args.allow_ip, args.acl_number)

    try:
        conn = ConnectHandler(
            device_type=args.device_type, host=host, port=args.ssh_port,
            username=args.ssh_user, password=ssh_password,
            secret=enable_password or ssh_password,
            timeout=args.ssh_timeout, conn_timeout=args.ssh_timeout,
        )
    except NetmikoAuthenticationException:
        return host, "error", "SSH authentication failed"
    except NetmikoTimeoutException:
        return host, "error", f"SSH connection timed out (port {args.ssh_port})"
    except Exception as exc:  # noqa: BLE001 - one bad host must never abort the batch
        return host, "error", f"{type(exc).__name__}: {exc}"

    try:
        conn.enable()
        running = conn.send_command("show running-config | include snmp-server community")
        if already_configured(running, args.community, args.allow_ip, args.acl_number):
            return host, "skip", "already configured"

        if args.dry_run:
            return host, "dry-run", "would push: " + " | ".join(commands)

        conn.send_config_set(commands)
        conn.save_config()
        return host, "ok", "pushed: " + " | ".join(commands)
    except Exception as exc:  # noqa: BLE001 - one bad host must never abort the batch
        return host, "error", f"{type(exc).__name__}: {exc}"
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001 - best-effort cleanup only
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hosts", nargs="+", help="one or more switch IPs/hostnames")
    parser.add_argument("--hosts-file", help="file with one IP/hostname per line ('#' comments allowed)")
    parser.add_argument("--ssh-user", default=os.environ.get("NETDISCOVERY_SSH_USER"),
                         help="default: env NETDISCOVERY_SSH_USER")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-timeout", type=float, default=10.0)
    parser.add_argument("--device-type", default="cisco_ios",
                         help="Netmiko device_type (default cisco_ios; e.g. cisco_xe, arubaoss, juniper_junos "
                              "for other vendors -- untested here, see README)")
    parser.add_argument("--community", required=True, help="SNMP RO community to configure")
    parser.add_argument("--allow-ip", help="restrict SNMP access to this source IP via a numbered ACL "
                                            "(strongly recommended -- see --no-acl to explicitly skip this)")
    parser.add_argument("--no-acl", action="store_true",
                         help="push the community with NO source restriction (opens SNMP to the whole "
                                 "network the switch can route to -- only use this if you understand that)")
    parser.add_argument("--acl-number", type=int, default=90, help="standard ACL number to use/extend")
    parser.add_argument("--apply", action="store_true", help="actually push changes (default: dry-run only)")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt before --apply")
    parser.add_argument("--concurrency", type=int, default=10)
    args = parser.parse_args()

    if not args.allow_ip and not args.no_acl:
        raise SystemExit("Pass --allow-ip <your management PC's IP> (recommended), "
                          "or --no-acl to explicitly push an unrestricted community.")
    if args.allow_ip and args.no_acl:
        raise SystemExit("--allow-ip and --no-acl are mutually exclusive.")
    if not args.ssh_user:
        raise SystemExit("--ssh-user is required (or set NETDISCOVERY_SSH_USER)")

    hosts = read_hosts(args.hosts, args.hosts_file)
    if not hosts:
        raise SystemExit("No hosts given -- pass --hosts and/or --hosts-file")

    ssh_password = os.environ.get("NETDISCOVERY_SSH_PASSWORD") or getpass.getpass(
        f"SSH password for {args.ssh_user}: ")
    enable_password = os.environ.get("NETDISCOVERY_ENABLE_PASSWORD") or getpass.getpass(
        "Enable password (blank = same as SSH password): ") or ssh_password

    mode = "DRY RUN (no changes will be made)" if not args.apply else "APPLY"
    print(f"{mode} -- {len(hosts)} host(s), community={args.community!r}, "
          f"acl={'none' if args.no_acl else f'{args.acl_number} -> {args.allow_ip}'}, "
          f"concurrency={args.concurrency}")

    if args.apply and not args.yes:
        answer = input(f"About to push config changes to {len(hosts)} switch(es). Type 'yes' to continue: ")
        if answer.strip().lower() != "yes":
            raise SystemExit("Aborted.")

    args.dry_run = not args.apply

    counts = {"ok": 0, "skip": 0, "dry-run": 0, "error": 0}
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
        futures = {executor.submit(configure_host, h, args, ssh_password, enable_password): h for h in hosts}
        for future in as_completed(futures):
            host, status, message = future.result()
            counts[status] += 1
            tag = {"ok": "[ok]", "skip": "[skip]", "dry-run": "[dry-run]", "error": "[error]"}[status]
            print(f"  {tag:<10} {host:<16} {message}")
    elapsed = time.monotonic() - start

    print(f"\nDone in {elapsed:.1f}s: {counts['ok']} pushed, {counts['skip']} already configured, "
          f"{counts['dry-run']} previewed, {counts['error']} failed")
    if counts["error"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
