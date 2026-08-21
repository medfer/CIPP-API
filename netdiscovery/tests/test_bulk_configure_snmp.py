"""Unit tests for bulk_configure_snmp.py's pure logic -- command building,
idempotency detection, host-list parsing. Doesn't touch the network: the
actual Netmiko/SSH interaction with a real Cisco device isn't covered by
this offline suite (no real switch to test against here -- see README).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bulk_configure_snmp import already_configured, build_commands, read_hosts  # noqa: E402


def test_build_commands_with_acl():
    assert build_commands("public", "192.168.1.1", 90) == [
        "access-list 90 permit host 192.168.1.1",
        "snmp-server community public RO 90",
    ]


def test_build_commands_without_acl():
    assert build_commands("public", None, 90) == ["snmp-server community public RO"]


def test_already_configured_with_acl_match():
    cfg = "snmp-server community public RO 90\nsome other line\n"
    assert already_configured(cfg, "public", "192.168.1.1", 90) is True


def test_already_configured_with_acl_no_match():
    cfg = "snmp-server community public RO 90\n"
    # different community string -> not a match even though an ACL'd line exists
    assert already_configured(cfg, "other", "192.168.1.1", 90) is False


def test_already_configured_without_acl_match():
    assert already_configured("snmp-server community public RO", "public", None, 90) is True


def test_already_configured_empty_config():
    assert already_configured("", "public", None, 90) is False


def test_read_hosts_merges_cli_and_file_dedupes_and_skips_comments(tmp_path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("192.168.99.10\n# a comment\n192.168.99.20\n\n192.168.99.10\n")

    hosts = read_hosts(["10.0.0.1"], str(hosts_file))
    assert hosts == ["10.0.0.1", "192.168.99.10", "192.168.99.20"]


def test_read_hosts_cli_only():
    assert read_hosts(["10.0.0.1", "10.0.0.2"], None) == ["10.0.0.1", "10.0.0.2"]


def test_read_hosts_none_given():
    assert read_hosts(None, None) == []
