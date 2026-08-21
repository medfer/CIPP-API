"""Unit tests for LiveSnmpTransport's constructor validation.

These don't touch the network -- they only check that bad SNMPv3
parameter combinations fail fast and clearly at construction time, rather
than surfacing as a confusing pysnmp error deep inside the first get/walk.
Actual SNMPv2c/v3 wire behavior is validated separately against a real
net-snmp agent (not part of this offline suite -- see README).
"""
import pytest

pytest.importorskip("pysnmp", reason="pysnmp is optional -- only needed for LiveSnmpTransport")

from netdiscovery.transport import LiveSnmpTransport  # noqa: E402


def test_v2c_default_construction_does_not_require_pysnmp_v3_args():
    LiveSnmpTransport(community="public")


def test_v3_requires_valid_security_level():
    with pytest.raises(ValueError, match="security_level"):
        LiveSnmpTransport(username="user", security_level="bogus")


def test_v3_auth_no_priv_requires_auth_password():
    with pytest.raises(ValueError, match="auth_password"):
        LiveSnmpTransport(username="user", security_level="authNoPriv", auth_password=None)


def test_v3_auth_priv_requires_priv_password():
    with pytest.raises(ValueError, match="priv_password"):
        LiveSnmpTransport(
            username="user", security_level="authPriv",
            auth_password="authpass", priv_password=None,
        )


def test_v3_rejects_unknown_auth_protocol():
    with pytest.raises(ValueError, match="auth_protocol"):
        LiveSnmpTransport(
            username="user", security_level="authNoPriv",
            auth_protocol="not-a-real-protocol", auth_password="authpass",
        )


def test_v3_rejects_unknown_priv_protocol():
    with pytest.raises(ValueError, match="priv_protocol"):
        LiveSnmpTransport(
            username="user", security_level="authPriv",
            auth_password="authpass", priv_protocol="not-a-real-protocol",
            priv_password="privpass",
        )


def test_v3_noauthnopriv_needs_no_passwords():
    LiveSnmpTransport(username="user", security_level="noAuthNoPriv")


def test_v3_full_authpriv_construction_succeeds():
    LiveSnmpTransport(
        username="user", security_level="authPriv",
        auth_protocol="sha256", auth_password="authpass",
        priv_protocol="aes256", priv_password="privpass",
    )
