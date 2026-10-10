"""Security regressions for signed policy, malformed input and active sessions."""
from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ObjectIdentifier

from agent_auth.scenarios import BASE_POLICY, REQUESTS, issue_for_mode, make_store
from agent_auth.gateway import AuthorizationError, AuthorizationGateway
from agent_auth.pki import AGENT_AUTHZ_OID, AGENT_URI, ResearchCA, decode_agent_extension, encode_agent_extension


def setup(mode="hybrid_ceiling", **gateway_options):
    ca = ResearchCA.create()
    store = make_store()
    gw = AuthorizationGateway(ca, store, **gateway_options)
    issued = issue_for_mode(ca, mode)
    return ca, store, gw, issued, gw.open_session(issued.cert, issued.key)


def resign(ca, cert, *, replacement=None, extra=None):
    builder = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
               .public_key(cert.public_key()).serial_number(cert.serial_number)
               .not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc))
    for extension in cert.extensions:
        if replacement is not None and extension.oid == AGENT_AUTHZ_OID:
            builder = builder.add_extension(x509.UnrecognizedExtension(AGENT_AUTHZ_OID, replacement), critical=False)
        else:
            builder = builder.add_extension(extension.value, extension.critical)
    if extra:
        builder = builder.add_extension(extra, critical=True)
    return builder.sign(ca.key, hashes.SHA256())


@pytest.mark.parametrize("payload", [None, [], {}, {"tool": "file", "action": "read", "resource": None},
                                      {"tool": "file", "action": "read", "resource": 3},
                                      {**REQUESTS[0][1], "unexpected": "argument"}])
def test_malformed_request_denies_without_crashing(payload):
    _, _, gw, _, session = setup()
    assert gw.authorize(session, payload) == (False, "invalid_request")
    assert gw.audit_log[-1]["decision"] == "DENY"


@pytest.mark.parametrize("policy", [{}, {"permissions": None}, {"permissions": [None]},
                                    {"permissions": [{"tool": "file", "action": "read"}]},
                                    {"permissions": [{"tool": "file", "action": "read", "resource_prefix": 3}]}])
def test_malformed_live_policy_denies_without_crashing(policy):
    _, store, gw, _, session = setup()
    store.replace_named_policy("research-policy-v1", policy)
    assert gw.authorize(session, REQUESTS[0][1]) == (False, "policy_error")


@pytest.mark.parametrize("resource", ["/research/file\x00outside", "/research/\\..\\secret"])
def test_unsupported_path_characters_deny(resource):
    _, _, gw, _, session = setup()
    assert gw.authorize(session, {**REQUESTS[0][1], "resource": resource}) == (False, "policy_error")


def test_percent_characters_are_literal_and_multiple_slashes_canonicalize():
    _, _, gw, _, session = setup()
    assert gw.canonicalize_resource("//research///paper.pdf") == "/research/paper.pdf"
    assert gw.canonicalize_resource("/research/%2e%2e/paper.pdf") == "/research/%2e%2e/paper.pdf"
    assert gw.authorize(session, {**REQUESTS[0][1], "resource": "//research/paper.pdf"})[0]


def test_mutating_cached_ceiling_does_not_change_signed_authority():
    _, store, gw, _, session = setup()
    shell = {"tool": "shell", "action": "execute", "resource_prefix": "/bin"}
    session.max_permissions.append(shell)
    store.replace_named_policy("research-policy-v1", {"permissions": [shell]})
    assert gw.authorize(session, {"tool": "shell", "action": "execute", "resource": "/bin/sh"}) == (
        False, "outside_signed_ceiling")
    with pytest.raises(FrozenInstanceError):
        session.mode = "external"


def test_mutating_cached_certificate_policy_does_not_change_signed_authority():
    _, _, gw, _, session = setup("certificate")
    session.embedded_policy["permissions"].append({"tool": "shell", "action": "execute", "resource_prefix": "/bin"})
    assert not gw.authorize(session, {"tool": "shell", "action": "execute", "resource": "/bin/sh"})[0]


def test_policy_store_snapshots_do_not_mutate_control_plane():
    _, store, gw, _, session = setup("external")
    snapshot = store.get_agent_policy(AGENT_URI)
    snapshot["permissions"].clear()
    assert gw.authorize(session, REQUESTS[0][1])[0]
    replacement = deepcopy(BASE_POLICY)
    store.replace_agent_policy(AGENT_URI, replacement)
    replacement["permissions"].clear()
    assert gw.authorize(session, REQUESTS[0][1])[0]


def test_certificate_expiry_is_checked_on_existing_session():
    import datetime as dt
    current = [dt.datetime.now(dt.timezone.utc)]
    _, _, gw, issued, session = setup(clock=lambda: current[0])
    assert gw.authorize(session, REQUESTS[0][1])[0]
    current[0] = issued.cert.not_valid_after_utc + dt.timedelta(microseconds=1)
    assert gw.authorize(session, REQUESTS[0][1]) == (False, "certificate_expired")


def test_unsupported_critical_extension_rejected_by_application_profile():
    ca, _, gw, issued, _ = setup()
    cert = resign(ca, issued.cert, extra=x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.567"), b"unknown"))
    with pytest.raises(AuthorizationError, match="unsupported critical"):
        gw.open_session(cert, issued.key)


@pytest.mark.parametrize("raw", [b"", b"\x0c", b"\x0c\x80", b"\x0c\x81\x02{}",
                                 b"\x0c\x82\x00\x02{}", b"\x0c\x02{}trailing",
                                 b"\x0c\x03{}", b"\x0c\x02[]", b"\x0c\x01\xff"])
def test_invalid_der_or_json_object_rejected(raw):
    with pytest.raises(ValueError):
        decode_agent_extension(raw)


@pytest.mark.parametrize("raw", [b"\x0c", b"\x0c\x02[]", encode_agent_extension({"version": True, "mode": "certificate", "permissions": []}),
                                 encode_agent_extension({"version": 1, "mode": "certificate", "permissions": [None]}),
                                 encode_agent_extension({"version": 1, "mode": "hybrid", "policy_id": []})])
def test_signed_malformed_authorization_extension_rejected_at_session_open(raw):
    ca, _, gw, issued, _ = setup()
    cert = resign(ca, issued.cert, replacement=raw)
    with pytest.raises(AuthorizationError):
        gw.open_session(cert, issued.key)


def test_duplicate_json_fields_rejected():
    raw_json = b'{"mode":"certificate","mode":"hybrid"}'
    with pytest.raises(ValueError, match="duplicate"):
        decode_agent_extension(b"\x0c" + bytes([len(raw_json)]) + raw_json)


def test_explicit_empty_signed_ceiling_is_not_replaced_by_permissions():
    ca = ResearchCA.create()
    gw = AuthorizationGateway(ca, make_store())
    issued = ca.issue_agent(mode="hybrid_ceiling", max_permissions=[],
                            permissions=deepcopy(BASE_POLICY["permissions"]))
    session = gw.open_session(issued.cert, issued.key)
    assert gw.authorize(session, REQUESTS[0][1]) == (False, "outside_signed_ceiling")


def test_default_agent_certificate_has_at_most_fifteen_minute_validity_span():
    import datetime as dt
    issued = ResearchCA.create().issue_agent(mode="external")
    assert issued.cert.not_valid_after_utc - issued.cert.not_valid_before_utc <= dt.timedelta(minutes=15)
