from copy import deepcopy
from pathlib import Path
import subprocess
from cryptography.hazmat.primitives import serialization

from agent_auth.pki import ResearchCA
from agent_auth.experiment import BASE_POLICY


def _verify_with_openssl(tmp_path: Path, *, critical: bool):
    ca = ResearchCA.create()
    issued = ca.issue_agent(
        mode="certificate",
        permissions=deepcopy(BASE_POLICY["permissions"]),
        extension_critical=critical,
    )
    ca_path = tmp_path / ("ca-critical.pem" if critical else "ca-noncritical.pem")
    cert_path = tmp_path / ("agent-critical.pem" if critical else "agent-noncritical.pem")
    ca_path.write_bytes(ca.cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(issued.pem)
    return subprocess.run(
        ["openssl", "verify", "-CAfile", str(ca_path), str(cert_path)],
        text=True, capture_output=True,
    )


def test_unknown_noncritical_extension_is_ignored_by_generic_openssl(tmp_path: Path):
    proc = _verify_with_openssl(tmp_path, critical=False)
    assert proc.returncode == 0
    assert "OK" in proc.stdout


def test_unknown_critical_extension_fails_generic_openssl_validation(tmp_path: Path):
    proc = _verify_with_openssl(tmp_path, critical=True)
    assert proc.returncode != 0
    assert "critical" in (proc.stdout + proc.stderr).lower()
