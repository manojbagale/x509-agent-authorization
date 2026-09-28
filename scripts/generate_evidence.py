from copy import deepcopy
from pathlib import Path
import subprocess
from cryptography.hazmat.primitives import serialization

from agent_auth.pki import ResearchCA
from agent_auth.experiment import BASE_POLICY

out = Path(__file__).resolve().parents[1] / 'evidence'
out.mkdir(exist_ok=True)
ca = ResearchCA.create()
noncritical = ca.issue_agent(mode='certificate', permissions=deepcopy(BASE_POLICY['permissions']), extension_critical=False)
critical = ca.issue_agent(mode='certificate', permissions=deepcopy(BASE_POLICY['permissions']), extension_critical=True)

(out/'root_ca.pem').write_bytes(ca.cert.public_bytes(serialization.Encoding.PEM))
(out/'agent_noncritical.pem').write_bytes(noncritical.pem)
(out/'agent_critical.pem').write_bytes(critical.pem)

commands = {
    'noncritical_verify.txt': ['openssl','verify','-CAfile',str(out/'root_ca.pem'),str(out/'agent_noncritical.pem')],
    'critical_verify.txt': ['openssl','verify','-CAfile',str(out/'root_ca.pem'),str(out/'agent_critical.pem')],
    'certificate_text.txt': ['openssl','x509','-in',str(out/'agent_noncritical.pem'),'-noout','-text'],
}
for name, cmd in commands.items():
    p = subprocess.run(cmd, text=True, capture_output=True)
    (out/name).write_text('$ ' + ' '.join(cmd) + '\n' + p.stdout + p.stderr + f'\nexit_code={p.returncode}\n')
