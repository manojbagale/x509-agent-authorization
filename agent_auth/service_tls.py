"""Ephemeral service certificates for loopback mutual-TLS experiments."""
from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization

from agent_auth.pki import ResearchCA


@dataclass(frozen=True)
class ServiceTLS:
    ca_file: str
    server_cert: str
    server_key: str
    client_cert: str
    client_key: str
    client_fingerprint: str

    @classmethod
    def create(cls, directory, *, server_name="localhost"):
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        ca = ResearchCA.create()  # A service CA, separate from the agent CA.
        server = ca.issue_server(dns_name=server_name)
        client = ca.issue_agent(mode="external", agent_uri="spiffe://seminar.fisk.edu/service/gateway")
        def write(name, data):
            p = directory/name
            p.touch(mode=0o600, exist_ok=False)
            p.write_bytes(data)
            return str(p.resolve())
        return cls(write("ca.pem", ca.cert.public_bytes(serialization.Encoding.PEM)),
                   write("server.pem", server.pem), write("server-key.pem", server.key_pem),
                   write("gateway.pem", client.pem), write("gateway-key.pem", client.key_pem),
                   client.cert.fingerprint(hashes.SHA256()).hex())

    def client_context(self, *, include_certificate=True):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_file)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        if include_certificate:
            context.load_cert_chain(self.client_cert, self.client_key)
        return context

    def server_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.server_cert, self.server_key)
        context.load_verify_locations(cafile=self.ca_file)
        context.verify_mode = ssl.CERT_REQUIRED
        return context
