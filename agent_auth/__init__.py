"""Research prototype for X.509-bound authorization experiments with AI agents."""

from .gateway import AuthorizationGateway, Session
from .policy import AuthorizationError, PolicyStore
from .pki import AGENT_AUTHZ_OID, AGENT_URI, TRUST_DOMAIN, ResearchCA

__all__ = [
    "AuthorizationGateway",
    "AuthorizationError",
    "PolicyStore",
    "Session",
    "ResearchCA",
    "AGENT_AUTHZ_OID",
    "AGENT_URI",
    "TRUST_DOMAIN",
]
