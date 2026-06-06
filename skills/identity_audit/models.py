# skills/identity_audit/models.py
"""
Responsabilidad única: definir las estructuras de datos compartidas
entre todos los módulos del skill identity_audit.

Ningún otro módulo define dataclasses propias para este skill.
Los imports van siempre desde los módulos hoja hacia models, nunca al revés.
"""

from dataclasses import dataclass, field
from typing import List, Optional


# ── Constantes compartidas ────────────────────────────────────────────────────

HIGH_PRIVILEGE_GROUPS = [
    "Administrators", "Administradores",
    "Domain Admins", "Administradores del dominio",
    "Enterprise Admins", "Administradores de empresa",
    "Schema Admins", "Administradores de esquema",
    "Remote Desktop Users", "Usuarios de escritorio remoto",
    "Remote Management Users",
]

REMOTE_SESSION_INDICATORS = [
    "rdpclip", "tstheme", "dwm",
    "winvnc", "tvnserver", "vncserver", "screenshare",
]

ELEVATED_MONITORING_NAMES = [
    "csfalconservice", "sentinelagent", "mssense",
    "taniumclient", "carbonblack", "cylancesvc", "cylancememdef",
]


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class LocalAccount:
    name: str
    enabled: bool
    last_logon: str
    password_never_expires: bool
    flags: List[str] = field(default_factory=list)


@dataclass
class AdminMember:
    name: str
    object_class: str
    principal_source: str


@dataclass
class SessionInfo:
    raw: str
    active: bool


@dataclass
class StoredCredential:
    target: str
    cred_type: str = ""
    user: str = ""


@dataclass
class ServiceAccount:
    service: str
    display: str
    account: str


@dataclass
class RdpConnection:
    local_address: str
    remote_address: str
    state: str
