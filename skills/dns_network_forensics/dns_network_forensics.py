# skills/dns_network_forensics/dns_network_forensics.py
"""
Skill — DNS & Network Forensics
Auditoría forense de la actividad de red del equipo:
DNS cache, ARP cache, conexiones activas y endpoints de monitorización.

Permite identificar con qué servidores ha estado comunicándose el equipo,
detectar endpoints de telemetría y monitorización, y documentar la
infraestructura de red corporativa visible desde el equipo del trabajador.

Operación: solo lectura, sin elevación de privilegios.
Fuentes: Get-DnsClientCache, arp -a, netstat, Get-NetTCPConnection.
"""

import re
import json
import hashlib
import datetime
import subprocess
from pathlib import Path
from typing import Optional
from collections import defaultdict


# ── Categorías de dominio ─────────────────────────────────────────────────────

# Patrones de dominios de monitorización y telemetría conocidos
MONITORING_DOMAINS = {
    # Nexthink
    "nexthink": {
        "tool": "Nexthink Collector",
        "risk": "orange",
        "note": "Servidor de telemetría Nexthink — monitorización de empleado",
    },
    # Zscaler
    "zscaler": {
        "tool": "Zscaler",
        "risk": "orange",
        "note": "Infraestructura Zscaler — inspección SSL y proxy corporativo",
    },
    "zscalerone": {
        "tool": "Zscaler",
        "risk": "orange",
        "note": "Infraestructura Zscaler",
    },
    # CrowdStrike
    "crowdstrike": {
        "tool": "CrowdStrike Falcon",
        "risk": "yellow",
        "note": "Servidor CrowdStrike — EDR telemetría",
    },
    "falconheavy": {
        "tool": "CrowdStrike Falcon",
        "risk": "yellow",
        "note": "CrowdStrike Falcon cloud",
    },
    # Snow Software
    "snowsoftware": {
        "tool": "Snow Inventory Agent",
        "risk": "yellow",
        "note": "Servidor Snow Software — inventario de software",
    },
    # LogMeIn
    "logmein": {
        "tool": "LogMeIn Rescue",
        "risk": "red",
        "note": "Servidor LogMeIn — acceso remoto",
    },
    "logme.in": {
        "tool": "LogMeIn Rescue",
        "risk": "red",
        "note": "Servidor LogMeIn — acceso remoto",
    },
    # Microsoft telemetría
    "telemetry.microsoft": {
        "tool": "Windows Telemetry",
        "risk": "yellow",
        "note": "Telemetría Windows",
    },
    "watson.microsoft": {
        "tool": "Windows Error Reporting",
        "risk": "yellow",
        "note": "Reporte de errores Windows",
    },
    "vortex.data.microsoft": {
        "tool": "Windows Telemetry",
        "risk": "yellow",
        "note": "Telemetría Windows DiagTrack",
    },
    # Azure AD / Intune
    "manage.microsoft": {
        "tool": "Microsoft Intune",
        "risk": "yellow",
        "note": "Endpoint Microsoft Intune MDM",
    },
    "login.microsoftonline": {
        "tool": "Azure AD",
        "risk": "yellow",
        "note": "Autenticación Azure AD",
    },
    # AI y productividad (para contexto)
    "api.anthropic": {
        "tool": "Claude AI (Anthropic)",
        "risk": "green",
        "note": "API Claude — uso del trabajador",
    },
    "claude.ai": {
        "tool": "Claude AI",
        "risk": "green",
        "note": "Claude AI — uso del trabajador",
    },
    "copilot": {
        "tool": "GitHub Copilot / Microsoft Copilot",
        "risk": "yellow",
        "note": "Copilot — puede enviar contexto de código a la nube",
    },
}

# Patrones de dominios internos corporativos conocidos
CORPORATE_DOMAIN_PATTERNS = [
    r"\.sareb\.srb$",
    r"\.sareb\.es$",
    r"devsareb\.srb$",
    r"sareblocal\.",
    r"\.emeal\.",
    r"nttdata\.com$",
    r"\.ntt\.com$",
    r"mshome\.net$",
]

# Puertos de monitorización conocidos
MONITORING_PORTS = {
    443:  "HTTPS/TLS",
    80:   "HTTP",
    8443: "HTTPS alternativo",
    514:  "Syslog",
    6514: "Syslog TLS",
    4222: "NATS (Nexthink)",
    8080: "HTTP proxy",
    9000: "Agente monitorización",
}


# ── Utilidades ────────────────────────────────────────────────────────────────

def _ps(cmd: str, timeout: int = 20) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _run(cmd: list, timeout: int = 15) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _categorize_domain(domain: str) -> str:
    """Clasifica un dominio como: corporate, monitoring, external, local."""
    d = domain.lower().strip()

    if d in ("localhost", "::1", "127.0.0.1") or d.endswith(".local"):
        return "local"

    for pattern in CORPORATE_DOMAIN_PATTERNS:
        if re.search(pattern, d):
            return "corporate"

    for keyword in MONITORING_DOMAINS:
        if keyword.lower() in d:
            return "monitoring"

    return "external"


def _match_monitoring(domain: str) -> Optional[dict]:
    d = domain.lower()
    for keyword, info in MONITORING_DOMAINS.items():
        if keyword.lower() in d:
            return info
    return None


def _is_private_ip(ip: str) -> bool:
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.") or
        ip in ("127.0.0.1", "::1", "localhost")
    )


# ── Recolección ───────────────────────────────────────────────────────────────

def _get_dns_cache() -> list[dict]:
    """Lee el caché DNS completo."""
    output = _ps(
        "Get-DnsClientCache | "
        "Select-Object Entry, RecordName, RecordType, Data, TimeToLive | "
        "ConvertTo-Json -Depth 3",
        timeout=15,
    )
    if not output:
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data or []
    except Exception:
        return []


def _get_arp_cache() -> list[dict]:
    """Lee la tabla ARP."""
    output = _run(["arp", "-a"])
    entries = []
    current_interface = None

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Detectar línea de interfaz
        if line.startswith("Interfaz:") or line.startswith("Interface:"):
            parts = line.split()
            if len(parts) >= 2:
                current_interface = parts[1]
            continue
        # Parsear entrada ARP
        parts = line.split()
        if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
            entries.append({
                "ip": parts[0],
                "mac": parts[1],
                "type": parts[2] if len(parts) > 2 else "",
                "interface": current_interface,
                "is_private": _is_private_ip(parts[0]),
                "is_local_mac": _is_local_administered_mac(parts[1]),
            })

    return entries


def _is_local_administered_mac(mac: str) -> bool:
    """
    Detecta MACs administradas localmente (VMs, VPNs, MACs randomizadas).
    El bit LSB del segundo bit del primer octeto = 1 indica MAC local.
    """
    try:
        first_octet = int(mac.split("-")[0].split(":")[0], 16)
        return bool(first_octet & 0x02)
    except Exception:
        return False


def _get_active_connections() -> list[dict]:
    """Lee conexiones TCP activas y en espera."""
    output = _ps(
        "Get-NetTCPConnection -State Established,Listen,TimeWait "
        "-ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress, LocalPort, RemoteAddress, "
        "RemotePort, State, OwningProcess | "
        "ConvertTo-Json -Depth 3",
        timeout=20,
    )
    if not output:
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data or []
    except Exception:
        return []


def _enrich_connection(conn: dict) -> dict:
    """Enriquece una conexión con nombre de proceso y categorización."""
    pid = conn.get("OwningProcess")
    proc_name = ""
    if pid:
        proc_name = _ps(
            f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).Name"
        )

    remote_ip = str(conn.get("RemoteAddress", "") or "")
    remote_port = conn.get("RemotePort", 0)

    return {
        "local": f"{conn.get('LocalAddress')}:{conn.get('LocalPort')}",
        "remote": f"{remote_ip}:{remote_port}",
        "remote_ip": remote_ip,
        "remote_port": int(remote_port) if remote_port else 0,
        "state": str(conn.get("State", "")),
        "pid": pid,
        "process": proc_name,
        "is_private": _is_private_ip(remote_ip),
        "is_monitoring_port": int(remote_port) in MONITORING_PORTS
        if remote_port else False,
    }


# ── Análisis DNS ──────────────────────────────────────────────────────────────

def _analyze_dns_cache(entries: list[dict]) -> dict:
    """
    Analiza el caché DNS y devuelve estadísticas y hallazgos.
    """
    domains = {}  # domain -> {category, monitoring_info, records}

    for entry in entries:
        domain = str(entry.get("Entry") or entry.get("RecordName") or "").strip().lower()
        data = str(entry.get("Data") or "").strip()

        if not domain or domain in ("localhost", ""):
            continue

        if domain not in domains:
            category = _categorize_domain(domain)
            monitoring = _match_monitoring(domain)
            domains[domain] = {
                "domain": domain,
                "category": category,
                "monitoring_info": monitoring,
                "records": [],
                "ips": set(),
            }

        if data:
            domains[domain]["records"].append(data)
            if re.match(r"\d+\.\d+\.\d+\.\d+", data):
                domains[domain]["ips"].add(data)

    # Convertir sets a listas
    for d in domains.values():
        d["ips"] = sorted(d["ips"])

    return domains


# ── Skill principal ───────────────────────────────────────────────────────────

class DNSNetworkForensics:
    SKILL_NAME = "dns_network_forensics"

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[DNSNetwork] Iniciando auditoría de red y DNS...")

        # Recopilar datos
        dns_raw = _get_dns_cache()
        arp_entries = _get_arp_cache()
        connections_raw = _get_active_connections()

        print(
            f"[DNSNetwork] DNS: {len(dns_raw)} entradas | "
            f"ARP: {len(arp_entries)} entradas | "
            f"Conexiones: {len(connections_raw)}"
        )

        # Analizar DNS
        dns_domains = _analyze_dns_cache(dns_raw)

        # Enriquecer conexiones (solo muestra limitada para no tardar)
        connections = []
        for conn in connections_raw[:50]:
            connections.append(_enrich_connection(conn))

        # Generar hallazgos
        self._report_dns_monitoring(dns_domains)
        self._report_dns_corporate_infra(dns_domains)
        self._report_dns_summary(dns_domains)
        self._report_arp_anomalies(arp_entries)
        self._report_active_connections(connections)

        print("[DNSNetwork] Completado")

    # ── Hallazgos ─────────────────────────────────────────────────────────────

    def _report_dns_monitoring(self, domains: dict):
        """Hallazgo: dominios de monitorización en caché DNS."""
        from core.audit_engine import AuditFinding

        monitoring = {
            k: v for k, v in domains.items()
            if v["category"] == "monitoring"
        }

        if not monitoring:
            return

        # Agrupar por herramienta
        by_tool = defaultdict(list)
        for domain, info in monitoring.items():
            tool = info["monitoring_info"]["tool"]
            by_tool[tool].append({
                "domain": domain,
                "ips": info["ips"],
                "note": info["monitoring_info"]["note"],
                "risk": info["monitoring_info"]["risk"],
            })

        # Determinar riesgo máximo
        risk_order = {"green": 0, "yellow": 1, "orange": 2, "red": 3}
        max_risk = max(
            (info["monitoring_info"]["risk"] for info in monitoring.values()),
            key=lambda r: risk_order.get(r, 0),
            default="yellow"
        )

        tool_summary = []
        for tool, entries in by_tool.items():
            ips = sorted(set(ip for e in entries for ip in e["ips"]))
            tool_summary.append(
                f"{tool}: {len(entries)} dominio(s), "
                f"IPs: {', '.join(ips[:3]) if ips else 'no resueltas'}"
            )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="dns_monitoring_endpoints",
            title=(
                f"DNS caché: {len(monitoring)} dominio(s) de monitorización "
                f"resueltos ({len(by_tool)} herramienta(s))"
            ),
            description=(
                f"El caché DNS del equipo contiene {len(monitoring)} "
                f"dominio(s) asociados a herramientas de monitorización "
                f"activas: {', '.join(by_tool.keys())}. "
                "Esto confirma comunicación reciente con estos servidores."
            ),
            risk_level=max_risk,
            technical_risk=(
                "La presencia de estos dominios en el caché DNS confirma "
                "que el equipo ha establecido conexiones activas con "
                "servidores de monitorización. El caché DNS persiste tras "
                "el reinicio y refleja actividad reciente."
            ),
            legal_risk=(
                "La comunicación activa con endpoints de monitorización "
                "confirma que el tratamiento de datos está en curso. "
                "Cada herramienta detectada requiere base legal documentada "
                "y comunicación al trabajador — RGPD art. 13."
            ),
            what_it_is=(
                "Registros en el caché DNS local que evidencian resolución "
                "reciente de nombres de dominio de herramientas de "
                "monitorización corporativas."
            ),
            what_it_is_not=(
                "No es evidencia de transmisión de datos específicos. "
                "Solo confirma que se ha producido comunicación de red "
                "con estos servidores."
            ),
            raw_data={
                "monitoring_domains": {
                    k: {
                        "domain": v["domain"],
                        "ips": v["ips"],
                        "tool": v["monitoring_info"]["tool"],
                        "note": v["monitoring_info"]["note"],
                        "risk": v["monitoring_info"]["risk"],
                    }
                    for k, v in monitoring.items()
                },
                "by_tool": dict(by_tool),
                "tool_summary": tool_summary,
                "total_monitoring_domains": len(monitoring),
            },
        ))

    def _report_dns_corporate_infra(self, domains: dict):
        """Hallazgo: infraestructura corporativa interna visible."""
        from core.audit_engine import AuditFinding

        corporate = {
            k: v for k, v in domains.items()
            if v["category"] == "corporate"
        }

        if not corporate:
            return

        # Agrupar por dominio base
        domain_groups = defaultdict(list)
        for domain in corporate:
            parts = domain.split(".")
            if len(parts) >= 2:
                base = ".".join(parts[-2:])
            else:
                base = domain
            domain_groups[base].append(domain)

        # Extraer IPs únicas
        all_ips = set()
        for v in corporate.values():
            all_ips.update(v["ips"])

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="dns_corporate_infrastructure",
            title=(
                f"DNS caché: {len(corporate)} servidor(es) de "
                f"infraestructura corporativa interna"
            ),
            description=(
                f"El caché DNS muestra {len(corporate)} servidor(es) de "
                f"infraestructura interna corporativa en "
                f"{len(domain_groups)} dominio(s) base. "
                f"IPs internas únicas: {len(all_ips)}. "
                "Esto mapea la infraestructura de red accesible desde "
                "el equipo del trabajador."
            ),
            risk_level="yellow",
            technical_risk=(
                "El caché DNS revela la estructura de la red interna "
                "corporativa, incluyendo nombres de servidor, subredes "
                "y servicios activos. Esta información es relevante "
                "para auditoría forense de conectividad."
            ),
            legal_risk=(
                "La visibilidad de infraestructura interna indica que "
                "el equipo tiene acceso a sistemas corporativos. "
                "Relevante para DPIA bajo RGPD art. 35 si hay acceso "
                "a datos personales en esos sistemas."
            ),
            what_it_is=(
                "Mapa de infraestructura de red interna corporativa "
                "derivado del caché DNS del equipo."
            ),
            what_it_is_not=(
                "No implica acceso no autorizado a esos sistemas. "
                "Es la infraestructura normal a la que el equipo "
                "tiene acceso en la red corporativa."
            ),
            raw_data={
                "corporate_domains": list(corporate.keys())[:50],
                "domain_groups": {
                    k: v[:10] for k, v in list(domain_groups.items())[:20]
                },
                "unique_ips": sorted(all_ips)[:30],
                "total": len(corporate),
            },
        ))

    def _report_dns_summary(self, domains: dict):
        """Hallazgo: resumen completo del caché DNS."""
        from core.audit_engine import AuditFinding

        if not domains:
            return

        by_category = defaultdict(int)
        for v in domains.values():
            by_category[v["category"]] += 1

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="dns_cache_inventory",
            title=(
                f"Inventario DNS caché: {len(domains)} dominio(s) — "
                + ", ".join(
                    f"{cat}: {count}"
                    for cat, count in sorted(by_category.items())
                )
            ),
            description=(
                f"Resumen del caché DNS del equipo: "
                f"{len(domains)} dominios resueltos recientemente. "
                + " | ".join(
                    f"{cat.upper()}: {count}"
                    for cat, count in sorted(by_category.items())
                )
            ),
            risk_level="yellow",
            technical_risk=(
                "El caché DNS es una huella digital de la actividad de red "
                "reciente del equipo. Permite identificar qué servicios "
                "han sido contactados sin necesidad de capturar tráfico."
            ),
            legal_risk=(
                "El mapa completo de comunicaciones de red del equipo "
                "es evidencia forense relevante para documentar el "
                "alcance de los tratamientos de datos activos."
            ),
            what_it_is=(
                "Inventario completo del caché DNS: registro de todos los "
                "dominios resueltos recientemente por el equipo."
            ),
            what_it_is_not=(
                "El caché DNS no muestra el contenido de las comunicaciones, "
                "solo los destinos contactados."
            ),
            raw_data={
                "total_domains": len(domains),
                "by_category": dict(by_category),
                "all_domains": [
                    {
                        "domain": v["domain"],
                        "category": v["category"],
                        "ips": v["ips"][:3],
                        "tool": v["monitoring_info"]["tool"]
                        if v["monitoring_info"] else None,
                    }
                    for v in sorted(
                        domains.values(),
                        key=lambda x: (
                            {"monitoring": 0, "corporate": 1,
                             "external": 2, "local": 3}.get(
                                x["category"], 4
                            )
                        )
                    )
                ],
            },
        ))

    def _report_arp_anomalies(self, entries: list[dict]):
        """Hallazgo: anomalías en la tabla ARP."""
        from core.audit_engine import AuditFinding

        if not entries:
            return

        local_mac_entries = [
            e for e in entries
            if e.get("is_local_mac") and not _is_private_ip(e["ip"])
        ]

        # Gateway con MAC local administrada (puede ser VPN/VM)
        gateway_entries = [
            e for e in entries
            if e.get("is_local_mac")
        ]

        risk = "yellow"
        flags = []

        if gateway_entries:
            for e in gateway_entries:
                flags.append(
                    f"MAC_administrada_localmente: {e['ip']} → {e['mac']} "
                    f"(posible VPN endpoint, VM o MAC randomizada)"
                )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="arp_cache_analysis",
            title=(
                f"Tabla ARP: {len(entries)} entrada(s) — "
                f"{len(gateway_entries)} con MAC administrada localmente"
            ),
            description=(
                f"La tabla ARP contiene {len(entries)} entrada(s). "
                + (
                    f"Se detectaron {len(gateway_entries)} dispositivo(s) "
                    "con MAC administrada localmente, lo que puede indicar "
                    "endpoints VPN, adaptadores virtuales o dispositivos "
                    "con MAC randomizada."
                    if gateway_entries else
                    "No se detectaron anomalías en MACs."
                )
            ),
            risk_level=risk,
            technical_risk=(
                "La tabla ARP revela los dispositivos activos en la misma "
                "subred de red. Las MACs administradas localmente pueden "
                "indicar infraestructura VPN o virtual que actúa como "
                "gateway de tráfico."
            ),
            legal_risk=(
                "La identificación del gateway de red (posiblemente Zscaler) "
                "en la tabla ARP confirma que todo el tráfico pasa por "
                "infraestructura corporativa de inspección."
            ),
            what_it_is=(
                "Tabla ARP: mapeo de direcciones IP a MAC en la subred local. "
                "Las MACs administradas localmente (segundo bit del primer "
                "octeto = 1) indican dispositivos virtuales o VPN."
            ),
            what_it_is_not=(
                "No implica actividad maliciosa. Las MACs locales son "
                "normales en entornos con VPN corporativa activa."
            ),
            raw_data={
                "arp_entries": entries,
                "local_mac_entries": gateway_entries,
                "flags": flags,
                "total": len(entries),
            },
        ))

    def _report_active_connections(self, connections: list[dict]):
        """Hallazgo: conexiones TCP activas hacia endpoints de monitorización."""
        from core.audit_engine import AuditFinding

        if not connections:
            return

        # Filtrar conexiones establecidas a IPs no locales
        external_established = [
            c for c in connections
            if c["state"] == "Established" and
            not _is_private_ip(c["remote_ip"]) and
            c["remote_ip"] not in ("0.0.0.0", "::", "")
        ]

        # Conexiones a puertos de monitorización
        monitoring_conns = [
            c for c in connections
            if c.get("is_monitoring_port") and c["state"] == "Established"
        ]

        risk = "yellow"
        if external_established:
            risk = "orange"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="active_tcp_connections",
            title=(
                f"Conexiones TCP activas: {len(connections)} total — "
                f"{len(external_established)} externas establecidas"
            ),
            description=(
                f"Se han analizado {len(connections)} conexiones TCP. "
                f"{len(external_established)} conexiones establecidas "
                f"hacia IPs externas a la red privada. "
                + (
                    f"{len(monitoring_conns)} conexiones en puertos de "
                    "monitorización conocidos."
                    if monitoring_conns else ""
                )
            ),
            risk_level=risk,
            technical_risk=(
                "Las conexiones TCP activas muestran en tiempo real "
                "con qué servidores se está comunicando el equipo. "
                "Las conexiones externas establecidas pueden incluir "
                "agentes de monitorización activos."
            ),
            legal_risk=(
                "Las conexiones activas hacia servidores de monitorización "
                "confirman que el tratamiento de datos personales está "
                "ocurriendo en este momento — RGPD art. 32."
            ),
            what_it_is=(
                "Snapshot de conexiones TCP activas en el momento de "
                "la auditoría, con proceso asociado cuando es accesible."
            ),
            what_it_is_not=(
                "No captura contenido de las comunicaciones. Solo documenta "
                "origen, destino, puerto y proceso de cada conexión."
            ),
            raw_data={
                "total_connections": len(connections),
                "external_established": len(external_established),
                "monitoring_port_connections": len(monitoring_conns),
                "external_sample": external_established[:15],
                "monitoring_connections": monitoring_conns[:10],
                "monitoring_ports": MONITORING_PORTS,
            },
        ))