# skills/network_monitor/network_scanner.py
"""
Skill 4 — Network Monitor
Detecta conexiones salientes activas, destinos externos,
túneles TLS, proxies y patrones de exfiltración
"""

import socket
import psutil
import subprocess
import json
import threading
from collections import defaultdict


# IPs/rangos corporativos conocidos que no son sospechosos
TRUSTED_SUFFIXES = [
    "microsoft.com", "windows.com", "windowsupdate.com",
    "office.com", "office365.com", "microsoftonline.com",
    "azure.com", "azureedge.net", "live.com",
    "google.com", "googleapis.com", "gstatic.com",
    "akamai.net", "akamaized.net", "cloudfront.net",
    "amazonaws.com", "digicert.com",
]

# Productos de monitorización conocidos por sus destinos
MONITORING_DESTINATIONS = {
    "falconapi.crowdstrike.com":      "CrowdStrike Falcon",
    "ts01-crowdstrike.com":           "CrowdStrike Falcon",
    "netskope.com":                   "Netskope",
    "goskope.com":                    "Netskope",
    "zscaler.net":                    "Zscaler",
    "zscalertwo.net":                 "Zscaler",
    "zscalerthree.net":               "Zscaler",
    "sentinelone.com":                "SentinelOne",
    "tanium.com":                     "Tanium",
    "activtrak.com":                  "ActivTrak",
    "teramind.co":                    "Teramind",
    "hubstaff.com":                   "Hubstaff",
    "veriato.com":                    "Veriato",
}

MONITORING_PORTS = {
    443:  "HTTPS/TLS",
    8443: "HTTPS alternativo",
    4443: "HTTPS alternativo",
    8080: "HTTP proxy",
    3128: "Squid proxy",
    9000: "Agente corporativo común",
}


class NetworkMonitor:
    SKILL_NAME = "network_monitor"
    MAX_HOSTNAME_LOOKUPS = 12
    HOSTNAME_LOOKUP_TIMEOUT = 0.35

    def __init__(self, engine):
        self.engine = engine
        self.connections = []
        self.process_map = {}
        self.hostname_cache = {}
        self.hostname_lookups = 0

    def run(self):
        print("[Network] Iniciando auditoría de red...")
        self._build_process_map()
        self._collect_connections()
        self._check_external_connections()
        self._check_monitoring_destinations()
        self._check_proxy_config()
        self._check_dns_config()

    # ── Mapa de procesos ───────────────────────────────────────────

    def _build_process_map(self):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                self.process_map[proc.pid] = proc.info["name"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _collect_connections(self):
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED" and conn.raddr:
                    self.connections.append({
                        "pid":        conn.pid,
                        "process":    self.process_map.get(conn.pid, "unknown"),
                        "local_port": conn.laddr.port if conn.laddr else None,
                        "remote_ip":  conn.raddr.ip,
                        "remote_port":conn.raddr.port,
                        "status":     conn.status,
                    })
        except Exception as e:
            print(f"[Network] Error recopilando conexiones: {e}")

    # ── Conexiones externas ────────────────────────────────────────

    def _check_external_connections(self):
        from core.audit_engine import AuditFinding

        external = [
            c for c in self.connections
            if not self._is_local(c["remote_ip"])
        ]

        if not external:
            return

        # Agrupa por proceso
        by_process = defaultdict(list)
        for c in external:
            by_process[c["process"]].append(c)

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="network_external",
            title=f"Conexiones externas activas ({len(external)} establecidas)",
            description=(
                f"Se han detectado {len(external)} conexiones de red "
                f"establecidas hacia IPs externas desde "
                f"{len(by_process)} procesos distintos."
            ),
            risk_level="yellow",
            technical_risk=(
                "Las conexiones externas establecidas pueden corresponder "
                "a agentes corporativos enviando telemetría, datos de "
                "monitorización o actualizaciones."
            ),
            legal_risk=(
                "Las conexiones en sí no implican ilegalidad. "
                "El riesgo depende del tipo de datos transmitidos."
            ),
            what_it_is=(
                "Conexiones TCP activas desde este equipo hacia "
                "servidores en Internet."
            ),
            what_it_is_not=(
                "No implica exfiltración de datos personales. "
                "La mayoría son actualizaciones, telemetría de SO "
                "y aplicaciones legítimas."
            ),
            raw_data={
                "total_external": len(external),
                "by_process": {
                    proc: [
                        f"{c['remote_ip']}:{c['remote_port']}"
                        for c in conns
                    ]
                    for proc, conns in list(by_process.items())[:20]
                }
            }
        ))

    # ── Destinos de monitorización ─────────────────────────────────

    def _check_monitoring_destinations(self):
        from core.audit_engine import AuditFinding

        found_monitoring = {}

        for conn in self.connections:
            hostname = self._resolve_hostname(conn["remote_ip"])
            for domain, product in MONITORING_DESTINATIONS.items():
                if hostname.endswith(domain):
                    if product not in found_monitoring:
                        found_monitoring[product] = []
                    found_monitoring[product].append({
                        "process":  conn["process"],
                        "hostname": hostname,
                        "port":     conn["remote_port"],
                    })

        for product, conns in found_monitoring.items():
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="network_monitoring_destination",
                title=f"Conexión activa a infraestructura de {product}",
                description=(
                    f"Se detecta tráfico activo hacia servidores de {product}. "
                    f"Esto confirma que el agente está operativo y comunicándose."
                ),
                risk_level="orange",
                technical_risk=(
                    f"{product} está enviando datos activamente a sus servidores. "
                    "Puede incluir telemetría del sistema, eventos de seguridad "
                    "o datos de actividad del usuario."
                ),
                legal_risk=(
                    "Confirma la operación activa del software. "
                    "Ver evaluación legal en el compliance engine."
                ),
                what_it_is=(
                    f"Conexión de red activa del agente {product} "
                    "hacia su infraestructura cloud."
                ),
                what_it_is_not=(
                    "No confirma qué datos específicos se están enviando, "
                    "solo que el agente está activo y conectado."
                ),
                raw_data={"product": product, "connections": conns}
            ))
            print(f"[Network] Conexión monitorización: {product}")

    # ── Proxy config ───────────────────────────────────────────────

    def _check_proxy_config(self):
        from core.audit_engine import AuditFinding
        import winreg

        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_READ
            )
            proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            proxy_server = ""
            try:
                proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except (FileNotFoundError, OSError):
                pass
            winreg.CloseKey(key)

            if proxy_enable:
                self.engine.add_finding(AuditFinding(
                    skill=self.SKILL_NAME,
                    category="network_proxy",
                    title=f"Proxy corporativo configurado: {proxy_server}",
                    description=(
                        "El sistema tiene un proxy HTTP/HTTPS configurado "
                        "que intercepta el tráfico web."
                    ),
                    risk_level="orange",
                    technical_risk=(
                        "Todo el tráfico HTTP/HTTPS pasa por este proxy. "
                        "Si tiene certificado raíz instalado, puede "
                        "descifrar el tráfico HTTPS."
                    ),
                    legal_risk=(
                        "Requiere información previa al trabajador "
                        "según LOPDGDD art. 87 y doctrina Barbulescu."
                    ),
                    what_it_is=(
                        "Un proxy es un servidor intermediario por el que "
                        "pasa todo el tráfico web del equipo."
                    ),
                    what_it_is_not=(
                        "El proxy no implica lectura de contenido cifrado "
                        "salvo que haya inspección SSL activa."
                    ),
                    raw_data={
                        "proxy_enabled": bool(proxy_enable),
                        "proxy_server": proxy_server
                    }
                ))
        except (FileNotFoundError, OSError, PermissionError):
            pass

    # ── DNS config ─────────────────────────────────────────────────

    def _check_dns_config(self):
        from core.audit_engine import AuditFinding

        suspicious_dns = []
        corporate_dns_ranges = [
            "10.", "172.16.", "172.17.", "172.18.",
            "172.19.", "172.20.", "172.30.", "172.31.",
            "192.168."
        ]

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-DnsClientServerAddress -AddressFamily IPv4 | "
                 "Select-Object InterfaceAlias, ServerAddresses | "
                 "ConvertTo-Json"],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0 and result.stdout.strip():
                adapters = json.loads(result.stdout)
                if isinstance(adapters, dict):
                    adapters = [adapters]
                for adapter in adapters:
                    servers = adapter.get("ServerAddresses", []) or []
                    for dns in servers:
                        if any(dns.startswith(r) for r in corporate_dns_ranges):
                            suspicious_dns.append({
                                "interface": adapter.get("InterfaceAlias"),
                                "dns": dns
                            })
        except Exception as e:
            print(f"[Network] Error leyendo DNS: {e}")

        if suspicious_dns:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="network_dns",
                title="DNS corporativo interno detectado",
                description=(
                    "El equipo usa servidores DNS de red interna corporativa, "
                    "lo que permite al empleador registrar todas las "
                    "consultas de nombres de dominio."
                ),
                risk_level="yellow",
                technical_risk=(
                    "El DNS corporativo registra cada dominio consultado, "
                    "revelando qué servicios y sitios web usa el equipo."
                ),
                legal_risk=(
                    "Los logs DNS revelan patrones de uso sin descifrar tráfico. "
                    "Su retención y análisis está sujeta al RGPD."
                ),
                what_it_is=(
                    "Servidor DNS interno que traduce nombres de dominio "
                    "a IPs y puede registrar todas las consultas."
                ),
                what_it_is_not=(
                    "El DNS no ve el contenido de las comunicaciones, "
                    "solo los nombres de dominio consultados."
                ),
                raw_data={"corporate_dns": suspicious_dns}
            ))

    # ── Helpers ────────────────────────────────────────────────────

    def _is_local(self, ip: str) -> bool:
        return (
            ip.startswith("127.") or
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("172.") or
            ip == "::1"
        )

    def _resolve_hostname(self, ip: str) -> str:
        if ip in self.hostname_cache:
            return self.hostname_cache[ip]

        if self.hostname_lookups >= self.MAX_HOSTNAME_LOOKUPS:
            self.hostname_cache[ip] = ip
            return ip

        result = {"hostname": ip}

        def worker():
            try:
                result["hostname"] = socket.gethostbyaddr(ip)[0].lower()
            except Exception:
                result["hostname"] = ip

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(self.HOSTNAME_LOOKUP_TIMEOUT)

        hostname = result["hostname"]
        self.hostname_cache[ip] = hostname
        self.hostname_lookups += 1
        return hostname