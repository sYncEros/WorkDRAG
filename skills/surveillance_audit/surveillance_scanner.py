# skills/surveillance_audit/surveillance_scanner.py
"""
Skill 2 — Auditoría de Superficie de Vigilancia
Detecta capacidades de monitorización: EDR, DLP, inspección SSL,
monitorización de productividad, soporte remoto e inspección de navegador
"""

import winreg
import subprocess
import json
import psutil
from pathlib import Path


# Catálogo de productos conocidos por categoría
SURVEILLANCE_CATALOG = {
    "edr_xdr": {
        "CrowdStrike Falcon": {
            "processes": ["csfalconservice", "csfalconcontainer", "falcond"],
            "services": ["csagent", "csfalconservice"],
            "drivers": ["csagent.sys"],
        },
        "SentinelOne": {
            "processes": ["sentinelagent", "sentinelone"],
            "services": ["sentinelagent"],
            "drivers": ["sentinelle.sys"],
        },
        "Microsoft Defender for Endpoint": {
            "processes": ["mssense", "sensecncproxy", "senseir"],
            "services": ["sense"],
            "drivers": [],
        },
        "Tanium": {
            "processes": ["taniumclient", "taniumexecwrapper"],
            "services": ["taniumclient"],
            "drivers": [],
        },
        "Cybereason": {
            "processes": ["amicrobe", "executionpreventionsvc"],
            "services": ["cybereason"],
            "drivers": [],
        },
    },
    "dlp": {
        "Microsoft Purview (DLP)": {
            "processes": ["mipagent", "msip"],
            "services": ["mipagent"],
            "registry": [r"SOFTWARE\Microsoft\MIPPlugin"],
        },
        "Forcepoint DLP": {
            "processes": ["fp_cmi", "fpwin"],
            "services": ["fpwin"],
            "registry": [],
        },
        "Symantec DLP": {
            "processes": ["edpa", "edplhd"],
            "services": ["edpa"],
            "registry": [],
        },
    },
    "network_inspection": {
        "Netskope": {
            "processes": ["nssvcconfig", "nsdiag"],
            "services": ["netskopestats"],
            "registry": [r"SOFTWARE\Netskope"],
        },
        "Zscaler": {
            "processes": ["zclient", "zsa"],
            "services": ["zsa"],
            "registry": [r"SOFTWARE\Zscaler"],
        },
        "Cisco Umbrella": {
            "processes": ["ciscoumbrella"],
            "services": ["ciscoumbrella"],
            "registry": [r"SOFTWARE\OpenDNS\ERC"],
        },
    },
    "productivity_monitoring": {
        "ActivTrak": {
            "processes": ["activtrak", "atclient"],
            "services": ["activtrak"],
            "registry": [r"SOFTWARE\ActivTrak"],
        },
        "Teramind": {
            "processes": ["teramind", "tmagent"],
            "services": ["teramind"],
            "registry": [],
        },
        "Hubstaff": {
            "processes": ["hubstaff"],
            "services": [],
            "registry": [r"SOFTWARE\Hubstaff"],
        },
        "Veriato": {
            "processes": ["veriato", "pcrecorder"],
            "services": ["veriato"],
            "registry": [],
        },
        "Controlio": {
            "processes": ["controlio"],
            "services": [],
            "registry": [],
        },
    },
    "remote_support": {
        "TeamViewer": {
            "processes": ["teamviewer", "teamviewer_service"],
            "services": ["teamviewer"],
            "registry": [r"SOFTWARE\TeamViewer"],
        },
        "AnyDesk": {
            "processes": ["anydesk"],
            "services": ["anydesk"],
            "registry": [],
        },
        "BeyondTrust": {
            "processes": ["bomgar", "bomgar-scc"],
            "services": ["bomgar"],
            "registry": [],
        },
        "ConnectWise Control": {
            "processes": ["screenconnect"],
            "services": ["screenconnect"],
            "registry": [],
        },
    },
}

# Nivel de riesgo por categoría
CATEGORY_RISK = {
    "edr_xdr": "yellow",
    "dlp": "yellow",
    "network_inspection": "orange",
    "productivity_monitoring": "red",
    "remote_support": "orange",
}


class SurveillanceAudit:
    SKILL_NAME = "surveillance_audit"

    def __init__(self, engine):
        self.engine = engine
        self.running_processes = self._get_running_processes()

    def run(self):
        print("[Surveillance] Iniciando auditoría de superficie de vigilancia...")
        self._scan_catalog()
        self._check_ssl_inspection()
        self._check_browser_extensions_policy()
        self._check_input_monitoring()

    # ── Procesos activos ───────────────────────────────────────────

    def _get_running_processes(self) -> set:
        names = set()
        for proc in psutil.process_iter(["name"]):
            try:
                names.add(proc.info["name"].lower().replace(".exe", ""))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return names

    def _check_service_exists(self, service_name: str) -> bool:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                f"SYSTEM\\CurrentControlSet\\Services\\{service_name}",
                0, winreg.KEY_READ
            )
            winreg.CloseKey(key)
            return True
        except (FileNotFoundError, PermissionError, OSError):
            return False

    def _check_registry_exists(self, path: str) -> bool:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ
            )
            winreg.CloseKey(key)
            return True
        except (FileNotFoundError, PermissionError, OSError):
            return False

    # ── Escaneo del catálogo ───────────────────────────────────────

    def _scan_catalog(self):
        from core.audit_engine import AuditFinding

        for category, products in SURVEILLANCE_CATALOG.items():
            for product_name, indicators in products.items():
                detected = self._detect_product(indicators)
                if not detected["found"]:
                    continue

                risk = CATEGORY_RISK.get(category, "yellow")

                descriptions = {
                    "edr_xdr": (
                        "Agente EDR/XDR detectado. Estos sistemas monitorizan "
                        "comportamiento del sistema en tiempo real para detectar amenazas.",
                        "Monitoriza procesos, red y comportamiento del sistema.",
                        "No implica necesariamente lectura de contenido personal. "
                        "Es seguridad corporativa estándar en empresas medianas y grandes.",
                        "low-medium"
                    ),
                    "dlp": (
                        "Software DLP detectado. Controla la transferencia de datos "
                        "para prevenir fugas de información.",
                        "Puede inspeccionar archivos transferidos y correos salientes.",
                        "No implica monitorización de productividad ni vigilancia "
                        "de actividad personal. Foco en datos, no en personas.",
                        "medium"
                    ),
                    "network_inspection": (
                        "Agente de inspección de red/proxy detectado. "
                        "Puede interceptar y analizar tráfico HTTPS.",
                        "Puede descifrar y analizar tráfico web corporativo.",
                        "No garantiza que se lea contenido específico, "
                        "pero la capacidad técnica existe. "
                        "Requiere informar al trabajador bajo LOPDGDD.",
                        "medium-high"
                    ),
                    "productivity_monitoring": (
                        "Software de monitorización de productividad detectado. "
                        "Esta categoría incluye productos que pueden registrar "
                        "actividad, capturas de pantalla o uso de aplicaciones.",
                        "Puede registrar actividad, tiempo en apps, "
                        "capturas periódicas de pantalla.",
                        "No todas las funciones tienen que estar activadas. "
                        "Pero la capacidad existe y requiere consentimiento explícito "
                        "bajo RGPD/LOPDGDD.",
                        "high"
                    ),
                    "remote_support": (
                        "Software de acceso remoto detectado. "
                        "Permite control remoto del equipo.",
                        "Permite acceso completo al escritorio de forma remota.",
                        "Puede ser uso legítimo de soporte técnico. "
                        "El riesgo es el uso no transparente o no consentido.",
                        "medium"
                    ),
                }

                desc, tech, not_impl, legal = descriptions.get(
                    category,
                    ("Software detectado.", "Capacidad desconocida.",
                     "Uso desconocido.", "medium")
                )

                self.engine.add_finding(AuditFinding(
                    skill=self.SKILL_NAME,
                    category=category,
                    title=f"{product_name} detectado",
                    description=desc,
                    risk_level=risk,
                    technical_risk=tech,
                    legal_risk=(
                        f"Riesgo legal estimado: {legal}. "
                        "Ver compliance engine para análisis LOPDGDD/RGPD."
                    ),
                    what_it_is=desc,
                    what_it_is_not=not_impl,
                    raw_data={
                        "product": product_name,
                        "category": category,
                        "detection": detected
                    }
                ))

                print(
                    f"[Surveillance] DETECTADO: {product_name} "
                    f"— Riesgo: {risk.upper()}"
                )

    def _detect_product(self, indicators: dict) -> dict:
        found_processes = [
            p for p in indicators.get("processes", [])
            if p in self.running_processes
        ]
        found_services = [
            s for s in indicators.get("services", [])
            if self._check_service_exists(s)
        ]
        found_registry = [
            r for r in indicators.get("registry", [])
            if self._check_registry_exists(r)
        ]
        found = bool(found_processes or found_services or found_registry)
        return {
            "found": found,
            "processes": found_processes,
            "services": found_services,
            "registry": found_registry,
        }

    # ── Inspección SSL ─────────────────────────────────────────────

    def _check_ssl_inspection(self):
        from core.audit_engine import AuditFinding

        corp_root_certs = []
        ssl_inspection_vendors = [
            "netskope", "zscaler", "forcepoint", "cisco",
            "bluecoat", "symantec", "websense", "iboss",
            "palo alto", "checkpoint", "fortinet", "sophos"
        ]

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ChildItem Cert:\\LocalMachine\\Root | "
                 "Select-Object Subject, Issuer | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                certs = json.loads(result.stdout)
                if isinstance(certs, dict):
                    certs = [certs]
                for cert in certs:
                    subject = cert.get("Subject", "").lower()
                    if any(v in subject for v in ssl_inspection_vendors):
                        corp_root_certs.append(cert.get("Subject", ""))
        except Exception as e:
            print(f"[Surveillance] Error leyendo certs SSL: {e}")

        if corp_root_certs:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="ssl_inspection",
                title="Certificado raíz de inspección SSL/TLS detectado",
                description=(
                    "Se han encontrado certificados raíz corporativos que "
                    "permiten interceptar y descifrar tráfico HTTPS."
                ),
                risk_level="orange",
                technical_risk=(
                    "Con este certificado instalado, un proxy corporativo puede "
                    "descifrar, analizar y registrar todo el tráfico HTTPS, "
                    "incluyendo contraseñas y contenido de páginas web."
                ),
                legal_risk=(
                    "Requiere informar explícitamente al trabajador. "
                    "Sin información previa puede vulnerar art. 87 LOPDGDD "
                    "y doctrina Barbulescu II (TEDH)."
                ),
                what_it_is=(
                    "Un certificado raíz de inspección SSL permite al proxy "
                    "corporativo actuar como intermediario en conexiones HTTPS, "
                    "descifrando el tráfico para inspeccionarlo."
                ),
                what_it_is_not=(
                    "No demuestra que el tráfico se esté leyendo activamente, "
                    "pero sí que existe la capacidad técnica."
                ),
                raw_data={"ssl_inspection_certs": corp_root_certs}
            ))

    # ── Política de extensiones del navegador ──────────────────────

    def _check_browser_extensions_policy(self):
        from core.audit_engine import AuditFinding

        browsers = {
            "Chrome": r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
            "Edge": r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist",
            "Firefox": r"SOFTWARE\Policies\Mozilla\Firefox\Extensions\Install",
        }

        forced_extensions = {}
        for browser, reg_path in browsers.items():
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ
                )
                idx = 0
                exts = []
                while True:
                    try:
                        _, val, _ = winreg.EnumValue(key, idx)
                        exts.append(str(val))
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
                if exts:
                    forced_extensions[browser] = exts
            except (FileNotFoundError, PermissionError, OSError):
                pass

        if forced_extensions:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="browser_inspection",
                title="Extensiones de navegador forzadas por política corporativa",
                description=(
                    "El navegador tiene extensiones instaladas obligatoriamente "
                    "por política corporativa."
                ),
                risk_level="orange",
                technical_risk=(
                    "Las extensiones forzadas pueden tener acceso completo "
                    "al contenido de páginas web, historial y formularios."
                ),
                legal_risk=(
                    "Depende de la funcionalidad de cada extensión. "
                    "Si capturan contenido web personal, aplica LOPDGDD art. 87."
                ),
                what_it_is=(
                    "Extensiones instaladas por GPO/política que el usuario "
                    "no puede desinstalar."
                ),
                what_it_is_not=(
                    "No implica necesariamente espionaje. Muchas son "
                    "extensiones de seguridad o DLP legítimas."
                ),
                raw_data={"forced_extensions": forced_extensions}
            ))

    # ── Monitorización de entrada ──────────────────────────────────

    def _check_input_monitoring(self):
        from core.audit_engine import AuditFinding

        keylogger_indicators = [
            "hook", "keylog", "inputcapture",
            "pcagent", "spector", "refog"
        ]

        found = [
            p for p in self.running_processes
            if any(k in p for k in keylogger_indicators)
        ]

        if found:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="input_monitoring",
                title="Posible monitorización de entrada detectada",
                description=(
                    "Se han encontrado procesos con nombres asociados "
                    "a captura de entrada de teclado o ratón."
                ),
                risk_level="red",
                technical_risk=(
                    "Un keylogger puede registrar todo lo que se escribe, "
                    "incluyendo contraseñas y comunicaciones privadas."
                ),
                legal_risk=(
                    "El keylogging sin consentimiento explícito es "
                    "muy probablemente ilegal bajo LOPDGDD y ET art. 20bis. "
                    "Alto riesgo jurídico para la empresa."
                ),
                what_it_is="Software de captura de pulsaciones de teclado.",
                what_it_is_not=(
                    "Puede ser falso positivo. Algunos procesos legítimos "
                    "de accesibilidad usan hooks de teclado."
                ),
                raw_data={"suspicious_processes": found}
            ))