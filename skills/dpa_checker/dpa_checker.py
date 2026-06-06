# skills/dpa_checker/dpa_checker.py
"""
Skill — DPA Checker
Verifica si existe un Data Processing Agreement (DPA) válido con Microsoft
y otros proveedores cloud, compara el nivel de telemetría configurado
vs el declarado en el DPA, y detecta discrepancias entre lo firmado
y la configuración técnica real del equipo.
"""

import subprocess
import json
import winreg
import os
import ipaddress
import psutil
from pathlib import Path
from datetime import datetime
from core.capability_intel import (
    get_sources,
    certutil_root_summary,
    gpresult_summary,
    fltmc_summary,
)


# ── Configuración ──────────────────────────────────────────────────────────────

# Proveedores cloud principales a verificar
CLOUD_PROVIDERS = {
    "Microsoft 365 / Azure": {
        "registry_keys": [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Office\16.0\Common\Privacy",
             "ControllerConnectedServicesEnabled"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\office\16.0\common\privacy",
             "disconnectedstate"),
        ],
        "tenant_key": (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CDPUserSvc",
            "TenantId"
        ),
        "dpa_url": "https://aka.ms/DPA",
        "telemetry_key": (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowTelemetry"
        ),
    },
}

# Niveles de telemetría y su conformidad DPA
TELEMETRY_DPA_COMPLIANCE = {
    0: ("Seguridad",  True,  "Conforme — mínimo de datos enviados"),
    1: ("Básico",     True,  "Conforme — nivel recomendado por AEPD"),
    2: ("Mejorado",   False, "Posible incumplimiento — datos de uso enviados"),
    3: ("Completo",   False, "Incumplimiento probable — máximo volumen de datos"),
}

# Servicios conectados de Office que implican transferencia de datos
OFFICE_CONNECTED_SERVICES = {
    "ControllerConnectedServicesEnabled": "Servicios controlados por Microsoft activos",
    "UserContentDisabled":                "Análisis de contenido del usuario activo",
    "DownloadContentDisabled":            "Descarga de contenido en la nube activa",
}

# Claves de tenant/organización
TENANT_REGISTRY_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData",
     "TenantId"),
    (winreg.HKEY_CURRENT_USER,
     r"SOFTWARE\Microsoft\Office\16.0\Common\ServicesManagerCache",
     "TenantId"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Enrollments",
     None),  # enumerate subkeys
]


class DPAChecker:
    SKILL_NAME = "dpa_checker"

    def __init__(self, engine):
        self.engine              = engine
        self.tenant_id           = None
        self.tenant_name         = None
        self.telemetry_level     = None
        self.telemetry_compliant = None
        self.office_services     = {}
        self.dpa_indicators      = []
        self.discrepancies       = []
        self.providers_found     = []
        self.triangulation       = {}

    def run(self):
        print("[DPA] Iniciando verificación de DPA y conformidad...")
        self._detect_tenant()
        self._check_telemetry_compliance()
        self._check_office_privacy_settings()
        self._check_azure_ad_dpa_indicators()
        self._check_microsoft_dpa_registry()
        self._detect_other_providers()
        self._detect_generic_cloud_capabilities()
        self._collect_triangulation()
        self._report()

    def _collect_triangulation(self):
        """Recolecta señales de contraste con herramientas nativas."""
        self.triangulation = {
            "gpresult": gpresult_summary(),
            "certutil_root": certutil_root_summary(),
            "fltmc_filters": fltmc_summary(),
        }

    def _is_external_ip(self, ip: str) -> bool:
        ip = str(ip or "").strip()
        if not ip:
            return False
        try:
            parsed = ipaddress.ip_address(ip)
            return not (
                parsed.is_private or parsed.is_loopback or
                parsed.is_link_local or parsed.is_multicast or
                parsed.is_reserved
            )
        except ValueError:
            return False

    # ── Detección de tenant ────────────────────────────────────────────────────

    def _detect_tenant(self):
        """Detecta el tenant de Microsoft 365 al que pertenece el equipo."""

        # Método 1: Azure AD Join info
        try:
            result = subprocess.run(
                ["dsregcmd", "/status"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if "TenantId" in line and ":" in line:
                        self.tenant_id = line.split(":", 1)[1].strip()
                    elif "TenantName" in line and ":" in line:
                        self.tenant_name = line.split(":", 1)[1].strip()
                    elif "DomainName" in line and ":" in line and not self.tenant_name:
                        self.tenant_name = line.split(":", 1)[1].strip()
        except Exception:
            pass

        # Método 2: Registro de MDM
        if not self.tenant_id:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Enrollments"
                )
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            tid, _ = winreg.QueryValueEx(subkey, "AADTenantID")
                            if tid:
                                self.tenant_id = tid
                        except OSError:
                            pass
                        try:
                            tname, _ = winreg.QueryValueEx(subkey, "AADTenantName")
                            if tname:
                                self.tenant_name = tname
                        except OSError:
                            pass
                        winreg.CloseKey(subkey)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                pass

        if self.tenant_id:
            print(
                f"[DPA] Tenant detectado: "
                f"{self.tenant_name or 'Desconocido'} "
                f"({self.tenant_id})"
            )
        else:
            print("[DPA] Tenant Microsoft no detectado")

    # ── Conformidad de telemetría ──────────────────────────────────────────────

    def _check_telemetry_compliance(self):
        """Verifica si el nivel de telemetría es conforme con un DPA estándar."""
        level = None

        registry_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
             "AllowTelemetry"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
             "AllowTelemetry"),
        ]

        for hive, key_path, value_name in registry_keys:
            try:
                key   = winreg.OpenKey(hive, key_path)
                value, _ = winreg.QueryValueEx(key, value_name)
                winreg.CloseKey(key)
                level = int(value)
                break
            except OSError:
                pass

        if level is None:
            level = 3  # Sin política = nivel completo por defecto

        self.telemetry_level = level
        compliance_info = TELEMETRY_DPA_COMPLIANCE.get(
            level, (str(level), False, "Nivel desconocido")
        )
        level_name, is_compliant, compliance_desc = compliance_info
        self.telemetry_compliant = is_compliant

        print(
            f"[DPA] Telemetría nivel {level} ({level_name}) — "
            f"{'✅ Conforme' if is_compliant else '⚠️ No conforme'}: "
            f"{compliance_desc}"
        )

        if not is_compliant:
            self.discrepancies.append({
                "type":        "telemetry_level",
                "description": f"Nivel de telemetría {level_name} ({level})",
                "issue":       compliance_desc,
                "severity":    "high",
            })

    # ── Configuración de privacidad de Office ─────────────────────────────────

    def _check_office_privacy_settings(self):
        """Verifica la configuración de privacidad de Office 365."""
        office_privacy_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\office\16.0\common\privacy"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Policies\Microsoft\office\16.0\common\privacy"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Office\16.0\Common\Privacy"),
        ]

        privacy_values = {}
        for hive, key_path in office_privacy_keys:
            try:
                key = winreg.OpenKey(hive, key_path)
                i   = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        privacy_values[name] = value
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                pass

        self.office_services = privacy_values

        # Detectar experiencias conectadas activas
        if "ControllerConnectedServicesEnabled" in privacy_values:
            val = privacy_values["ControllerConnectedServicesEnabled"]
            if int(val) == 1:
                self.discrepancies.append({
                    "type":        "office_connected_services",
                    "description": "Servicios conectados de Office controlados por Microsoft activos",
                    "issue":       "Contenido de documentos puede enviarse a Microsoft para IA/análisis",
                    "severity":    "medium-high",
                })

        # Verificar si hay política de privacidad de Office configurada
        if not privacy_values:
            self.discrepancies.append({
                "type":        "office_no_privacy_policy",
                "description": "Sin política de privacidad de Office configurada",
                "issue":       "Office opera con configuración por defecto — máxima telemetría",
                "severity":    "medium",
            })
            print("[DPA] Office: sin política de privacidad configurada")
        else:
            print(f"[DPA] Office: {len(privacy_values)} valores de privacidad configurados")

    # ── Indicadores de DPA en Azure AD ────────────────────────────────────────

    def _check_azure_ad_dpa_indicators(self):
        """Busca indicadores de configuración DPA en Azure AD y MDM."""
        try:
            result = subprocess.run(
                ["dsregcmd", "/status"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                indicators = {}
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    for key in [
                        "EnterpriseJoined", "DomainJoined",
                        "AzureAdJoined", "MDMUrl",
                        "ComplianceUrl", "SettingsUrl",
                    ]:
                        if key in line and ":" in line:
                            val = line.split(":", 1)[1].strip()
                            indicators[key] = val

                if indicators:
                    self.dpa_indicators.extend([
                        {"key": k, "value": v}
                        for k, v in indicators.items()
                    ])
                    print(
                        f"[DPA] Azure AD indicators: "
                        f"{list(indicators.keys())}"
                    )

                    # MDM URL indica contrato de gestión
                    if "MDMUrl" in indicators and indicators["MDMUrl"]:
                        self.dpa_indicators.append({
                            "key":   "MDM_Contract_Present",
                            "value": indicators["MDMUrl"],
                            "note":  "URL MDM presente — indica contrato de gestión activo",
                        })
        except Exception as e:
            print(f"[DPA] Error comprobando Azure AD: {e}")

    # ── Indicadores DPA en registro ────────────────────────────────────────────

    def _check_microsoft_dpa_registry(self):
        """Busca valores de registro que indiquen DPA o acuerdos de datos."""
        dpa_registry_checks = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
             "UseWUServer",
             "WSUS activo — gestión de actualizaciones corporativa"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
             "WUServer",
             "Servidor WSUS corporativo configurado"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\CCM",
             "SMSMP",
             "SCCM/ConfigMgr activo — gestión corporativa Microsoft"),
        ]

        for hive, key_path, value_name, description in dpa_registry_checks:
            try:
                key   = winreg.OpenKey(hive, key_path)
                value, _ = winreg.QueryValueEx(key, value_name)
                winreg.CloseKey(key)
                if value:
                    self.dpa_indicators.append({
                        "key":         value_name,
                        "value":       str(value)[:80],
                        "description": description,
                    })
                    print(f"[DPA] {description}: {str(value)[:50]}")
            except OSError:
                pass

    # ── Otros proveedores cloud ────────────────────────────────────────────────

    def _detect_other_providers(self):
        """Detecta otros proveedores cloud activos que requieren DPA."""
        other_providers = {
            "Nexthink": {
                "process": "nxtd.exe",
                "service": "Nexthink Collector",
                "dpa_required": True,
            },
            "CrowdStrike": {
                "process": "CSFalconService.exe",
                "service": "CSFalconService",
                "dpa_required": True,
            },
            "Zscaler": {
                "process": "ZSATunnel.exe",
                "service": "ZscalerService",
                "dpa_required": True,
            },
            "Netskope": {
                "process": "nsClientUIR.exe",
                "service": "NetskopeClient",
                "dpa_required": True,
            },
        }

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Process | Select-Object Name | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                procs = json.loads(result.stdout)
                if isinstance(procs, dict):
                    procs = [procs]
                running_procs = {
                    str(p.get("Name", "")).lower()
                    for p in (procs or [])
                }

                for provider, info in other_providers.items():
                    proc_name = info["process"].lower().replace(".exe", "")
                    if proc_name in running_procs:
                        self.providers_found.append({
                            "provider":     provider,
                            "process":      info["process"],
                            "dpa_required": info["dpa_required"],
                            "note": (
                                f"{provider} activo — requiere DPA "
                                "específico con este proveedor"
                            ),
                        })
                        print(f"[DPA] Proveedor detectado: {provider}")
        except Exception as e:
            print(f"[DPA] Error detectando proveedores: {e}")

    def _detect_generic_cloud_capabilities(self):
        """Detecta capacidad genérica de envío externo por agentes privilegiados."""
        generic_agents = []
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                    continue
                remote_ip = conn.raddr.ip
                if not self._is_external_ip(remote_ip):
                    continue
                pid = conn.pid
                if not pid:
                    continue
                try:
                    proc = psutil.Process(pid)
                    username = (proc.username() or "").lower()
                    if "system" not in username:
                        continue
                    generic_agents.append({
                        "provider": "Unknown/System Agent",
                        "process": proc.name(),
                        "pid": pid,
                        "username": proc.username(),
                        "remote_ip": remote_ip,
                        "remote_port": conn.raddr.port,
                        "dpa_required": True,
                        "note": (
                            "Proceso privilegiado con conexión externa activa; "
                            "requiere trazabilidad de finalidad y cobertura contractual"
                        ),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass

        # Evita duplicados exactos por proceso+ip+puerto
        seen = set()
        deduped = []
        for item in generic_agents:
            key = (item["process"], item["remote_ip"], item["remote_port"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)

        if deduped:
            self.providers_found.extend(deduped)
            print(f"[DPA] Capacidades genéricas detectadas (SYSTEM->externo): {len(deduped)}")

    # ── Reporte ────────────────────────────────────────────────────────────────

    def _report(self):
        from core.audit_engine import AuditFinding

        # ── Hallazgo 1: Tenant detectado ──────────────────────────────────────
        if self.tenant_id:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="dpa_tenant_identified",
                title=(
                    f"Equipo vinculado a tenant corporativo Microsoft: "
                    f"{self.tenant_name or self.tenant_id}"
                ),
                description=(
                    f"El equipo está registrado en el tenant de Microsoft 365 "
                    f"'{self.tenant_name or 'Desconocido'}' "
                    f"(ID: {self.tenant_id}). "
                    "Toda la actividad en servicios Microsoft queda vinculada "
                    "a este tenant y es potencialmente accesible al administrador."
                ),
                risk_level="yellow",
                technical_risk=(
                    "El tenant corporativo da al administrador de M365 acceso "
                    "a: logs de actividad, emails, documentos en OneDrive, "
                    "chats de Teams, historial de navegación Edge y "
                    "telemetría de dispositivo."
                ),
                legal_risk=(
                    "La vinculación al tenant corporativo implica que Microsoft "
                    "procesa datos del trabajador bajo el DPA empresa-Microsoft. "
                    "El trabajador tiene derecho a conocer qué datos se procesan "
                    "y bajo qué base legal bajo RGPD art. 13."
                ),
                what_it_is=(
                    "El tenant de Microsoft 365 es el identificador de la "
                    "organización en los servicios cloud de Microsoft. "
                    "Todos los datos creados en servicios Microsoft quedan "
                    "asociados a este tenant."
                ),
                what_it_is_not=(
                    "No implica que el empleador esté accediendo activamente "
                    "a los datos — pero tiene capacidad técnica para hacerlo "
                    "a través de la consola de administración de M365."
                ),
                raw_data={
                    "tenant_id":        self.tenant_id,
                    "tenant_name":      self.tenant_name,
                    "dpa_indicators":   self.dpa_indicators,
                    "dpa_reference_url": "https://aka.ms/DPA",
                }
            ))

        # ── Hallazgo 2: Telemetría no conforme con DPA estándar ───────────────
        if not self.telemetry_compliant:
            level_info = TELEMETRY_DPA_COMPLIANCE.get(
                self.telemetry_level,
                (str(self.telemetry_level), False, "")
            )
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="dpa_telemetry_noncompliant",
                title=(
                    f"Telemetría Windows nivel {level_info[0]} "
                    f"({self.telemetry_level}) — no conforme con DPA estándar AEPD"
                ),
                description=(
                    f"El nivel de telemetría configurado ({level_info[0]}) "
                    f"supera el nivel recomendado por la AEPD para "
                    f"entornos corporativos (nivel 1 — Básico). "
                    f"{level_info[2]}."
                ),
                risk_level="red",
                technical_risk=(
                    f"Nivel {self.telemetry_level} envía a Microsoft: "
                    + {
                        2: "datos de uso de aplicaciones, historial de navegación Edge, "
                           "contenido de búsquedas y diagnósticos detallados",
                        3: "todos los datos anteriores más: contenido de documentos, "
                           "memoria de procesos en error, actividad completa del usuario "
                           "y datos de configuración avanzada",
                    }.get(self.telemetry_level, "datos no especificados")
                ),
                legal_risk=(
                    "Un DPA con Microsoft que no incluya restricciones de telemetría "
                    "al nivel 1 puede no ser conforme con RGPD art. 5 "
                    "(minimización de datos) y art. 32 (seguridad del tratamiento). "
                    "La AEPD recomienda explícitamente nivel 1 en entornos corporativos."
                ),
                what_it_is=(
                    "El nivel de telemetría determina qué datos envía Windows "
                    "a Microsoft. El nivel Completo (3) es el máximo y el que "
                    "aplica por defecto sin política GPO."
                ),
                what_it_is_not=(
                    "No implica que Microsoft use estos datos de forma ilegítima. "
                    "El problema es que el empleador no ha aplicado las restricciones "
                    "técnicas que le corresponden bajo RGPD art. 32."
                ),
                raw_data={
                    "telemetry_level":       self.telemetry_level,
                    "telemetry_level_name":  level_info[0],
                    "aepd_recommended_level": 1,
                    "compliant":             False,
                    "discrepancies":         self.discrepancies,
                }
            ))

        # ── Hallazgo 3: Sin política de privacidad de Office ──────────────────
        no_office_policy = any(
            d["type"] == "office_no_privacy_policy"
            for d in self.discrepancies
        )
        if no_office_policy:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="dpa_office_no_policy",
                title="Office 365 sin política de privacidad GPO — telemetría máxima",
                description=(
                    "No existe política GPO de privacidad para Office 365. "
                    "Office opera con configuración por defecto, enviando "
                    "el máximo volumen de datos a Microsoft incluyendo "
                    "contenido de documentos para funciones de IA."
                ),
                risk_level="orange",
                technical_risk=(
                    "Sin política GPO, Office envía por defecto: "
                    "nombres de archivos, contenido para corrección ortográfica, "
                    "datos para PowerPoint Designer, datos para Editor IA, "
                    "uso de funciones y diagnósticos de aplicación."
                ),
                legal_risk=(
                    "El empleador debe configurar la privacidad de Office "
                    "mediante GPO para limitar el tratamiento de datos "
                    "de los trabajadores bajo RGPD art. 32 y art. 5. "
                    "Sin esta configuración el DPA con Microsoft puede ser "
                    "insuficiente para cubrir el volumen de datos transmitidos."
                ),
                what_it_is=(
                    "La ausencia de política GPO de privacidad de Office significa "
                    "que se aplica la configuración por defecto de Microsoft, "
                    "que es la más permisiva en cuanto a datos enviados."
                ),
                what_it_is_not=(
                    "No es una vulneración activa — es una omisión de medidas "
                    "técnicas que le corresponden al empleador."
                ),
                raw_data={
                    "office_privacy_values": self.office_services,
                    "recommendation":        "Aplicar GPO de privacidad Office nivel 2 o inferior",
                }
            ))

        # ── Hallazgo 4: Proveedores adicionales sin DPA verificable ───────────
        if self.providers_found:
            sources = get_sources(
                "endpoint_monitoring_capabilities",
                "worker_rights_and_surveillance_context",
            )
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="dpa_additional_providers",
                title=(
                    f"Proveedores cloud adicionales activos que requieren DPA: "
                    f"{', '.join(p['provider'] for p in self.providers_found)}"
                ),
                description=(
                    f"Se han detectado {len(self.providers_found)} proveedores "
                    "cloud adicionales activos en el equipo. Cada uno requiere "
                    "un DPA específico además del DPA con Microsoft."
                ),
                risk_level="orange",
                technical_risk=(
                    "Proveedores detectados: " +
                    ", ".join(
                        f"{p['provider']} ({p['process']})"
                        for p in self.providers_found
                    )
                ),
                legal_risk=(
                    "Cada proveedor cloud que procesa datos del trabajador "
                    "requiere su propio DPA y base legal bajo RGPD art. 28. "
                    "El trabajador tiene derecho a conocer todos los subencargados "
                    "del tratamiento bajo RGPD art. 13."
                ),
                what_it_is=(
                    "Agentes de software de terceros activos en el equipo que "
                    "envían datos a servidores externos, cada uno con sus "
                    "propios acuerdos de procesamiento de datos."
                ),
                what_it_is_not=(
                    "Su presencia no implica violación — pero el trabajador "
                    "tiene derecho a saber qué datos envía cada proveedor "
                    "y bajo qué acuerdo legal."
                ),
                raw_data={
                    "providers": self.providers_found,
                    "independent_sources": sources,
                    "triangulation": self.triangulation,
                }
            ))

        # ── Hallazgo 5: Solicitud de verificación DPA ─────────────────────────
        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="dpa_verification_needed",
            title="Verificación manual de DPA requerida — no automatizable completamente",
            description=(
                "La existencia y validez del DPA entre el empleador y Microsoft "
                "no puede verificarse técnicamente desde el equipo del trabajador. "
                "Requiere solicitud formal al DPO de la empresa."
            ),
            risk_level="yellow",
            technical_risk=(
                "Sin DPA válido con Microsoft, todo el tratamiento de datos "
                "a través de M365 (email, Teams, OneDrive, telemetría) "
                "carece de base legal adecuada bajo RGPD art. 28."
            ),
            legal_risk=(
                "El RGPD art. 28 exige contrato escrito entre responsable "
                "del tratamiento (empleador) y encargado (Microsoft). "
                "Sin DPA válido el empleador incumple RGPD y la AEPD "
                "puede imponer multas de hasta 10M€ o 2% de facturación global."
            ),
            what_it_is=(
                "Lista de verificaciones manuales necesarias para confirmar "
                "la existencia y adecuación del DPA con Microsoft y otros proveedores."
            ),
            what_it_is_not=(
                "No implica que el DPA no exista — simplemente no es verificable "
                "de forma técnica desde el equipo del trabajador."
            ),
            raw_data={
                "tenant_id":          self.tenant_id,
                "tenant_name":        self.tenant_name,
                "dpa_url_microsoft":  "https://aka.ms/DPA",
                "aepd_reference":     "https://www.aepd.es/guias/guia-proteccion-datos-relaciones-laborales.pdf",
                "independent_sources": get_sources(
                    "endpoint_monitoring_capabilities",
                    "event_and_logging_capabilities",
                    "worker_rights_and_surveillance_context",
                ),
                "triangulation": self.triangulation,
                "manual_checks": [
                    "Solicitar al DPO copia del DPA vigente con Microsoft",
                    "Verificar que el DPA incluye restricción de telemetría a nivel 1",
                    "Comprobar fecha de última revisión del DPA (debe ser posterior a Nov 2023)",
                    "Solicitar listado de subencargados aprobados por Microsoft",
                    f"Verificar DPA para Nexthink si está activo ({any(p['provider']=='Nexthink' for p in self.providers_found)})",
                    f"Verificar DPA para CrowdStrike si está activo ({any(p['provider']=='CrowdStrike' for p in self.providers_found)})",
                    "Solicitar registro de actividades de tratamiento (RAT) actualizado",
                ],
            }
        ))

        print(
            f"[DPA] Completado — "
            f"tenant: {self.tenant_name or 'no detectado'}, "
            f"telemetría conforme: {self.telemetry_compliant}, "
            f"discrepancias: {len(self.discrepancies)}, "
            f"proveedores: {len(self.providers_found)}"
        )