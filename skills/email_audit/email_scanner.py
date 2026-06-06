# skills/email_audit/email_scanner.py
"""
Skill — Auditoría de Cliente de Email
Detecta add-ins de Outlook corporativos, reglas de reenvío automático,
acceso de terceros al buzón, perfiles IMAP/SMTP configurados y
políticas Exchange que controlan la configuración del cliente.
"""

import winreg
import subprocess
import json
from pathlib import Path


class EmailAudit:
    SKILL_NAME = "email_audit"

    # Add-ins de monitorización conocidos para Outlook
    MONITORING_ADDIN_KEYWORDS = [
        "monitor", "audit", "track", "record", "dlp",
        "compliance", "archiv", "journaling", "supervision",
        "policy", "retention", "ediscovery", "legal hold",
        "barracuda", "proofpoint", "mimecast", "symantec",
        "zix", "virtru", "sealpath",
    ]

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[Email] Iniciando auditoría de cliente de email...")
        self._check_outlook_addins()
        self._check_outlook_profiles()
        self._check_forwarding_rules()
        self._check_exchange_policies()
        self._check_email_archiving()
        print("[Email] Completado.")

    # ── Add-ins de Outlook ─────────────────────────────────────────

    def _check_outlook_addins(self):
        from core.audit_engine import AuditFinding

        addin_paths = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Office\Outlook\Addins"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Office\Outlook\Addins"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins"),
        ]

        addins = []
        for hive, path in addin_paths:
            hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        addin_name = winreg.EnumKey(key, idx)
                        info = self._get_addin_info(hive, path, addin_name)
                        if info:
                            info["hive"] = hive_name
                            info["suspicious"] = self._is_monitoring_addin(info)
                            addins.append(info)
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        if not addins:
            return

        suspicious = [a for a in addins if a["suspicious"]]
        risk = "orange" if suspicious else "yellow"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="email_outlook_addins",
            title=f"Add-ins de Outlook detectados ({len(addins)}, "
                  f"{len(suspicious)} con indicadores de monitorización)",
            description=(
                "Se han encontrado complementos instalados en Outlook. "
                "Los add-ins tienen acceso completo al buzón: emails, "
                "contactos, calendarios y datos adjuntos."
            ),
            risk_level=risk,
            technical_risk=(
                "Los add-ins de Outlook se ejecutan dentro del cliente de email "
                "y pueden leer, copiar y enviar cualquier elemento del buzón. "
                "Los add-ins corporativos forzados pueden enviar copias de emails "
                "a sistemas de archivado o supervisión."
            ),
            legal_risk=(
                "Add-ins que copian o analizan el contenido del buzón sin "
                "información previa al trabajador pueden vulnerar LOPDGDD art. 87 "
                "y el secreto de las comunicaciones. Requieren base legal explícita."
            ),
            what_it_is=(
                "Complementos instalados en Microsoft Outlook que amplían "
                "sus funcionalidades. Pueden ser instalados por el usuario "
                "o forzados por políticas corporativas."
            ),
            what_it_is_not=(
                "No todo add-in es vigilancia. Herramientas de firma digital, "
                "cifrado, calendarios y productividad también son add-ins legítimos."
            ),
            raw_data={
                "addins": addins,
                "suspicious": suspicious,
                "total": len(addins)
            }
        ))

    def _get_addin_info(self, hive, base_path: str, addin_name: str) -> dict | None:
        try:
            path = f"{base_path}\\{addin_name}"
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            info = {"name": addin_name}
            for field in ["FriendlyName", "Description", "LoadBehavior",
                          "Manifest", "CommandLineSafe"]:
                try:
                    val, _ = winreg.QueryValueEx(key, field)
                    info[field.lower()] = str(val)
                except (FileNotFoundError, PermissionError, OSError):
                    pass
            winreg.CloseKey(key)
            return info
        except Exception:
            return None

    def _is_monitoring_addin(self, addin: dict) -> bool:
        text = " ".join([
            str(addin.get("name", "")),
            str(addin.get("friendlyname", "")),
            str(addin.get("description", "")),
        ]).lower()
        return any(k in text for k in self.MONITORING_ADDIN_KEYWORDS)

    # ── Perfiles de Outlook y cuentas configuradas ─────────────────

    def _check_outlook_profiles(self):
        from core.audit_engine import AuditFinding

        profiles = []

        # Perfiles de Outlook en registro
        profile_paths = [
            r"SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles",
            r"SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles",
        ]

        for path in profile_paths:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ
                )
                idx = 0
                while True:
                    try:
                        profile_name = winreg.EnumKey(key, idx)
                        profiles.append({
                            "profile_name": profile_name,
                            "registry_path": path,
                        })
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
                break
            except (FileNotFoundError, PermissionError, OSError):
                pass

        if not profiles:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="email_outlook_profiles",
            title=f"Perfiles de Outlook configurados ({len(profiles)})",
            description=(
                "Se han detectado perfiles de Outlook. Cada perfil puede "
                "contener múltiples cuentas de email y sus configuraciones."
            ),
            risk_level="green",
            technical_risk=(
                "Inventario de perfiles. Múltiples perfiles pueden indicar "
                "acceso a cuentas corporativas adicionales no conocidas."
            ),
            legal_risk=(
                "Bajo. Es información estructural de configuración. "
                "El empleador puede tener acceso a las cuentas Exchange configuradas."
            ),
            what_it_is=(
                "Perfiles de configuración de Microsoft Outlook que agrupan "
                "cuentas de email y sus ajustes de conexión."
            ),
            what_it_is_not=(
                "No contiene el contenido de los emails, solo la configuración "
                "de conexión y preferencias del cliente."
            ),
            raw_data={"profiles": profiles}
        ))

    # ── Reglas de reenvío automático ───────────────────────────────

    def _check_forwarding_rules(self):
        from core.audit_engine import AuditFinding

        # Buscar reglas de Outlook almacenadas localmente o en Exchange
        # Comprobamos mediante PowerShell si hay reglas de reenvío activas
        forwarding_rules = []

        # Método 1: Buscar en reglas almacenadas en archivo .rwz local
        outlook_appdata = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Outlook"
        if outlook_appdata.exists():
            rule_files = list(outlook_appdata.glob("*.rwz"))
            for rf in rule_files:
                forwarding_rules.append({
                    "type": "local_rules_file",
                    "path": str(rf),
                    "size_bytes": rf.stat().st_size,
                    "note": "Archivo de reglas de Outlook encontrado. "
                            "Requiere análisis manual para verificar reglas de reenvío."
                })

        # Método 2: Intentar consultar Exchange via PowerShell/EWS (sin credenciales adicionales)
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Add-Type -AssemblyName 'Microsoft.Office.Interop.Outlook' -ErrorAction SilentlyContinue; "
                 "$outlook = New-Object -ComObject Outlook.Application -ErrorAction SilentlyContinue; "
                 "if ($outlook) { "
                 "  $rules = $outlook.Session.DefaultStore.GetRules(); "
                 "  $ruleList = @(); "
                 "  foreach ($rule in $rules) { "
                 "    $ruleList += @{Name=$rule.Name; Enabled=$rule.Enabled; IsServer=$rule.IsServer} "
                 "  }; "
                 "  $ruleList | ConvertTo-Json "
                 "} else { '[]' }"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip() not in ("[]", ""):
                rules_data = json.loads(result.stdout)
                if isinstance(rules_data, dict):
                    rules_data = [rules_data]
                for rule in (rules_data or []):
                    rule_info = {
                        "type": "outlook_rule",
                        "name": rule.get("Name"),
                        "enabled": rule.get("Enabled"),
                        "is_server_rule": rule.get("IsServer"),
                    }
                    forwarding_rules.append(rule_info)
        except Exception:
            pass

        # Comprobar configuración de reenvío en Exchange via registro
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover",
                0, winreg.KEY_READ
            )
            try:
                redirect, _ = winreg.QueryValueEx(key, "RedirectServers")
                if redirect:
                    forwarding_rules.append({
                        "type": "autodiscover_redirect",
                        "redirect_servers": str(redirect),
                        "note": "Configuración de redirección de Autodiscover detectada."
                    })
            except (FileNotFoundError, PermissionError, OSError):
                pass
            winreg.CloseKey(key)
        except Exception:
            pass

        if not forwarding_rules:
            return

        server_rules = [r for r in forwarding_rules if r.get("is_server_rule")]
        risk = "orange" if server_rules else "yellow"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="email_forwarding_rules",
            title=f"Configuración de reglas de email ({len(forwarding_rules)} elementos)",
            description=(
                "Se han detectado reglas de email o archivos de reglas de Outlook. "
                "Las reglas de reenvío automático pueden enviar copias de emails "
                "a direcciones no deseadas."
            ),
            risk_level=risk,
            technical_risk=(
                "Las reglas de reenvío activas en servidor (Exchange) redirigen "
                "emails incluso cuando el cliente Outlook no está abierto. "
                "Las reglas de reenvío a externos pueden ser vectores de exfiltración "
                "de datos o resultado de compromisos de cuenta."
            ),
            legal_risk=(
                "Reglas de reenvío configuradas por el empleador sin conocimiento "
                "del trabajador pueden vulnerar el secreto de las comunicaciones "
                "y LOPDGDD art. 87."
            ),
            what_it_is=(
                "Reglas de procesamiento automático de email que pueden mover, "
                "copiar o reenviar mensajes según criterios predefinidos."
            ),
            what_it_is_not=(
                "No toda regla es problemática. Filtros de spam, organización "
                "de carpetas y respuestas automáticas son usos legítimos."
            ),
            raw_data={"rules": forwarding_rules}
        ))

    # ── Políticas Exchange (MAPI/registry) ─────────────────────────

    def _check_exchange_policies(self):
        from core.audit_engine import AuditFinding

        policies = []

        exchange_policy_keys = [
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Policies\Microsoft\office\16.0\outlook",
             "Outlook policies (HKCU)"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\office\16.0\outlook",
             "Outlook policies (HKLM)"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Exchange\Client\Options",
             "Exchange Client Options"),
        ]

        for hive, path, label in exchange_policy_keys:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(key, idx)
                        policies.append({
                            "source": label,
                            "name": name,
                            "value": str(value),
                            "type": vtype,
                        })
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        if not policies:
            return

        # Filtrar políticas de supervisión/archivado
        supervision_keywords = [
            "journaling", "archiv", "retention", "compliance",
            "supervision", "dlp", "audit", "legal", "ediscovery"
        ]
        supervision = [
            p for p in policies
            if any(k in p["name"].lower() for k in supervision_keywords)
        ]

        risk = "orange" if supervision else "yellow"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="email_exchange_policies",
            title=f"Políticas GPO de Outlook/Exchange activas ({len(policies)})",
            description=(
                "Se han detectado políticas corporativas aplicadas al cliente "
                "de email Outlook mediante GPO o registro."
            ),
            risk_level=risk,
            technical_risk=(
                "Las políticas de Exchange pueden forzar archivado de emails, "
                "deshabilitar cifrado personal, activar journaling, "
                "controlar configuración del cliente o forzar add-ins."
            ),
            legal_risk=(
                "Políticas que activan journaling o supervisión de email "
                "sin información previa vulneran LOPDGDD art. 87 "
                "y el secreto de las comunicaciones (CP art. 197)."
            ),
            what_it_is=(
                "Configuraciones forzadas por la empresa para controlar el "
                "comportamiento de Outlook y su conexión con Exchange/M365."
            ),
            what_it_is_not=(
                "Muchas políticas son de seguridad estándar: desactivar macros, "
                "forzar cifrado TLS, deshabilitar acceso a cuentas personales."
            ),
            raw_data={"policies": policies, "supervision_policies": supervision}
        ))

    # ── Archivado y Journaling ──────────────────────────────────────

    def _check_email_archiving(self):
        from core.audit_engine import AuditFinding

        archiving_indicators = []

        # Comprobar si hay cliente de archivado corporativo instalado
        archiving_software = [
            "Mimecast", "Proofpoint", "Barracuda Email Archiver",
            "Symantec Enterprise Vault", "Veritas Enterprise Vault",
            "Global Relay", "Smarsh", "Postmaster", "GFI MailArchiver",
            "MailStore", "Jatheon", "Retain", "Zantaz"
        ]

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
                 "| Select-Object DisplayName, Publisher | ConvertTo-Json"],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0 and result.stdout.strip():
                installed = json.loads(result.stdout)
                if isinstance(installed, dict):
                    installed = [installed]
                for app in installed:
                    name = str(app.get("DisplayName") or "").lower()
                    for sw in archiving_software:
                        if sw.lower() in name:
                            archiving_indicators.append({
                                "software": app.get("DisplayName"),
                                "publisher": app.get("Publisher"),
                                "type": "email_archiving",
                            })
        except Exception:
            pass

        # Comprobar si hay carpeta OST de archivado en línea
        ost_paths = [
            Path.home() / "AppData" / "Local" / "Microsoft" / "Outlook",
            Path("C:/Users") / Path.home().name / "AppData/Local/Microsoft/Outlook"
        ]
        for ost_base in ost_paths:
            if ost_base.exists():
                for f in ost_base.glob("*.ost"):
                    archiving_indicators.append({
                        "type": "ost_file",
                        "path": str(f),
                        "size_mb": round(f.stat().st_size / 1024 / 1024, 1),
                        "note": "Archivo de datos Outlook (caché local del buzón Exchange)"
                    })
                break

        if not archiving_indicators:
            return

        software_found = [i for i in archiving_indicators if i["type"] == "email_archiving"]
        risk = "orange" if software_found else "green"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="email_archiving",
            title=f"Indicadores de archivado de email ({len(archiving_indicators)})",
            description=(
                "Se han detectado indicadores de sistemas de archivado de email: "
                "software de archivado corporativo o archivos de datos de Outlook."
            ),
            risk_level=risk,
            technical_risk=(
                "El software de archivado corporativo realiza copias de todos "
                "los emails enviados y recibidos en sistemas corporativos. "
                "El empleador tiene acceso a este archivo en herramientas de eDiscovery."
            ),
            legal_risk=(
                "El archivado de emails es una práctica corporativa estándar "
                "pero requiere información previa al trabajador bajo LOPDGDD art. 87 "
                "sobre el período de retención y quién tiene acceso."
            ),
            what_it_is=(
                "Sistemas que copian automáticamente todos los emails corporativos "
                "a un repositorio centralizado, accesible por la empresa."
            ),
            what_it_is_not=(
                "El archivado por obligación legal (compliance financiero, "
                "sector sanitario) es un requisito normativo, no vigilancia."
            ),
            raw_data={"archiving": archiving_indicators}
        ))
