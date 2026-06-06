# skills/third_party_apps_audit/third_party_scanner.py
"""
Skill — Auditoría de Apps de Terceros con Telemetría
Analiza Slack, Zoom, Teams, VSCode, y otras apps corporativas:
endpoints de telemetría, permisos, políticas corporativas y
configuración gestionada por la empresa.
"""

import winreg
import subprocess
import json
from pathlib import Path


class ThirdPartyAppsAudit:
    SKILL_NAME = "third_party_apps_audit"

    # Definición de apps a auditar con sus indicadores
    APP_PROFILES = {
        "slack": {
            "display_name": "Slack",
            "install_patterns": ["slack"],
            "config_paths": [
                Path.home() / "AppData" / "Roaming" / "Slack",
            ],
            "telemetry_endpoints": [
                "api.slack.com", "slack.com/api", "analytics.slack.com",
                "slack-core.com",
            ],
            "policy_keys": [
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Policies\Slack Technologies\Slack"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Policies\SlackTechnologies\Slack"),
            ],
            "risk_note": (
                "Slack puede enviar telemetría de uso, mensajes de diagnóstico "
                "y datos de actividad. Con licencias Enterprise Grid, "
                "los administradores pueden exportar todos los mensajes incluidos "
                "los canales privados y DMs con autorización judicial o interna."
            ),
        },
        "zoom": {
            "display_name": "Zoom",
            "install_patterns": ["zoom"],
            "config_paths": [
                Path.home() / "AppData" / "Roaming" / "Zoom",
            ],
            "telemetry_endpoints": [
                "zoom.us", "telemetry.zoom.us", "analytics.zoom.us",
                "log.zoom.us",
            ],
            "policy_keys": [
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Policies\Zoom\Zoom Meetings"),
                (winreg.HKEY_CURRENT_USER,
                 r"SOFTWARE\Zoom\Zoom Meetings"),
            ],
            "risk_note": (
                "Zoom recopila datos de uso de reuniones, calidad de audio/video, "
                "estadísticas de participantes y metadatos de reuniones. "
                "La función de atención (attention tracking) fue eliminada, "
                "pero pueden existir funciones de supervisión corporativas."
            ),
        },
        "teams": {
            "display_name": "Microsoft Teams",
            "install_patterns": ["teams", "msteams"],
            "config_paths": [
                Path.home() / "AppData" / "Roaming" / "Microsoft" / "Teams",
                Path.home() / "AppData" / "Local" / "Microsoft" / "Teams",
            ],
            "telemetry_endpoints": [
                "teams.microsoft.com", "presence.teams.microsoft.com",
                "config.teams.microsoft.com", "teams.cdn.office.net",
            ],
            "policy_keys": [
                (winreg.HKEY_CURRENT_USER,
                 r"SOFTWARE\Microsoft\Office\Teams"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Policies\Microsoft\MicrosoftTeams"),
            ],
            "risk_note": (
                "Teams comparte la infraestructura de M365: el empleador puede "
                "acceder a chats, reuniones grabadas y archivos compartidos "
                "desde el centro de administración. Los administradores pueden "
                "activar la supervisión de comunicaciones (Communication Compliance)."
            ),
        },
        "vscode": {
            "display_name": "Visual Studio Code",
            "install_patterns": ["visual studio code", "vscode", "code.exe"],
            "config_paths": [
                Path.home() / "AppData" / "Roaming" / "Code",
            ],
            "telemetry_endpoints": [
                "dc.services.visualstudio.com", "vortex.data.microsoft.com",
                "marketplace.visualstudio.com",
            ],
            "policy_keys": [
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Policies\Microsoft\VisualStudioCode"),
            ],
            "risk_note": (
                "VSCode envía telemetría de uso y errores a Microsoft por defecto. "
                "Las extensiones instaladas pueden tener telemetría propia. "
                "Si hay extensiones corporativas forzadas, pueden enviar "
                "información sobre el código escrito a servidores externos."
            ),
        },
        "webex": {
            "display_name": "Cisco Webex",
            "install_patterns": ["webex", "cisco webex"],
            "config_paths": [
                Path.home() / "AppData" / "Local" / "WebEx",
            ],
            "telemetry_endpoints": [
                "webex.com", "ciscospark.com", "wbx2.com",
            ],
            "policy_keys": [],
            "risk_note": (
                "Webex en entornos corporativos puede activar grabación "
                "automática de reuniones y transcripción con IA. "
                "Los administradores tienen acceso a todas las grabaciones."
            ),
        },
        "chrome": {
            "display_name": "Google Chrome",
            "install_patterns": ["google chrome"],
            "config_paths": [
                Path.home() / "AppData" / "Local" / "Google" / "Chrome",
            ],
            "telemetry_endpoints": [
                "clients4.google.com", "update.googleapis.com",
                "safebrowsing.googleapis.com",
            ],
            "policy_keys": [
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Policies\Google\Chrome"),
                (winreg.HKEY_CURRENT_USER,
                 r"SOFTWARE\Policies\Google\Chrome"),
            ],
            "risk_note": (
                "Chrome con políticas corporativas puede tener "
                "CloudReporting activo (envía actividad al admin), "
                "extensiones forzadas y modo incógnito deshabilitado."
            ),
        },
    }

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[ThirdPartyApps] Iniciando auditoría de aplicaciones de terceros...")
        installed = self._get_installed_apps()
        self._analyze_corporate_apps(installed)
        self._analyze_app_policies()
        self._analyze_vscode_extensions()
        self._analyze_teams_compliance()
        print("[ThirdPartyApps] Completado.")

    # ── Apps instaladas y sus perfiles de riesgo ───────────────────

    def _get_installed_apps(self) -> list[dict]:
        apps = []
        uninstall_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hive, path in uninstall_keys:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        sub_name = winreg.EnumKey(key, idx)
                        sub = winreg.OpenKey(key, sub_name, 0, winreg.KEY_READ)
                        info = {}
                        for field in ["DisplayName", "Publisher",
                                      "DisplayVersion", "InstallDate"]:
                            try:
                                v, _ = winreg.QueryValueEx(sub, field)
                                info[field.lower()] = str(v)
                            except (FileNotFoundError, PermissionError, OSError):
                                pass
                        winreg.CloseKey(sub)
                        if info.get("displayname"):
                            apps.append(info)
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass
        return apps

    def _match_app_profile(self, app_name: str) -> str | None:
        name_lower = app_name.lower()
        for app_key, profile in self.APP_PROFILES.items():
            if any(p in name_lower for p in profile["install_patterns"]):
                return app_key
        return None

    # ── Análisis de apps corporativas conocidas ────────────────────

    def _analyze_corporate_apps(self, installed: list[dict]):
        from core.audit_engine import AuditFinding

        found_apps = {}
        for app in installed:
            name = app.get("displayname", "")
            profile_key = self._match_app_profile(name)
            if profile_key and profile_key not in found_apps:
                found_apps[profile_key] = {
                    "installed_name": name,
                    "version": app.get("displayversion"),
                    "publisher": app.get("publisher"),
                    "install_date": app.get("installdate"),
                    **self.APP_PROFILES[profile_key],
                }

        if not found_apps:
            return

        apps_summary = []
        for key, app in found_apps.items():
            config_exists = any(
                p.exists() for p in app.get("config_paths", [])
            )
            apps_summary.append({
                "app": app["display_name"],
                "version": app.get("version"),
                "config_present": config_exists,
                "telemetry_endpoints": app.get("telemetry_endpoints", []),
                "risk_note": app.get("risk_note"),
            })

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="third_party_apps_installed",
            title=f"Apps corporativas con telemetría detectadas ({len(found_apps)})",
            description=(
                "Se han detectado aplicaciones de colaboración y desarrollo "
                "con capacidades de telemetría y control corporativo: "
                + ", ".join(a["display_name"] for a in found_apps.values()) + "."
            ),
            risk_level="yellow",
            technical_risk=(
                "Estas aplicaciones envían telemetría de uso a sus proveedores "
                "y pueden tener funciones de control corporativo (exportación de "
                "mensajes, grabación de reuniones, estadísticas de actividad) "
                "accesibles para administradores de empresa."
            ),
            legal_risk=(
                "El uso de funciones de supervisión en estas plataformas "
                "(exportación de chats, compliance, Communication Compliance) "
                "sin información previa puede vulnerar LOPDGDD art. 87 "
                "y ET art. 20bis."
            ),
            what_it_is=(
                "Aplicaciones de productividad y colaboración corporativas "
                "que incluyen funcionalidades de control y telemetría "
                "accesibles por administradores de empresa."
            ),
            what_it_is_not=(
                "La telemetría de diagnóstico estándar (errores, rendimiento) "
                "es diferente de las funciones de supervisión de empleados."
            ),
            raw_data={"apps": apps_summary}
        ))

    # ── Políticas GPO de apps de terceros ──────────────────────────

    def _analyze_app_policies(self):
        from core.audit_engine import AuditFinding

        all_policies = []

        for app_key, profile in self.APP_PROFILES.items():
            for hive, reg_path in profile.get("policy_keys", []):
                hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                try:
                    key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
                    values = []
                    idx = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, idx)
                            values.append({"name": name, "value": str(value)})
                            idx += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                    if values:
                        all_policies.append({
                            "app": profile["display_name"],
                            "registry_path": f"{hive_name}\\{reg_path}",
                            "policies": values,
                        })
                except (FileNotFoundError, PermissionError, OSError):
                    pass

        if not all_policies:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="third_party_apps_policies",
            title=f"Políticas corporativas GPO de apps de terceros "
                  f"({len(all_policies)} apps)",
            description=(
                "Se han encontrado configuraciones de políticas corporativas "
                "aplicadas a aplicaciones de terceros mediante el registro de Windows."
            ),
            risk_level="orange",
            technical_risk=(
                "Las políticas GPO de estas apps pueden forzar: telemetría activa, "
                "desactivar cifrado E2E, forzar inicio de sesión corporativo, "
                "habilitar grabación automática o bloquear ajustes de privacidad."
            ),
            legal_risk=(
                "Políticas que activan funciones de supervisión sin informar "
                "al trabajador pueden vulnerar LOPDGDD art. 87 y RGPD art. 13. "
                "La desactivación forzada de cifrado E2E es especialmente sensible."
            ),
            what_it_is=(
                "Configuraciones del registro aplicadas por GPO corporativa "
                "que controlan el comportamiento de apps como Teams, "
                "Zoom, Chrome o VSCode."
            ),
            what_it_is_not=(
                "No todas las políticas de apps implican supervisión. "
                "Muchas son de seguridad: forzar login corporativo, "
                "deshabilitar funciones no autorizadas."
            ),
            raw_data={"app_policies": all_policies}
        ))

    # ── Extensiones de VSCode ──────────────────────────────────────

    def _analyze_vscode_extensions(self):
        from core.audit_engine import AuditFinding

        extensions_dir = Path.home() / ".vscode" / "extensions"
        if not extensions_dir.exists():
            return

        extensions = []
        monitoring_keywords = [
            "telemetry", "monitor", "track", "analytics", "audit",
            "activity", "time", "productivity", "keylog", "screenshot",
        ]

        for ext_dir in extensions_dir.iterdir():
            if not ext_dir.is_dir():
                continue
            pkg_file = ext_dir / "package.json"
            if not pkg_file.exists():
                continue
            try:
                pkg = json.loads(pkg_file.read_text(encoding="utf-8", errors="ignore"))
                name = pkg.get("name", "")
                publisher = pkg.get("publisher", "")
                description = pkg.get("description", "")
                combined = (name + publisher + description).lower()

                ext_info = {
                    "name": name,
                    "publisher": publisher,
                    "version": pkg.get("version"),
                    "description": description[:120] if description else None,
                    "suspicious": any(k in combined for k in monitoring_keywords),
                }

                # Comprobar si tiene acceso a red en su contribuciones
                capabilities = pkg.get("capabilities", {})
                if capabilities.get("untrustedWorkspaces", {}).get("supported") == "limited":
                    ext_info["restricted_in_untrusted"] = True

                extensions.append(ext_info)
            except Exception:
                pass

        if not extensions:
            return

        suspicious = [e for e in extensions if e["suspicious"]]
        risk = "orange" if suspicious else "green"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="vscode_extensions",
            title=f"Extensiones de VSCode instaladas ({len(extensions)}, "
                  f"{len(suspicious)} con indicadores de telemetría)",
            description=(
                "Se han detectado extensiones de Visual Studio Code. "
                "Las extensiones tienen acceso al código fuente, terminal "
                "y pueden enviar telemetría a sus proveedores."
            ),
            risk_level=risk,
            technical_risk=(
                "Las extensiones de VSCode se ejecutan con los permisos del usuario "
                "y pueden leer archivos, ejecutar comandos y comunicarse con "
                "servidores externos. Extensiones de productivity/time tracking "
                "pueden monitorizar el tiempo de desarrollo."
            ),
            legal_risk=(
                "Extensiones de telemetría de código o time tracking instaladas "
                "corporativamente sin información previa pueden vulnerar "
                "LOPDGDD art. 87 si monitorizan la actividad del desarrollador."
            ),
            what_it_is=(
                "Complementos del editor de código que amplían sus funcionalidades. "
                "Pueden ser instalados por el usuario o forzados por políticas."
            ),
            what_it_is_not=(
                "La mayoría de extensiones son herramientas de productividad legítimas: "
                "linting, autocompletado, control de versiones."
            ),
            raw_data={
                "extensions": extensions,
                "suspicious": suspicious,
                "total": len(extensions)
            }
        ))

    # ── Teams Communication Compliance ────────────────────────────

    def _analyze_teams_compliance(self):
        from core.audit_engine import AuditFinding

        compliance_indicators = []

        # Buscar configuración de Teams que indica compliance corporativo
        teams_config_path = (
            Path.home() / "AppData" / "Roaming" / "Microsoft" / "Teams"
        )
        if teams_config_path.exists():
            # Buscar archivos de configuración de políticas
            for config_file in ["settings.json", "desktop-config.json"]:
                cfg = teams_config_path / config_file
                if cfg.exists():
                    try:
                        data = json.loads(
                            cfg.read_text(encoding="utf-8", errors="ignore")
                        )
                        if isinstance(data, dict):
                            # Indicadores de políticas corporativas
                            if data.get("isLoggedIn") and data.get("currentOrg"):
                                compliance_indicators.append({
                                    "type": "teams_corporate_login",
                                    "org": data.get("currentOrg", {}).get("name"),
                                    "tenant_id": data.get("currentOrg", {}).get("id"),
                                    "note": "Login corporativo activo — "
                                            "el administrador de M365 tiene acceso "
                                            "a chats y reuniones."
                                })
                    except Exception:
                        pass

        # Comprobar registro de Teams
        teams_reg_paths = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Office\Teams"),
        ]
        for hive, path in teams_reg_paths:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        if any(k in name.lower() for k in
                               ["compliance", "record", "policy", "supervise"]):
                            compliance_indicators.append({
                                "type": "teams_registry_policy",
                                "key": name,
                                "value": str(value),
                            })
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        if not compliance_indicators:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="teams_compliance",
            title=f"Indicadores de supervisión corporativa en Microsoft Teams "
                  f"({len(compliance_indicators)})",
            description=(
                "Se han detectado indicadores de uso corporativo de Microsoft Teams "
                "que pueden implicar acceso del empleador a comunicaciones."
            ),
            risk_level="orange",
            technical_risk=(
                "Con Teams bajo tenant corporativo M365, el administrador puede: "
                "exportar chats (eDiscovery), activar Communication Compliance "
                "(supervisión de mensajes con IA), acceder a grabaciones de reuniones "
                "y ver presencia y actividad de usuarios."
            ),
            legal_risk=(
                "La supervisión de mensajes de Teams mediante Communication Compliance "
                "requiere información previa explícita bajo LOPDGDD art. 87 "
                "y la doctrina Barbulescu II. El secreto de las comunicaciones "
                "se aplica incluso en canales laborales."
            ),
            what_it_is=(
                "Funcionalidades del tenant M365 que permiten al empleador "
                "acceder y supervisar las comunicaciones de Teams de sus empleados."
            ),
            what_it_is_not=(
                "El uso de Teams para trabajo no implica automáticamente supervisión. "
                "Requiere configuración activa por parte del administrador."
            ),
            raw_data={"compliance_indicators": compliance_indicators}
        ))
