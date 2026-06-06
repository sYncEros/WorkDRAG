# skills/addon_audit/addon_scanner.py
"""
Skill — Add-in & Extension Auditor
Audita en profundidad extensiones de navegador, add-ins de Office/Outlook/Teams
y extensiones de VSCode con indicadores de monitorización o telemetría.
Complementa browser_audit, email_audit y third_party_apps_audit con detalle real
de permisos, capacidades y destinos de datos.
"""

import json
import subprocess
import winreg
import os
from pathlib import Path


# ── Catálogos de detección ─────────────────────────────────────────────────────

# Permisos de extensión de navegador que implican capacidad de vigilancia
HIGH_RISK_PERMISSIONS = {
    "<all_urls>":           "Acceso a todos los sitios web",
    "webRequest":           "Interceptar tráfico de red",
    "webRequestBlocking":   "Bloquear y modificar tráfico",
    "cookies":              "Leer y modificar cookies",
    "history":              "Acceder al historial de navegación",
    "tabs":                 "Ver URLs de todas las pestañas",
    "nativeMessaging":      "Comunicarse con apps nativas",
    "downloads":            "Acceder a descargas",
    "clipboardRead":        "Leer el portapapeles",
    "clipboardWrite":       "Escribir en el portapapeles",
    "desktopCapture":       "Capturar pantalla",
    "pageCapture":          "Capturar páginas completas",
    "management":           "Gestionar otras extensiones",
    "proxy":                "Controlar la configuración del proxy",
}

MEDIUM_RISK_PERMISSIONS = {
    "storage":              "Almacenar datos localmente",
    "identity":             "Acceder a identidad del usuario",
    "notifications":        "Mostrar notificaciones",
    "contextMenus":         "Añadir menús contextuales",
    "bookmarks":            "Acceder a marcadores",
}

# Extensiones conocidas de monitorización o vigilancia corporativa
KNOWN_SURVEILLANCE_EXTENSIONS = {
    "ejjladinnckdgjalghmamkbdkbiionfl": "Cisco Umbrella Roaming",
    "iheobagjkfklnlikgihanlhcddjoihkg": "Netskope Steering",
    "eppiocemhmnlbhjplcgkofciiegomcon": "Forcepoint DLP",
    "aapbdbdomjkkjkaonfhkkikfgjllcleb": "Google Translate (puede leer contenido)",
    "ndjpnladcallmjemlbaebfadecfhkepb": "Cisco AnyConnect",
    "bkbeeeffjjeopflfhgeknacdieedcoml": "CrowdStrike Falcon",
}

# Add-ins de Office de monitorización conocidos
KNOWN_MONITORING_ADDINS = {
    "MSIP.OutlookAddin":                "Microsoft Azure Information Protection — registra acceso a documentos y emails",
    "Microsoft.Purview.Compliance":     "Microsoft Purview — compliance y DLP",
    "Microsoft.DataLossPrevention":     "Microsoft DLP activo en Office",
    "Microsoft.InformationProtection":  "Azure Information Protection",
    "Veriato":                          "Veriato — monitorización de empleados",
    "Teramind":                         "Teramind — employee monitoring",
    "ActivTrak":                        "ActivTrak — productivity monitoring",
}

# Extensiones VSCode de time tracking / monitorización
VSCODE_TRACKERS = {
    "WakaTime.vscode-wakatime":         "WakaTime — time tracking de código",
    "codetime.codetime":                "Code Time — métricas de programación",
    "softwaredotcom.swdc-vscode":       "Software.com — developer analytics",
    "GitLab.gitlab-workflow":           "GitLab Workflow — puede reportar actividad",
    "GitHub.vscode-pull-request-github":"GitHub PR — reporta actividad a GitHub",
    "ms-vsliveshare.vsliveshare":       "Live Share — compartir sesión en tiempo real",
    "TabNine.tabnine-vscode":           "TabNine — envía código a servidores externos",
    "GitHub.copilot":                   "GitHub Copilot — envía código a Microsoft",
}

# Rutas de extensiones de navegador
BROWSER_EXTENSION_PATHS = {
    "Chrome": Path(os.environ.get("LOCALAPPDATA", "")) /
              "Google/Chrome/User Data/Default/Extensions",
    "Edge":   Path(os.environ.get("LOCALAPPDATA", "")) /
              "Microsoft/Edge/User Data/Default/Extensions",
    "Firefox": Path(os.environ.get("APPDATA", "")) /
               "Mozilla/Firefox/Profiles",
}

BROWSER_POLICY_KEYS = {
    "Chrome": r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
    "Edge":   r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist",
    "Firefox": r"SOFTWARE\Policies\Mozilla\Firefox\Extensions",
}

VSCODE_EXTENSIONS_PATH = Path(os.environ.get("USERPROFILE", "")) / ".vscode/extensions"

KNOWN_BENIGN_EXTENSIONS = {
    "maafgiompdekodanheihhgilkjchcakm": "S/MIME Outlook — firma digital de correo corporativo",
}

class AddonAudit:
    SKILL_NAME = "addon_audit"

    def __init__(self, engine):
        self.engine = engine
        self.browser_findings   = []
        self.office_findings    = []
        self.vscode_findings    = []
        self.teams_findings     = []

    def run(self):
        print("[Addon] Iniciando auditoría de add-ins y extensiones...")
        self._audit_browser_extensions()
        self._audit_forced_extensions()
        self._audit_office_addins()
        self._audit_vscode_extensions()
        self._audit_teams_compliance()
        self._report()

    # ── Navegador — extensiones instaladas ────────────────────────────────────

    def _audit_browser_extensions(self):
        """Analiza extensiones instaladas en Chrome y Edge con sus permisos."""
        for browser, ext_path in BROWSER_EXTENSION_PATHS.items():
            if not ext_path.exists():
                continue
            extensions = []
            for ext_id in ext_path.iterdir():
                if not ext_id.is_dir():
                    continue
                manifest = self._read_manifest(ext_id)
                if not manifest:
                    continue
                name        = manifest.get("name", ext_id.name)
                permissions = manifest.get("permissions", [])
                host_perms  = manifest.get("host_permissions", [])
                all_perms   = permissions + host_perms

                high   = [p for p in all_perms if p in HIGH_RISK_PERMISSIONS]
                medium = [p for p in all_perms if p in MEDIUM_RISK_PERMISSIONS]
                known  = KNOWN_SURVEILLANCE_EXTENSIONS.get(ext_id.name, "")

                if high or known:
                    extensions.append({
                        "id":          ext_id.name,
                        "name":        name,
                        "browser":     browser,
                        "high_risk":   high,
                        "medium_risk": medium,
                        "known":       known,
                        "all_perms":   all_perms,
                    })

            if extensions:
                print(f"[Addon] {browser} — {len(extensions)} extensiones con permisos relevantes")
                self.browser_findings.extend(extensions)

    def _read_manifest(self, ext_dir: Path) -> dict | None:
        """Lee el manifest.json de la versión más reciente de una extensión."""
        try:
            versions = [d for d in ext_dir.iterdir() if d.is_dir()]
            if not versions:
                return None
            latest = sorted(versions)[-1]
            manifest_path = latest / "manifest.json"
            if manifest_path.exists():
                return json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            pass
        return None

    # ── Navegador — extensiones forzadas por GPO ──────────────────────────────

    def _audit_forced_extensions(self):
        """Lee extensiones forzadas por políticas GPO en el registro."""
        forced = []
        for browser, reg_key in BROWSER_POLICY_KEYS.items():
            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    key = winreg.OpenKey(hive, reg_key)
                    i   = 0
                    while True:
                        try:
                            _, value, _ = winreg.EnumValue(key, i)
                            ext_id = str(value).split(";")[0].strip()
                            known  = KNOWN_SURVEILLANCE_EXTENSIONS.get(ext_id, "")
                            forced.append({
                                "browser":  browser,
                                "ext_id":   ext_id,
                                "known":    known,
                                "source":   "GPO HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "GPO HKCU",
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except OSError:
                    pass

        if forced:
            print(f"[Addon] Extensiones forzadas por GPO: {len(forced)}")
            self.browser_findings.extend([{**f, "forced": True} for f in forced])

    # ── Office add-ins ────────────────────────────────────────────────────────

    def _audit_office_addins(self):
        """Audita add-ins de Outlook/Office instalados via registro y GPO."""
        addin_keys = [
            r"SOFTWARE\Microsoft\Office\Outlook\Addins",
            r"SOFTWARE\Microsoft\Office\Word\Addins",
            r"SOFTWARE\Microsoft\Office\Excel\Addins",
            r"SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins",
        ]
        addins = []
        for key_path in addin_keys:
            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    key = winreg.OpenKey(hive, key_path)
                    i   = 0
                    while True:
                        try:
                            addin_name = winreg.EnumKey(key, i)
                            addin_key  = winreg.OpenKey(key, addin_name)
                            try:
                                desc, _ = winreg.QueryValueEx(addin_key, "Description")
                            except OSError:
                                desc = ""
                            try:
                                load_behavior, _ = winreg.QueryValueEx(addin_key, "LoadBehavior")
                            except OSError:
                                load_behavior = -1

                            known = ""
                            for k, v in KNOWN_MONITORING_ADDINS.items():
                                if k.lower() in addin_name.lower():
                                    known = v
                                    break

                            addins.append({
                                "name":          addin_name,
                                "description":   desc,
                                "load_behavior": load_behavior,
                                "always_loaded": load_behavior in (3, 9),
                                "known":         known,
                                "registry":      key_path,
                            })
                            winreg.CloseKey(addin_key)
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except OSError:
                    pass

        self.office_findings = addins
        if addins:
            always = [a for a in addins if a["always_loaded"]]
            known  = [a for a in addins if a["known"]]
            print(f"[Addon] Office add-ins: {len(addins)} total, {len(always)} siempre activos, {len(known)} conocidos")

    # ── VSCode extensiones ────────────────────────────────────────────────────

    def _audit_vscode_extensions(self):
        """Detecta extensiones VSCode con telemetría o time tracking."""
        if not VSCODE_EXTENSIONS_PATH.exists():
            print("[Addon] VSCode no detectado o sin extensiones")
            return

        trackers = []
        all_exts = []

        for ext_dir in VSCODE_EXTENSIONS_PATH.iterdir():
            if not ext_dir.is_dir():
                continue

            pkg_path = ext_dir / "package.json"
            if not pkg_path.exists():
                continue

            try:
                pkg = json.loads(
                    pkg_path.read_text(encoding="utf-8", errors="ignore")
                )
            except Exception:
                continue

            publisher   = pkg.get("publisher", "").lower().strip()
            name        = pkg.get("name", "").lower().strip()
            full_id     = f"{publisher}.{name}"
            description = str(pkg.get("description", "")).lower()

            # Buscar en catálogo por full_id
            tracker_id = ""
            for known_id, desc in VSCODE_TRACKERS.items():
                if desc is None:
                    continue
                if known_id.lower() == full_id:
                    tracker_id = desc
                    break

            # Detectar por publisher directamente
            if not tracker_id:
                risky_publishers = {
                    "openai":   "OpenAI Codex — envía código a servidores de OpenAI",
                    "tabnine":  "TabNine — envía código a servidores externos para IA",
                    "wakatime": "WakaTime — time tracking de actividad de código",
                }
                if publisher in risky_publishers:
                    tracker_id = risky_publishers[publisher]

            # Detectar por keywords en descripción o nombre
            telemetry_keywords = [
                "telemetry", "analytics", "tracking", "wakatime",
                "codetime", "metrics", "usage", "heartbeat", "ai code",
                "send code", "code completion ai",
            ]
            has_telemetry = (
                bool(tracker_id) or
                any(k in description for k in telemetry_keywords) or
                any(k in name for k in telemetry_keywords)
            )

            entry = {
                "dir":           ext_dir.name,
                "full_id":       f"{pkg.get('publisher', '?')}.{pkg.get('name', '?')}",
                "display_name":  pkg.get("displayName", pkg.get("name", ext_dir.name)),
                "known_tracker": tracker_id,
                "has_telemetry": has_telemetry,
            }
            all_exts.append(entry)
            if has_telemetry:
                trackers.append(entry)

        self.vscode_findings = trackers
        print(f"[Addon] VSCode — {len(all_exts)} extensiones, {len(trackers)} con telemetría")
        for t in trackers:
            print(f"[Addon]   ⚠️  {t['full_id']} — {t['known_tracker'] or 'telemetría detectada'}")

    # ── Teams Compliance Recording ─────────────────────────────────────────────

    def _audit_teams_compliance(self):
        """Detecta si Teams tiene Compliance Recording o supervisión activa."""
        compliance_indicators = []

        # Registro de políticas Teams
        teams_policy_keys = [
            r"SOFTWARE\Policies\Microsoft\Office\16.0\Teams",
            r"SOFTWARE\Microsoft\Office\16.0\Teams",
        ]
        for key_path in teams_policy_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                i   = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if any(k in name.lower() for k in
                               ["record", "compliance", "transcript", "capture", "monitor"]):
                            compliance_indicators.append({
                                "key":   name,
                                "value": value,
                                "path":  key_path,
                            })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                pass

        # Verificar configuración de Teams en AppData
        teams_config = (
            Path(os.environ.get("APPDATA", "")) /
            "Microsoft/Teams/desktop-config.json"
        )
        if teams_config.exists():
            try:
                config = json.loads(
                    teams_config.read_text(encoding="utf-8", errors="ignore")
                )
                if config.get("isComplianceRecordingEnabled"):
                    compliance_indicators.append({
                        "key":   "isComplianceRecordingEnabled",
                        "value": True,
                        "path":  str(teams_config),
                    })
                if config.get("enableTranscription"):
                    compliance_indicators.append({
                        "key":   "enableTranscription",
                        "value": True,
                        "path":  str(teams_config),
                    })
            except Exception:
                pass

        self.teams_findings = compliance_indicators
        if compliance_indicators:
            print(f"[Addon] Teams compliance indicators: {len(compliance_indicators)}")
        else:
            print("[Addon] Teams — sin indicadores de Compliance Recording detectados")

    # ── Reporte ────────────────────────────────────────────────────────────────

    def _report(self):
        from core.audit_engine import AuditFinding

        # ── Hallazgo 0: Extensiones forzadas por GPO (todas, sin filtro de catálogo)
        forced_all = [e for e in self.browser_findings if e.get("forced")]
        
        if forced_all:
            forced_suspicious = [
                e for e in forced_all
                if e["ext_id"] not in KNOWN_BENIGN_EXTENSIONS
            ]
            forced_benign = [
                e for e in forced_all
                if e["ext_id"] in KNOWN_BENIGN_EXTENSIONS
            ]
            risk = "green" if not forced_suspicious else "orange"

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="addon_browser_permissions",
                title=(
                    f"Extensiones forzadas por GPO: {len(forced_all)}"
                    + (f" ({len(forced_benign)} estándar corporativo)" if forced_benign else "")
                    + (f" ({len(forced_suspicious)} sin clasificar)" if forced_suspicious else "")
                ),
                description=(
                    f"La empresa ha forzado la instalación de {len(forced_all)} extensiones "
                    "en el navegador mediante política GPO. El trabajador no puede desinstalarlas."
                ),
                risk_level=risk,
                technical_risk=(
                    "IDs: " + ", ".join(e["ext_id"] for e in forced_all) +
                    ". Forzadas desde: " + ", ".join({e["source"] for e in forced_all})
                ),
                legal_risk=(
                    "Las extensiones forzadas por GPO requieren información previa al trabajador "
                    "sobre su función y datos que recopilan, bajo LOPDGDD art. 87 y RGPD art. 13."
                ),
                what_it_is=(
                    "Extensiones instaladas automáticamente por el empleador "
                    "sin intervención del trabajador."
                ),
                what_it_is_not=(
                    "No implica vigilancia activa, pero el trabajador no puede "
                    "conocer ni controlar su comportamiento."
                ),
                raw_data={
                    "forced_suspicious": forced_suspicious,
                    "forced_benign":     forced_benign,
                    "total_forced":      len(forced_all),
                }
            ))
        # ── Hallazgo 1: Extensiones navegador con permisos de vigilancia ──────
        high_risk_exts = [
            e for e in self.browser_findings
            if e.get("high_risk") or e.get("known")
        ]
        if high_risk_exts:
            forced = [e for e in high_risk_exts if e.get("forced")]
            risk   = "red" if forced else "orange"
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="addon_browser_permissions",
                title=(
                    f"Extensiones con permisos de vigilancia: "
                    f"{len(high_risk_exts)} detectadas"
                    + (f" ({len(forced)} forzadas por GPO)" if forced else "")
                ),
                description=(
                    f"Se han detectado {len(high_risk_exts)} extensiones "
                    f"con permisos de alto riesgo. "
                    + (f"{len(forced)} están forzadas por política corporativa. " if forced else "")
                    + "Estas extensiones tienen capacidad técnica de "
                    "interceptar formularios, leer contraseñas o capturar contenido web."
                ),
                risk_level=risk,
                technical_risk=(
                    "Permisos detectados: " +
                    ", ".join({
                        HIGH_RISK_PERMISSIONS.get(p, p)
                        for e in high_risk_exts
                        for p in e.get("high_risk", [])
                    })
                ),
                legal_risk=(
                    "Extensiones con acceso completo al navegador pueden interceptar "
                    "comunicaciones del trabajador. Requieren información previa bajo "
                    "LOPDGDD art. 87 y doctrina Barbulescu II."
                ),
                what_it_is=(
                    "Extensiones instaladas en el navegador que han declarado permisos "
                    "amplios sobre el contenido web, tráfico de red o datos del usuario."
                ),
                what_it_is_not=(
                    "No todas las extensiones con estos permisos son maliciosas. "
                    "Algunas son herramientas legítimas de seguridad corporativa. "
                    "El problema es la falta de información previa al trabajador."
                ),
                raw_data={
                    "extensions":     high_risk_exts,
                    "forced_by_gpo":  forced,
                    "total_detected": len(high_risk_exts),
                }
            ))

        # ── Hallazgo 2: Add-ins Office siempre activos ─────────────────────────
        always_on = [a for a in self.office_findings if a["always_loaded"]]
        if always_on:
            known_monitor = [a for a in always_on if a["known"]]
            risk = "red" if known_monitor else "orange"
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="addon_office_capabilities",
                title=(
                    f"Add-ins de Office siempre activos: {len(always_on)}"
                    + (f" ({len(known_monitor)} de monitorización conocidos)"
                       if known_monitor else "")
                ),
                description=(
                    f"Se han detectado {len(always_on)} add-ins de Office "
                    f"configurados para cargarse siempre (LoadBehavior 3 o 9). "
                    "Tienen acceso completo a emails, documentos y calendarios."
                ),
                risk_level=risk,
                technical_risk=(
                    "Add-ins con LoadBehavior 3/9 se cargan en cada inicio de Office "
                    "con acceso a todos los datos del buzón y documentos abiertos."
                ),
                legal_risk=(
                    "Add-ins corporativos en Outlook pueden leer, clasificar y reenviar "
                    "correos del trabajador. La doctrina Barbulescu II exige información "
                    "previa sobre el alcance del acceso."
                ),
                what_it_is=(
                    "Complementos de Microsoft Office instalados que se activan "
                    "automáticamente con el programa y tienen acceso a todos sus datos."
                ),
                what_it_is_not=(
                    "No todos los add-ins son de vigilancia. Muchos son herramientas "
                    "de productividad legítimas. El riesgo está en los que envían "
                    "datos a sistemas externos sin información al trabajador."
                ),
                raw_data={
                    "addins":             always_on,
                    "known_monitoring":   known_monitor,
                    "total_addins_found": len(self.office_findings),
                }
            ))

        # ── Hallazgo 3: VSCode time trackers ──────────────────────────────────
        if self.vscode_findings:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="addon_vscode_trackers",
                title=(
                    f"Extensiones VSCode con telemetría de actividad: "
                    f"{len(self.vscode_findings)} detectadas"
                ),
                description=(
                    f"Se han detectado {len(self.vscode_findings)} extensiones "
                    "de VSCode que recopilan métricas de actividad del desarrollador: "
                    "tiempo de codificación, proyectos activos, lenguajes usados."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Extensiones detectadas: " +
                    ", ".join(
                        e.get("known_tracker") or e["name"]
                        for e in self.vscode_findings
                    )
                ),
                legal_risk=(
                    "Las extensiones de time tracking monitorizan la actividad técnica "
                    "del desarrollador de forma continua. Si son instaladas corporativamente "
                    "sin información previa vulneran LOPDGDD art. 87."
                ),
                what_it_is=(
                    "Extensiones de VSCode que registran métricas de programación: "
                    "tiempo activo, archivos editados, lenguajes y proyectos."
                ),
                what_it_is_not=(
                    "Algunas son instaladas voluntariamente por el propio desarrollador. "
                    "El problema es cuando son corporativas y no informadas."
                ),
                raw_data={"trackers": self.vscode_findings}
            ))
        
        # ── Hallazgo 4: Teams Compliance Recording ────────────────────────────
        if self.teams_findings:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="addon_teams_recording",
                title=(
                    f"Teams — indicadores de grabación o compliance activos "
                    f"({len(self.teams_findings)})"
                ),
                description=(
                    "Se han detectado configuraciones de Teams que indican "
                    "grabación automática, transcripción o compliance recording activo."
                ),
                risk_level="red",
                technical_risk=(
                    "Indicadores: " +
                    ", ".join(f["key"] for f in self.teams_findings)
                ),
                legal_risk=(
                    "El Compliance Recording en Teams graba todas las llamadas y reuniones "
                    "del trabajador. Requiere información previa expresa bajo LOPDGDD art. 87 "
                    "y LOPDGDD art. 89 (videovigilancia). La doctrina Barbulescu II "
                    "exige proporcionalidad y finalidad legítima."
                ),
                what_it_is=(
                    "Configuración de Microsoft Teams que activa la grabación automática "
                    "de llamadas y reuniones para cumplimiento normativo corporativo."
                ),
                what_it_is_not=(
                    "No es grabación ilegal por sí misma. El problema es si el trabajador "
                    "no fue informado previamente de su existencia y alcance."
                ),
                raw_data={"indicators": self.teams_findings}
            ))

        print(
            f"[Addon] Completado — "
            f"extensiones navegador: {len(self.browser_findings)}, "
            f"add-ins Office: {len(self.office_findings)}, "
            f"VSCode trackers: {len(self.vscode_findings)}, "
            f"Teams compliance: {len(self.teams_findings)}"
        )