# skills/browser_audit/browser_scanner.py
"""
Skill 9 — Browser Data Audit
Detecta extensiones con acceso completo, sincronización de credenciales,
perfiles corporativos forzados, tracking embebido y políticas de navegador.
"""

import winreg
import json
import psutil
from pathlib import Path


# Extensiones conocidas por categoría y riesgo
EXTENSION_CATALOG = {
    # DLP / Inspección
    "extensions_dlp": {
        "jlgkhfafeamlnhgejgpmaennmamoaeef": ("Netskope", "orange"),
        "iheobagjkfklnlikgihanlhcddjoihkg": ("Zscaler", "orange"),
        "egnfpagmkjmiajklhgimhagnbgkljnjj": ("Forcepoint", "orange"),
        "mbgjekkfehklgdlhagbckhioggphlbmb": ("McAfee Web Control", "orange"),
        "llbcnfanfmailgelbbdpikanikkonbgm": ("Symantec DLP", "orange"),
        "kpmjjcbbgbdhknnomcjplmhgmkjbfhli": ("Microsoft Purview", "yellow"),
    },
    # Productividad / Monitorización
    "extensions_monitoring": {
        "aohghmighlieiainnegkcijnfilokake": ("Google Docs Offline", "green"),
        "mgndgikekgjfcpckkfioiadnlibdjbkf": ("Chrome Remote Desktop", "orange"),
        "pkedcjkdefgpdelpbcmbmeomcjbeemfm": ("Chrome Remote Desktop Host", "orange"),
        "gbkeegbaiigmenfmjfclcdghdpoidnfe": ("ActivTrak", "red"),
        "nkehbobngnhlfehankjkhjblbnkjjiij": ("Teramind", "red"),
    },
    # SSO / Identidad corporativa
    "extensions_identity": {
        "jmjjcblbhgblcfijokichlfnlbphlogi": ("Microsoft SSO", "yellow"),
        "ppnbnpeolgkicgegkbkbjmhlideopiji": ("Okta Browser Plugin", "yellow"),
        "iabjkhmealbicmcojdiahlfjoiecbmlf": ("OneLogin", "yellow"),
        "bcaajmmepmbcgjnmkljliogmhbiokopm": ("Ping Identity", "yellow"),
    },
    # Password managers corporativos
    "extensions_password": {
        "hdokiejnpimakedhajhdlcegeplioahd": ("LastPass", "yellow"),
        "aeblfdkhhhdcdjpifhhbdiojplfjncoa": ("1Password", "yellow"),
        "nngceckbapebfimnlniiiahkandclblb": ("Bitwarden", "green"),
        "fdjamakpfbbddfjaooikfcpapjohcfmg": ("Dashlane", "yellow"),
    },
}

# Permisos de extensión de alto riesgo
HIGH_RISK_PERMISSIONS = [
    "tabs",
    "webRequest",
    "webRequestBlocking",
    "nativeMessaging",
    "clipboardRead",
    "clipboardWrite",
    "history",
    "bookmarks",
    "cookies",
    "downloads",
    "management",
    "proxy",
]

BROWSERS = {
    "chrome": {
        "name": "Google Chrome",
        "ext_path": Path.home() / "AppData/Local/Google/Chrome/User Data/Default/Extensions",
        "prefs_path": Path.home() / "AppData/Local/Google/Chrome/User Data/Default/Preferences",
        "policy_key": r"SOFTWARE\Policies\Google\Chrome",
        "sync_key": r"SOFTWARE\Policies\Google\Chrome\SyncDisabled",
    },
    "edge": {
        "name": "Microsoft Edge",
        "ext_path": Path.home() / "AppData/Local/Microsoft/Edge/User Data/Default/Extensions",
        "prefs_path": Path.home() / "AppData/Local/Microsoft/Edge/User Data/Default/Preferences",
        "policy_key": r"SOFTWARE\Policies\Microsoft\Edge",
        "sync_key": r"SOFTWARE\Policies\Microsoft\Edge\SyncDisabled",
    },
    "firefox": {
        "name": "Mozilla Firefox",
        "ext_path": Path.home() / "AppData/Roaming/Mozilla/Firefox/Profiles",
        "prefs_path": None,
        "policy_key": r"SOFTWARE\Policies\Mozilla\Firefox",
        "sync_key": None,
    },
}


class BrowserAudit:
    SKILL_NAME = "browser_audit"

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[Browser] Iniciando auditoría de navegadores...")
        self._check_forced_extensions()
        self._check_installed_extensions()
        self._check_credential_sync()
        self._check_browser_policies()
        self._check_corporate_profiles()
        self._check_password_storage()

    # ── Extensiones forzadas por política ─────────────────────────

    def _check_forced_extensions(self):
        from core.audit_engine import AuditFinding

        forced = {}

        for browser_id, browser in BROWSERS.items():
            policy_key = browser.get("policy_key")
            if not policy_key:
                continue

            for subkey in ["ExtensionInstallForcelist",
                           "ExtensionInstallAllowlist"]:
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        f"{policy_key}\\{subkey}",
                        0, winreg.KEY_READ
                    )
                    idx = 0
                    while True:
                        try:
                            _, val, _ = winreg.EnumValue(key, idx)
                            ext_id = str(val).split(";")[0].strip()
                            if ext_id not in forced:
                                forced[ext_id] = {
                                    "browser": browser["name"],
                                    "type": subkey,
                                    "known": self._lookup_extension(ext_id),
                                }
                            idx += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except (FileNotFoundError, PermissionError, OSError):
                    pass

        if forced:
            high_risk = {
                k: v for k, v in forced.items()
                if v["known"] and v["known"]["risk"] in ["orange", "red"]
            }

            risk = "red" if any(
                v["known"]["risk"] == "red"
                for v in forced.values() if v["known"]
            ) else "orange"

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="browser_forced_extensions",
                title=f"Extensiones forzadas por política corporativa "
                      f"({len(forced)} extensiones)",
                description=(
                    f"{len(forced)} extensiones instaladas obligatoriamente "
                    f"por política GPO que el usuario no puede eliminar. "
                    + (f"{len(high_risk)} son de categoría de riesgo alto."
                       if high_risk else "")
                ),
                risk_level=risk,
                technical_risk=(
                    "Las extensiones forzadas tienen acceso completo "
                    "al navegador: contenido de páginas, formularios, "
                    "contraseñas introducidas, historial y cookies. "
                    "Algunas pueden interceptar o modificar el tráfico web."
                ),
                legal_risk=(
                    "Las extensiones con permisos amplios instaladas sin "
                    "conocimiento explícito del trabajador pueden vulnerar "
                    "LOPDGDD art. 87. Requieren información previa sobre "
                    "su función y datos que recopilan."
                ),
                what_it_is=(
                    "Extensiones de navegador instaladas por la empresa "
                    "mediante política GPO que no pueden ser eliminadas "
                    "por el usuario."
                ),
                what_it_is_not=(
                    "No todas son espionaje. Muchas son herramientas "
                    "de seguridad, SSO o DLP legítimas. "
                    "El problema es la falta de transparencia "
                    "sobre qué datos recopilan."
                ),
                raw_data={
                    "forced_extensions": forced,
                    "high_risk_count": len(high_risk)
                }
            ))
            print(
                f"[Browser] Extensiones forzadas: {len(forced)} "
                f"({len(high_risk)} alto riesgo)"
            )

    def _lookup_extension(self, ext_id: str) -> dict | None:
        for category, extensions in EXTENSION_CATALOG.items():
            if ext_id in extensions:
                name, risk = extensions[ext_id]
                return {"name": name, "risk": risk, "category": category}
        return None

    # ── Extensiones instaladas ─────────────────────────────────────

    def _check_installed_extensions(self):
        from core.audit_engine import AuditFinding

        suspicious_extensions = []

        for browser_id, browser in BROWSERS.items():
            ext_path = browser.get("ext_path")
            if not ext_path or not ext_path.exists():
                continue

            try:
                for ext_dir in ext_path.iterdir():
                    if not ext_dir.is_dir():
                        continue
                    ext_id = ext_dir.name

                    # Busca manifest.json
                    manifest = self._read_extension_manifest(ext_dir)
                    if not manifest:
                        continue

                    permissions = manifest.get("permissions", [])
                    high_risk_perms = [
                        p for p in permissions
                        if p in HIGH_RISK_PERMISSIONS
                    ]

                    # Verifica si está en catálogo conocido
                    known = self._lookup_extension(ext_id)

                    if known and known["risk"] in ["orange", "red"]:
                        suspicious_extensions.append({
                            "browser": browser["name"],
                            "id": ext_id,
                            "name": known["name"],
                            "risk": known["risk"],
                            "category": known["category"],
                            "permissions": high_risk_perms,
                        })
                    elif len(high_risk_perms) >= 4:
                        name = manifest.get("name", ext_id)
                        suspicious_extensions.append({
                            "browser": browser["name"],
                            "id": ext_id,
                            "name": name,
                            "risk": "orange",
                            "category": "unknown_high_permissions",
                            "permissions": high_risk_perms,
                        })
            except PermissionError:
                pass

        if suspicious_extensions:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="browser_suspicious_extensions",
                title=f"Extensiones con permisos amplios detectadas "
                      f"({len(suspicious_extensions)})",
                description=(
                    "Extensiones instaladas con acceso a datos sensibles "
                    "del navegador: contenido web, historial, cookies."
                ),
                risk_level="orange",
                technical_risk=(
                    "Extensiones con permisos como 'tabs', 'webRequest', "
                    "'cookies' o 'clipboardRead' tienen acceso a toda "
                    "la actividad de navegación y pueden interceptar "
                    "o exfiltrar datos."
                ),
                legal_risk=(
                    "Si estas extensiones transmiten datos de navegación "
                    "a terceros sin conocimiento del trabajador, "
                    "puede vulnerar LOPDGDD art. 87 y RGPD art. 5."
                ),
                what_it_is=(
                    "Extensiones de navegador con permisos que les dan "
                    "acceso amplio a la actividad de navegación."
                ),
                what_it_is_not=(
                    "Los permisos amplios no implican uso malicioso. "
                    "Muchas extensiones legítimas los necesitan "
                    "para funcionar correctamente."
                ),
                raw_data={"suspicious": suspicious_extensions}
            ))

    def _read_extension_manifest(self, ext_dir: Path) -> dict | None:
        for version_dir in ext_dir.iterdir():
            if not version_dir.is_dir():
                continue
            manifest_path = version_dir / "manifest.json"
            if manifest_path.exists():
                try:
                    return json.loads(
                        manifest_path.read_text(encoding="utf-8", errors="ignore")
                    )
                except Exception:
                    pass
        return None

    # ── Sincronización de credenciales ─────────────────────────────

    def _check_credential_sync(self):
        from core.audit_engine import AuditFinding

        sync_issues = []

        for browser_id, browser in BROWSERS.items():
            prefs_path = browser.get("prefs_path")
            if not prefs_path or not prefs_path.exists():
                continue

            try:
                prefs = json.loads(
                    prefs_path.read_text(encoding="utf-8", errors="ignore")
                )

                # Verifica si la sincronización está activa
                sync = prefs.get("sync", {})
                signin = prefs.get("signin", {})

                sync_active = (
                    sync.get("has_setup_sync_paused") is False or
                    sync.get("requested") or
                    signin.get("allowed")
                )

                # Verifica si las contraseñas se sincronizan
                passwords_syncing = (
                    sync.get("passwords") or
                    prefs.get("password_manager_enabled") or
                    prefs.get("credentials_enable_service")
                )

                if sync_active and passwords_syncing:
                    sync_issues.append({
                        "browser": browser["name"],
                        "sync_active": sync_active,
                        "passwords_syncing": bool(passwords_syncing),
                    })
            except Exception:
                pass

        if sync_issues:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="browser_credential_sync",
                title=f"Sincronización de contraseñas activa "
                      f"en {len(sync_issues)} navegadores",
                description=(
                    "Los navegadores están sincronizando contraseñas "
                    "guardadas hacia servidores externos "
                    "(Google/Microsoft)."
                ),
                risk_level="orange",
                technical_risk=(
                    "Las contraseñas sincronizadas están almacenadas "
                    "en servidores de Google o Microsoft. "
                    "En un perfil corporativo, el administrador "
                    "puede tener acceso a estas credenciales."
                ),
                legal_risk=(
                    "La sincronización de credenciales en perfiles "
                    "corporativos puede exponer contraseñas personales "
                    "al empleador. Riesgo bajo LOPDGDD art. 87."
                ),
                what_it_is=(
                    "Función del navegador que sincroniza contraseñas "
                    "guardadas entre dispositivos a través de la nube."
                ),
                what_it_is_not=(
                    "No implica que el empleador acceda activamente "
                    "a las contraseñas, pero existe la capacidad técnica "
                    "en perfiles corporativos gestionados."
                ),
                raw_data={"sync_browsers": sync_issues}
            ))

    # ── Políticas de navegador ─────────────────────────────────────

    def _check_browser_policies(self):
        from core.audit_engine import AuditFinding

        HIGH_RISK_POLICIES = {
            "SafeBrowsingExtendedReportingEnabled":
                "Reporte extendido de navegación segura — envía URLs a Google",
            "MetricsReportingEnabled":
                "Reportes de métricas habilitados",
            "CloudReportingEnabled":
                "Reporte en nube habilitado — actividad enviada al admin",
            "CloudManagementEnrollmentToken":
                "Equipo inscrito en gestión cloud del navegador",
            "BrowserSignin":
                "Inicio de sesión en navegador (1=obligatorio, 2=forzado)",
            "ManagedBookmarks":
                "Marcadores gestionados por la empresa",
            "URLBlocklist":
                "Lista de URLs bloqueadas por política",
            "URLAllowlist":
                "Lista de URLs permitidas por política",
            "PasswordManagerEnabled":
                "Gestor de contraseñas del navegador",
            "AutofillAddressEnabled":
                "Autocompletado de direcciones",
            "AutofillCreditCardEnabled":
                "Autocompletado de tarjetas de crédito",
            "PrintingEnabled":
                "Impresión habilitada/deshabilitada",
            "IncognitoModeAvailability":
                "Disponibilidad del modo incógnito (0=disponible, 1=desactivado)",
        }

        for browser_id, browser in BROWSERS.items():
            policy_key = browser.get("policy_key")
            if not policy_key:
                continue

            found_policies = {}
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    policy_key, 0, winreg.KEY_READ
                )
                for pol_name, description in HIGH_RISK_POLICIES.items():
                    try:
                        val, _ = winreg.QueryValueEx(key, pol_name)
                        found_policies[pol_name] = {
                            "value": val,
                            "description": description
                        }
                    except (FileNotFoundError, OSError):
                        pass
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

            if not found_policies:
                continue

            # CloudReportingEnabled es especialmente relevante
            cloud_reporting = "CloudReportingEnabled" in found_policies
            incognito_blocked = (
                found_policies.get(
                    "IncognitoModeAvailability", {}
                ).get("value") == 1
            )

            risk = "orange"
            if cloud_reporting:
                risk = "red"

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="browser_policies",
                title=f"Políticas corporativas en {browser['name']} "
                      f"({len(found_policies)} activas)"
                      + (" — Cloud Reporting activo" if cloud_reporting else "")
                      + (" — Modo incógnito bloqueado" if incognito_blocked else ""),
                description=(
                    f"{browser['name']} tiene {len(found_policies)} "
                    f"políticas corporativas activas que controlan "
                    f"su comportamiento."
                ),
                risk_level=risk,
                technical_risk=(
                    "CloudReportingEnabled envía datos de actividad "
                    "del navegador al administrador corporativo. "
                    "El bloqueo del modo incógnito impide al trabajador "
                    "tener sesiones de navegación privadas. "
                    "BrowserSignin forzado vincula la actividad al perfil "
                    "corporativo y la sincroniza."
                ),
                legal_risk=(
                    "CloudReportingEnabled sin información previa "
                    "al trabajador puede vulnerar LOPDGDD art. 87. "
                    "El bloqueo del modo incógnito elimina una herramienta "
                    "de privacidad del trabajador."
                ),
                what_it_is=(
                    "Políticas GPO que controlan el comportamiento del "
                    "navegador: qué puede hacer el usuario, qué datos "
                    "se envían y cómo se gestiona la sesión."
                ),
                what_it_is_not=(
                    "Las políticas de navegador son gestión corporativa "
                    "estándar. El problema es cuándo incluyen "
                    "reporting de actividad sin transparencia."
                ),
                raw_data={
                    "browser": browser["name"],
                    "policies": found_policies,
                    "cloud_reporting": cloud_reporting,
                    "incognito_blocked": incognito_blocked,
                }
            ))

    # ── Perfiles corporativos ──────────────────────────────────────

    def _check_corporate_profiles(self):
        from core.audit_engine import AuditFinding

        corporate_profiles = []

        for browser_id, browser in BROWSERS.items():
            prefs_path = browser.get("prefs_path")
            if not prefs_path or not prefs_path.exists():
                continue

            try:
                prefs = json.loads(
                    prefs_path.read_text(encoding="utf-8", errors="ignore")
                )

                account_info = prefs.get("account_info", [])
                if isinstance(account_info, list):
                    for account in account_info:
                        email = account.get("email", "")
                        if email and not email.endswith(
                            ("gmail.com", "outlook.com",
                             "hotmail.com", "yahoo.com")
                        ):
                            corporate_profiles.append({
                                "browser": browser["name"],
                                "email": email,
                                "is_corporate": True,
                            })
            except Exception:
                pass

        if corporate_profiles:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="browser_corporate_profile",
                title=f"Perfil corporativo activo en navegador "
                      f"({len(corporate_profiles)} cuentas)",
                description=(
                    "El navegador tiene sesión iniciada con cuenta "
                    "corporativa, vinculando la actividad de navegación "
                    "al perfil empresarial."
                ),
                risk_level="orange",
                technical_risk=(
                    "Con un perfil corporativo activo, el historial, "
                    "marcadores, extensiones y contraseñas guardadas "
                    "se sincronizan con la infraestructura corporativa. "
                    "El administrador de M365/Google Workspace puede "
                    "tener acceso a estos datos."
                ),
                legal_risk=(
                    "La navegación bajo perfil corporativo puede ser "
                    "monitorizadas por el empleador. "
                    "LOPDGDD art. 87 exige informar al trabajador "
                    "del alcance de esta monitorización."
                ),
                what_it_is=(
                    "Sesión del navegador iniciada con cuenta corporativa "
                    "que sincroniza actividad con la nube empresarial."
                ),
                what_it_is_not=(
                    "No implica lectura activa. Es una funcionalidad "
                    "de sincronización que requiere transparencia "
                    "sobre quién puede acceder a los datos."
                ),
                raw_data={"corporate_profiles": corporate_profiles}
            ))

    # ── Almacenamiento de contraseñas ──────────────────────────────

    def _check_password_storage(self):
        from core.audit_engine import AuditFinding

        password_dbs = []
        browser_password_paths = {
            "Chrome":
                Path.home() / "AppData/Local/Google/Chrome"
                             "/User Data/Default/Login Data",
            "Edge":
                Path.home() / "AppData/Local/Microsoft/Edge"
                             "/User Data/Default/Login Data",
            "Firefox":
                None,
        }

        for browser_name, db_path in browser_password_paths.items():
            if db_path and db_path.exists():
                try:
                    size_kb = db_path.stat().st_size / 1024
                    password_dbs.append({
                        "browser": browser_name,
                        "path": str(db_path),
                        "size_kb": round(size_kb, 1),
                    })
                except Exception:
                    pass

        if password_dbs:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="browser_password_db",
                title=f"Bases de datos de contraseñas del navegador "
                      f"detectadas ({len(password_dbs)})",
                description=(
                    "Los navegadores mantienen localmente bases de datos "
                    "con contraseñas guardadas cifradas."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Las bases de datos de contraseñas del navegador "
                    "están cifradas con la clave del perfil de Windows. "
                    "Un proceso con privilegios de administrador o un "
                    "agente EDR puede acceder a estas credenciales."
                ),
                legal_risk=(
                    "Las contraseñas personales guardadas en el navegador "
                    "corporativo están técnicamente accesibles para "
                    "el empleador. No guardar contraseñas personales "
                    "en navegadores corporativos."
                ),
                what_it_is=(
                    "Archivo SQLite local donde el navegador almacena "
                    "credenciales guardadas, cifradas con la clave "
                    "del perfil de Windows."
                ),
                what_it_is_not=(
                    "No implica que el empleador esté leyendo "
                    "las contraseñas. Es una advertencia sobre "
                    "la accesibilidad técnica potencial."
                ),
                raw_data={"password_dbs": password_dbs}
            ))

        print("[Browser] Completado")