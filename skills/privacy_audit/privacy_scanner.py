# skills/privacy_audit/privacy_scanner.py
"""
Skill 6 — Privacy Surface Audit
Detecta acceso a webcam, micrófono, clipboard,
APIs de screenshot y hooks de input
"""

import winreg
import subprocess
import json
import psutil
from pathlib import Path


# Procesos legítimos que usan cámara/micro
LEGITIMATE_AV_PROCS = {
    "teams", "zoom", "skype", "webex", "meet",
    "slack", "discord", "obs", "streamlabs",
    "chrome", "msedge", "firefox", "opera"
}

# APIs de captura de pantalla en procesos sospechosos
SCREENSHOT_API_KEYWORDS = [
    "screenshot", "screencap", "capture", "recorder",
    "screenrecord", "bitblt", "printwindow"
]

# Procesos con nombres asociados a keylogging/input hooks
INPUT_HOOK_KEYWORDS = [
    "hook", "keylog", "inputlog", "kbcapture",
    "mouselog", "inputcapture", "spyware", "monitor"
]


class PrivacyAudit:
    SKILL_NAME = "privacy_audit"

    def __init__(self, engine):
        self.engine = engine
        self.running_processes = self._get_running_processes()

    def run(self):
        print("[Privacy] Iniciando auditoría de superficie de privacidad...")
        self._check_camera_permissions()
        self._check_microphone_permissions()
        self._check_clipboard_access()
        self._check_location_access()
        self._check_input_hooks()
        self._check_screenshot_tools()
        self._check_screen_recording_policy()

    def _get_running_processes(self) -> dict:
        procs = {}
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                procs[proc.info["name"].lower().replace(".exe", "")] = {
                    "pid": proc.info["pid"],
                    "exe": proc.info.get("exe", "")
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs

    # ── Cámara ────────────────────────────────────────────────────

    def _check_camera_permissions(self):
        from core.audit_engine import AuditFinding

        camera_access = []
        suspicious_camera = []

        try:
            # Apps con acceso a cámara via UWP permissions
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                r"\CapabilityAccessManager\ConsentStore\webcam",
                0, winreg.KEY_READ
            )
            idx = 0
            while True:
                try:
                    app_name = winreg.EnumKey(key, idx)
                    app_key = winreg.OpenKey(key, app_name)
                    try:
                        value, _ = winreg.QueryValueEx(app_key, "Value")
                        if value == "Allow":
                            camera_access.append(app_name)
                            # Sospechoso si no es app de videollamada conocida
                            if not any(
                                leg in app_name.lower()
                                for leg in LEGITIMATE_AV_PROCS
                            ):
                                suspicious_camera.append(app_name)
                    except (FileNotFoundError, OSError):
                        pass
                    winreg.CloseKey(app_key)
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        if camera_access:
            risk = "orange" if suspicious_camera else "yellow"
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="privacy_camera",
                title=f"Aplicaciones con acceso a cámara "
                      f"({len(camera_access)} apps)",
                description=(
                    f"{len(camera_access)} aplicaciones tienen permiso "
                    f"de acceso a la cámara web. "
                    f"{len(suspicious_camera)} no son aplicaciones "
                    f"de videollamada conocidas."
                ),
                risk_level=risk,
                technical_risk=(
                    "Las aplicaciones con acceso a cámara pueden "
                    "activarla sin indicación visual en algunos casos."
                ),
                legal_risk=(
                    "El acceso a cámara en horario laboral sin "
                    "consentimiento explícito vulnera gravemente "
                    "LOPDGDD art. 89 y ET art. 20bis."
                ),
                what_it_is=(
                    "Permisos de acceso a cámara concedidos a "
                    "aplicaciones instaladas en el sistema."
                ),
                what_it_is_not=(
                    "Tener permiso no implica uso activo. "
                    "Teams, Zoom y similares necesitan este permiso "
                    "para videollamadas."
                ),
                raw_data={
                    "apps_with_access": camera_access,
                    "suspicious": suspicious_camera
                }
            ))

    # ── Micrófono ─────────────────────────────────────────────────

    def _check_microphone_permissions(self):
        from core.audit_engine import AuditFinding

        mic_access = []
        suspicious_mic = []

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                r"\CapabilityAccessManager\ConsentStore\microphone",
                0, winreg.KEY_READ
            )
            idx = 0
            while True:
                try:
                    app_name = winreg.EnumKey(key, idx)
                    app_key = winreg.OpenKey(key, app_name)
                    try:
                        value, _ = winreg.QueryValueEx(app_key, "Value")
                        if value == "Allow":
                            mic_access.append(app_name)
                            if not any(
                                leg in app_name.lower()
                                for leg in LEGITIMATE_AV_PROCS
                            ):
                                suspicious_mic.append(app_name)
                    except (FileNotFoundError, OSError):
                        pass
                    winreg.CloseKey(app_key)
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        if suspicious_mic:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="privacy_microphone",
                title=f"Apps no-videollamada con acceso a micrófono "
                      f"({len(suspicious_mic)})",
                description=(
                    f"Se han encontrado {len(suspicious_mic)} aplicaciones "
                    f"con acceso a micrófono que no son apps de "
                    f"videollamada estándar."
                ),
                risk_level="orange",
                technical_risk=(
                    "Aplicaciones con acceso a micrófono pueden capturar "
                    "audio ambiente de forma continua."
                ),
                legal_risk=(
                    "La grabación de audio sin consentimiento es "
                    "especialmente grave y puede constituir delito "
                    "bajo el art. 197 del Código Penal además de "
                    "vulnerar LOPDGDD."
                ),
                what_it_is=(
                    "Permisos de acceso a micrófono concedidos a "
                    "aplicaciones que no son videollamadas estándar."
                ),
                what_it_is_not=(
                    "Puede ser software de transcripción, accesibilidad "
                    "o asistentes de voz legítimos."
                ),
                raw_data={
                    "all_mic_access": mic_access,
                    "suspicious": suspicious_mic
                }
            ))

    # ── Clipboard ─────────────────────────────────────────────────

    def _check_clipboard_access(self):
        from core.audit_engine import AuditFinding

        clipboard_apps = []
        clipboard_keywords = [
            "clip", "paste", "board", "copy",
            "clipboard", "clipsync"
        ]

        for name, info in self.running_processes.items():
            if any(k in name for k in clipboard_keywords):
                if not any(
                    leg in name for leg in ["svchost", "system", "windows"]
                ):
                    clipboard_apps.append({
                        "name": name, "pid": info["pid"]
                    })

        # También verifica via registro
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                r"\CapabilityAccessManager\ConsentStore\clipboardRead",
                0, winreg.KEY_READ
            )
            idx = 0
            while True:
                try:
                    app_name = winreg.EnumKey(key, idx)
                    app_key = winreg.OpenKey(key, app_name)
                    try:
                        value, _ = winreg.QueryValueEx(app_key, "Value")
                        if value == "Allow":
                            clipboard_apps.append({"name": app_name, "source": "registry"})
                    except (FileNotFoundError, OSError):
                        pass
                    winreg.CloseKey(app_key)
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        if clipboard_apps:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="privacy_clipboard",
                title=f"Posible acceso al portapapeles detectado "
                      f"({len(clipboard_apps)} apps)",
                description=(
                    "Se han encontrado aplicaciones que pueden leer "
                    "el portapapeles del sistema."
                ),
                risk_level="orange",
                technical_risk=(
                    "El portapapeles puede contener contraseñas, "
                    "tokens, datos bancarios y comunicaciones privadas "
                    "copiadas recientemente."
                ),
                legal_risk=(
                    "El acceso al portapapeles sin consentimiento "
                    "puede capturar datos especialmente sensibles. "
                    "Alto riesgo bajo RGPD art. 9 si incluye "
                    "datos de categoría especial."
                ),
                what_it_is=(
                    "Software con acceso al portapapeles del sistema, "
                    "que puede leer lo que el usuario copia."
                ),
                what_it_is_not=(
                    "Gestores de portapapeles como Ditto o ClipX son "
                    "herramientas legítimas de productividad."
                ),
                raw_data={"clipboard_apps": clipboard_apps}
            ))

    # ── Geolocalización ────────────────────────────────────────────

    def _check_location_access(self):
        from core.audit_engine import AuditFinding

        location_enabled = False
        apps_with_location = []

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                r"\CapabilityAccessManager\ConsentStore\location",
                0, winreg.KEY_READ
            )
            try:
                val, _ = winreg.QueryValueEx(key, "Value")
                location_enabled = (val == "Allow")
            except (FileNotFoundError, OSError):
                pass

            idx = 0
            while True:
                try:
                    app_name = winreg.EnumKey(key, idx)
                    app_key = winreg.OpenKey(key, app_name)
                    try:
                        val, _ = winreg.QueryValueEx(app_key, "Value")
                        if val == "Allow":
                            apps_with_location.append(app_name)
                    except (FileNotFoundError, OSError):
                        pass
                    winreg.CloseKey(app_key)
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        if location_enabled and apps_with_location:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="privacy_location",
                title=f"Geolocalización activa con "
                      f"{len(apps_with_location)} apps autorizadas",
                description=(
                    "El servicio de ubicación está habilitado y varias "
                    "aplicaciones tienen permiso para acceder a él."
                ),
                risk_level="orange",
                technical_risk=(
                    "Las apps con acceso a ubicación pueden registrar "
                    "la posición geográfica del dispositivo y del trabajador."
                ),
                legal_risk=(
                    "La geolocalización de trabajadores requiere base "
                    "legal específica y está expresamente regulada "
                    "en ET art. 20bis. Sin información previa "
                    "es especialmente problemática."
                ),
                what_it_is=(
                    "Servicio de ubicación de Windows activo con "
                    "permisos concedidos a aplicaciones."
                ),
                what_it_is_not=(
                    "Puede ser para funciones legítimas: mapas, "
                    "zona horaria, búsquedas locales."
                ),
                raw_data={
                    "location_enabled": location_enabled,
                    "apps": apps_with_location
                }
            ))

    # ── Input hooks ───────────────────────────────────────────────

    def _check_input_hooks(self):
        from core.audit_engine import AuditFinding

        hook_procs = [
            name for name in self.running_processes
            if any(k in name for k in INPUT_HOOK_KEYWORDS)
        ]

        if hook_procs:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="privacy_input_hooks",
                title=f"Procesos con posibles hooks de entrada "
                      f"({len(hook_procs)})",
                description=(
                    "Se han encontrado procesos activos con nombres "
                    "asociados a captura de entrada de teclado o ratón."
                ),
                risk_level="red",
                technical_risk=(
                    "Los hooks de input pueden interceptar "
                    "absolutamente todo lo que se escribe o hace "
                    "con el ratón, incluyendo contraseñas."
                ),
                legal_risk=(
                    "El keylogging sin consentimiento explícito es "
                    "prácticamente indefendible legalmente. "
                    "Vulnera LOPDGDD, ET art. 20bis y posiblemente "
                    "art. 197 Código Penal."
                ),
                what_it_is=(
                    "Software que intercepta las pulsaciones de teclado "
                    "a nivel de sistema operativo."
                ),
                what_it_is_not=(
                    "Algunos hooks legítimos: software de accesibilidad, "
                    "gestores de atajos de teclado globales."
                ),
                raw_data={"hook_processes": hook_procs}
            ))

    # ── Screenshot tools ──────────────────────────────────────────

    def _check_screenshot_tools(self):
        from core.audit_engine import AuditFinding

        screen_procs = []
        known_screenshot_tools = [
            "recordit", "snagit", "greenshot", "lightshot",
            "gyazo", "screenpresso", "sharex", "screenrec",
            "loom", "droplr", "monosnap"
        ]

        for name in self.running_processes:
            if any(k in name for k in known_screenshot_tools):
                screen_procs.append(name)
            elif any(k in name for k in SCREENSHOT_API_KEYWORDS):
                if not any(
                    leg in name for leg in
                    ["snipping", "snippet", "snip", "xbox", "gamebar"]
                ):
                    screen_procs.append(name)

        if screen_procs:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="privacy_screenshot",
                title=f"Herramientas de captura de pantalla activas "
                      f"({len(screen_procs)})",
                description=(
                    "Se han detectado herramientas de captura de "
                    "pantalla en ejecución."
                ),
                risk_level="orange",
                technical_risk=(
                    "Las herramientas de screenshot pueden capturar "
                    "periódicamente la pantalla, incluyendo "
                    "comunicaciones privadas y contraseñas visibles."
                ),
                legal_risk=(
                    "La captura de pantalla periódica y automática "
                    "es una de las formas de vigilancia más invasivas. "
                    "Requiere consentimiento explícito bajo LOPDGDD."
                ),
                what_it_is=(
                    "Software capaz de tomar capturas de pantalla "
                    "de forma programada o continua."
                ),
                what_it_is_not=(
                    "Herramientas de screenshot manuales como "
                    "Snipping Tool son de uso personal y legítimo."
                ),
                raw_data={"screenshot_tools": screen_procs}
            ))

    # ── Screen recording policy ────────────────────────────────────

    def _check_screen_recording_policy(self):
        from core.audit_engine import AuditFinding

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ItemProperty "
                 "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\"
                 "WindowsAI -ErrorAction SilentlyContinue | "
                 "Select-Object DisableAIDataAnalysis | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            # Recall (Windows AI) habilitado = captura continua de pantalla
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if data and data.get("DisableAIDataAnalysis") == 0:
                    self.engine.add_finding(AuditFinding(
                        skill=self.SKILL_NAME,
                        category="privacy_screen_recording",
                        title="Windows Recall activo — captura continua de pantalla",
                        description=(
                            "Windows Recall está habilitado y no desactivado "
                            "por política. Esta función captura la pantalla "
                            "continuamente."
                        ),
                        risk_level="red",
                        technical_risk=(
                            "Windows Recall captura snapshots continuos de la "
                            "pantalla y los indexa. En un entorno corporativo, "
                            "esto puede incluir comunicaciones privadas, "
                            "contraseñas y datos sensibles."
                        ),
                        legal_risk=(
                            "La captura continua de pantalla sin desactivar "
                            "en equipos de trabajo es extremadamente problemática "
                            "bajo LOPDGDD y RGPD. Riesgo muy alto."
                        ),
                        what_it_is=(
                            "Windows Recall es una función de Windows 11 que "
                            "captura y analiza la pantalla continuamente para "
                            "permitir búsquedas de actividad pasada."
                        ),
                        what_it_is_not=(
                            "No es específicamente una herramienta corporativa, "
                            "pero su activación en equipos de trabajo "
                            "tiene implicaciones legales graves."
                        ),
                        raw_data={"windows_recall": "enabled"}
                    ))
        except Exception:
            pass

        print("[Privacy] Completado")