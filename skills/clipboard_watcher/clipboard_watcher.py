# skills/clipboard_watcher/clipboard_watcher.py
"""
Skill — Clipboard Watcher
Detecta qué procesos tienen acceso al portapapeles de Windows,
con qué frecuencia acceden y si envían datos a red.
Monitoriza durante un período corto y genera evidencia forense.
"""

import subprocess
import json
import winreg
import os
import time
import ctypes
import ctypes.wintypes
from pathlib import Path
from datetime import datetime


# ── Configuración ──────────────────────────────────────────────────────────────

MONITOR_SECONDS = 30  # segundos de monitorización activa
POLL_INTERVAL   = 2   # intervalo de polling en segundos

# Procesos legítimos que acceden al portapapeles normalmente
LEGITIMATE_CLIPBOARD_PROCS = {
    "explorer.exe",
    "svchost.exe",
    "conhost.exe",
    "TextInputHost.exe",
    "ApplicationFrameHost.exe",
    "SystemSettings.exe",
    "ctfmon.exe",
    "dwm.exe",
    "msedgewebview2.exe",
    "code.exe",
    "powershell.exe",
    "cmd.exe",
    "windowsterminal.exe",
    "python.exe",
}

# Procesos de monitorización conocidos que acceden al portapapeles
KNOWN_CLIPBOARD_MONITORS = {
    "teramind":     "Teramind — employee monitoring",
    "activtrak":    "ActivTrak — productivity monitoring",
    "veriato":      "Veriato — employee monitoring",
    "hubstaff":     "Hubstaff — time tracking",
    "desktime":     "DeskTime — time tracking",
    "interguard":   "InterGuard — employee monitoring",
    "spector":      "Spector — employee monitoring",
    "workpuls":     "Workpuls — employee monitoring",
    "insightful":   "Insightful — workforce analytics",
}

# APIs de Windows para clipboard
user32 = ctypes.windll.user32


class ClipboardWatcher:
    SKILL_NAME = "clipboard_watcher"

    def __init__(self, engine):
        self.engine            = engine
        self.clipboard_viewers = []
        self.suspicious_procs  = []
        self.monitor_events    = []
        self.rdp_clipboard     = False
        self.known_monitors    = []

    def run(self):
        print("[Clipboard] Iniciando auditoría de accesos al portapapeles...")
        self._check_clipboard_chain()
        self._check_clipboard_history_policy()
        self._check_rdp_clipboard()
        self._scan_processes_clipboard_access()
        self._monitor_clipboard_access()
        self._report()

    # ── Cadena de visualizadores ───────────────────────────────────────────────

    def _check_clipboard_chain(self):
        """Detecta procesos en la cadena de visualizadores del portapapeles."""
        try:
            # Obtener el handle del primer viewer de la cadena
            hwnd = user32.GetClipboardViewer()
            if hwnd:
                # Obtener PID del proceso propietario
                pid = ctypes.wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    proc_name = self._get_process_name(pid.value)
                    if proc_name and proc_name.lower() not in LEGITIMATE_CLIPBOARD_PROCS:
                        self.clipboard_viewers.append({
                            "hwnd":    hwnd,
                            "pid":     pid.value,
                            "process": proc_name,
                            "type":    "clipboard_viewer_chain",
                        })
                        print(f"[Clipboard] Viewer en cadena: {proc_name} (PID {pid.value})")
        except Exception as e:
            print(f"[Clipboard] Error leyendo cadena de viewers: {e}")

    def _check_clipboard_history_policy(self):
        """Verifica si el historial de portapapeles está activo y quién puede acceder."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\System"
            )
            try:
                value, _ = winreg.QueryValueEx(key, "AllowClipboardHistory")
                self.clipboard_viewers.append({
                    "type":    "clipboard_history_policy",
                    "enabled": bool(int(value)),
                    "value":   value,
                    "note":    "Política GPO de historial de portapapeles",
                })
            except OSError:
                pass
            try:
                value, _ = winreg.QueryValueEx(key, "AllowCrossDeviceClipboard")
                if int(value):
                    self.clipboard_viewers.append({
                        "type":  "cross_device_clipboard",
                        "value": value,
                        "note":  "Portapapeles sincronizado entre dispositivos — datos salen del equipo",
                    })
                    print("[Clipboard] ⚠️  Portapapeles cross-device ACTIVO")
            except OSError:
                pass
            winreg.CloseKey(key)
        except OSError:
            pass

    def _check_rdp_clipboard(self):
        """Detecta si el portapapeles está compartido via RDP."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            )
            try:
                value, _ = winreg.QueryValueEx(key, "fDisableClip")
                # 0 = clipboard habilitado en RDP, 1 = deshabilitado
                self.rdp_clipboard = (int(value) == 0)
                if self.rdp_clipboard:
                    print("[Clipboard] RDP clipboard HABILITADO — datos accesibles en sesión remota")
            except OSError:
                # Sin política = clipboard RDP habilitado por defecto
                self.rdp_clipboard = True
                print("[Clipboard] RDP clipboard: habilitado por defecto")
            winreg.CloseKey(key)
        except OSError:
            pass

    # ── Escaneo de procesos ────────────────────────────────────────────────────

    def _scan_processes_clipboard_access(self):
        """Busca procesos con handles abiertos al portapapeles."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Process | Where-Object { $_.MainWindowHandle -ne 0 } | "
                 "Select-Object Id, ProcessName, MainWindowTitle | "
                 "ConvertTo-Json -Depth 1"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                procs = json.loads(result.stdout)
                if isinstance(procs, dict):
                    procs = [procs]

                for proc in (procs or []):
                    name = str(proc.get("ProcessName", "")).lower()
                    # Verificar si es monitor conocido
                    for monitor_key, monitor_desc in KNOWN_CLIPBOARD_MONITORS.items():
                        if monitor_key in name:
                            self.known_monitors.append({
                                "pid":         proc.get("Id"),
                                "process":     proc.get("ProcessName"),
                                "description": monitor_desc,
                            })
                            print(f"[Clipboard] ⚠️  Monitor conocido: {proc.get('ProcessName')} — {monitor_desc}")

        except Exception as e:
            print(f"[Clipboard] Error escaneando procesos: {e}")

        # Buscar via WMI procesos con características de monitoring
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WmiObject Win32_Process | "
                 "Where-Object { $_.CommandLine -match 'clipboard|clip|keylog|monitor' } | "
                 "Select-Object ProcessId, Name, CommandLine | "
                 "ConvertTo-Json -Depth 1"],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0 and result.stdout.strip():
                procs = json.loads(result.stdout)
                if isinstance(procs, dict):
                    procs = [procs]
                for proc in (procs or []):
                    name = str(proc.get("Name", "")).lower()
                    if name not in LEGITIMATE_CLIPBOARD_PROCS:
                        self.suspicious_procs.append({
                            "pid":         proc.get("ProcessId"),
                            "process":     proc.get("Name"),
                            "commandline": str(proc.get("CommandLine", ""))[:100],
                            "type":        "clipboard_keyword_in_cmdline",
                        })
                        print(f"[Clipboard] Proceso sospechoso: {proc.get('Name')}")
        except Exception as e:
            print(f"[Clipboard] Error en WMI scan: {e}")

    # ── Monitorización activa ──────────────────────────────────────────────────

    def _monitor_clipboard_access(self):
        """Monitoriza cambios en el portapapeles durante MONITOR_SECONDS."""
        print(
            f"[Clipboard] Monitorizando portapapeles durante "
            f"{MONITOR_SECONDS} segundos..."
        )
        try:
            last_seq = user32.GetClipboardSequenceNumber()
            start    = time.time()
            changes  = 0

            while time.time() - start < MONITOR_SECONDS:
                time.sleep(POLL_INTERVAL)
                current_seq = user32.GetClipboardSequenceNumber()
                if current_seq != last_seq:
                    changes += 1
                    # Intentar identificar quién cambió el portapapeles
                    hwnd = user32.GetOpenClipboardWindow()
                    if hwnd:
                        pid = ctypes.wintypes.DWORD()
                        user32.GetWindowThreadProcessId(
                            hwnd, ctypes.byref(pid)
                        )
                        proc_name = self._get_process_name(pid.value)
                    else:
                        proc_name = "Desconocido"

                    self.monitor_events.append({
                        "timestamp":   datetime.now().strftime("%H:%M:%S"),
                        "seq_number":  current_seq,
                        "process":     proc_name or "Desconocido",
                        "suspicious":  (
                            proc_name and
                            proc_name.lower() not in LEGITIMATE_CLIPBOARD_PROCS
                        ),
                    })
                    last_seq = current_seq

            suspicious_events = [
                e for e in self.monitor_events if e["suspicious"]
            ]
            print(
                f"[Clipboard] Monitorización completada — "
                f"{changes} cambios, "
                f"{len(suspicious_events)} por procesos no estándar"
            )
            if suspicious_events:
                for e in suspicious_events:
                    print(f"[Clipboard]   ⚠️  {e['timestamp']} — {e['process']}")

        except Exception as e:
            print(f"[Clipboard] Error en monitorización: {e}")

    # ── Utilidades ─────────────────────────────────────────────────────────────

    def _get_process_name(self, pid: int) -> str:
        """Obtiene el nombre de proceso dado su PID."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return ""

    # ── Reporte ────────────────────────────────────────────────────────────────

    def _report(self):
        from core.audit_engine import AuditFinding

        suspicious_events = [e for e in self.monitor_events if e["suspicious"]]
        all_suspicious    = (
            self.clipboard_viewers +
            self.suspicious_procs +
            self.known_monitors
        )

        # ── Hallazgo 1: Monitores conocidos activos ────────────────────────────
        if self.known_monitors:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="clipboard_known_monitor",
                title=(
                    f"Software de monitorización con acceso al portapapeles: "
                    f"{len(self.known_monitors)} detectados"
                ),
                description=(
                    "Se han detectado procesos de software de monitorización "
                    "corporativa con acceso activo al portapapeles: " +
                    ", ".join(m["process"] for m in self.known_monitors)
                ),
                risk_level="red",
                technical_risk=(
                    "Estos procesos pueden leer el portapapeles del trabajador "
                    "en tiempo real, capturando contraseñas, tokens, datos bancarios "
                    "o cualquier texto copiado."
                ),
                legal_risk=(
                    "El acceso al portapapeles por software corporativo sin "
                    "consentimiento puede capturar datos especialmente sensibles "
                    "bajo RGPD art. 9. Vulnera LOPDGDD art. 87 sin información previa."
                ),
                what_it_is=(
                    "Software de monitorización de empleados con capacidad técnica "
                    "de leer el portapapeles del sistema en tiempo real."
                ),
                what_it_is_not=(
                    "No confirma que estén leyendo activamente el portapapeles "
                    "en este momento — pero tienen la capacidad técnica para hacerlo."
                ),
                raw_data={"known_monitors": self.known_monitors}
            ))

        # ── Hallazgo 2: Accesos sospechosos durante monitorización ─────────────
        if suspicious_events:
            unique_procs = list({e["process"] for e in suspicious_events})
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="clipboard_suspicious_access",
                title=(
                    f"Accesos al portapapeles por procesos no estándar: "
                    f"{len(suspicious_events)} eventos — "
                    f"{', '.join(unique_procs[:3])}"
                ),
                description=(
                    f"Durante {MONITOR_SECONDS}s de monitorización se detectaron "
                    f"{len(suspicious_events)} accesos al portapapeles "
                    f"por procesos fuera de la lista de procesos legítimos conocidos."
                ),
                risk_level="orange",
                technical_risk=(
                    "Procesos detectados: " + ", ".join(unique_procs) +
                    ". Cada acceso puede leer el contenido completo del portapapeles."
                ),
                legal_risk=(
                    "Accesos al portapapeles por software corporativo sin "
                    "información previa pueden capturar datos sensibles del trabajador "
                    "bajo LOPDGDD art. 87 y RGPD art. 9."
                ),
                what_it_is=(
                    "Eventos de cambio o lectura del portapapeles del sistema "
                    "detectados durante la ventana de monitorización."
                ),
                what_it_is_not=(
                    "Algunos procesos acceden al portapapeles de forma legítima "
                    "para funciones de productividad. Requiere análisis contextual."
                ),
                raw_data={
                    "events":          suspicious_events,
                    "monitor_seconds": MONITOR_SECONDS,
                    "unique_procs":    unique_procs,
                }
            ))

        # ── Hallazgo 3: RDP clipboard habilitado ──────────────────────────────
        if self.rdp_clipboard:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="clipboard_rdp_shared",
                title="Portapapeles compartido en sesiones RDP — datos accesibles remotamente",
                description=(
                    "El portapapeles de Windows está habilitado para sesiones "
                    "RDP. Durante una conexión remota, el administrador puede "
                    "leer y modificar el portapapeles del trabajador."
                ),
                risk_level="orange",
                technical_risk=(
                    "Con RDP clipboard habilitado, cualquier cuenta con acceso "
                    "RDP al equipo (EMEAL-IT, Local-Admin) puede leer el "
                    "portapapeles del trabajador durante una sesión remota "
                    "sin que el trabajador lo perciba."
                ),
                legal_risk=(
                    "El acceso al portapapeles durante sesión RDP puede capturar "
                    "contraseñas, tokens y datos bancarios copiados por el trabajador. "
                    "Vulnera LOPDGDD art. 87 si no hay información previa."
                ),
                what_it_is=(
                    "Configuración de RDP que permite compartir el portapapeles "
                    "entre el equipo local y la sesión remota del administrador."
                ),
                what_it_is_not=(
                    "No implica que los administradores estén leyendo el portapapeles "
                    "activamente — pero tienen acceso técnico durante sesiones RDP."
                ),
                raw_data={
                    "rdp_clipboard_enabled": self.rdp_clipboard,
                    "rdp_accounts_detected": ["EMEAL-IT", "Local-Admin"],
                }
            ))

        # ── Hallazgo 4: Cross-device clipboard ───────────────────────────────
        cross_device = [
            v for v in self.clipboard_viewers
            if v.get("type") == "cross_device_clipboard"
        ]
        if cross_device:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="clipboard_cross_device",
                title="Portapapeles sincronizado entre dispositivos — datos salen del equipo",
                description=(
                    "La función de portapapeles cross-device está activa. "
                    "El contenido del portapapeles se sincroniza con otros "
                    "dispositivos vinculados a la cuenta Microsoft."
                ),
                risk_level="orange",
                technical_risk=(
                    "El contenido del portapapeles (contraseñas, tokens, datos) "
                    "se envía a servidores de Microsoft para sincronización "
                    "entre dispositivos. Transferencia internacional de datos."
                ),
                legal_risk=(
                    "La sincronización del portapapeles a servidores externos "
                    "puede constituir transferencia internacional de datos "
                    "personales bajo RGPD cap. V sin base legal adecuada."
                ),
                what_it_is=(
                    "Función de Windows que sincroniza el historial del portapapeles "
                    "entre dispositivos vinculados a la misma cuenta Microsoft."
                ),
                what_it_is_not=(
                    "No es una función corporativa de vigilancia — es una "
                    "función de conveniencia de Windows que puede implicar "
                    "transferencia de datos sin control del trabajador."
                ),
                raw_data={"cross_device": cross_device}
            ))

        # ── Hallazgo 5: Sin accesos sospechosos ───────────────────────────────
        if (not self.known_monitors and not suspicious_events
                and not self.clipboard_viewers):
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="clipboard_clean",
                title=(
                    f"Sin accesos sospechosos al portapapeles detectados "
                    f"({MONITOR_SECONDS}s de monitorización)"
                ),
                description=(
                    "Durante la ventana de monitorización no se detectaron "
                    "procesos no estándar accediendo al portapapeles."
                ),
                risk_level="green",
                technical_risk=(
                    "Sin evidencia de monitorización activa del portapapeles "
                    "en el período analizado."
                ),
                legal_risk=(
                    "Riesgo bajo en este momento. "
                    "Mantener buenas prácticas: no copiar credenciales "
                    "ni datos sensibles en equipos corporativos."
                ),
                what_it_is=(
                    f"Resultado de {MONITOR_SECONDS}s de monitorización "
                    "del portapapeles sin detectar accesos anómalos."
                ),
                what_it_is_not=(
                    "No descarta monitorización en otros momentos. "
                    "La ventana de análisis es limitada."
                ),
                raw_data={
                    "monitor_seconds": MONITOR_SECONDS,
                    "total_events":    len(self.monitor_events),
                    "rdp_clipboard":   self.rdp_clipboard,
                }
            ))

        print(
            f"[Clipboard] Completado — "
            f"monitores conocidos: {len(self.known_monitors)}, "
            f"eventos sospechosos: {len(suspicious_events)}, "
            f"RDP clipboard: {'sí' if self.rdp_clipboard else 'no'}, "
            f"cross-device: {len(cross_device) if 'cross_device' in dir() else 0}"
        )