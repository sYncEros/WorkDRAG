# skills/event_log_monitor/event_log_monitor.py
"""
Skill — Event Log Monitor
Detecta Windows Event Forwarding (WEF) y PowerShell Transcription/Logging:
destinos de envío, transcripts locales, período de retención y
si el trabajador puede desactivarlos o están bloqueados por GPO.
"""

import subprocess
import json
import winreg
import os
from pathlib import Path
from datetime import datetime


# ── Configuración ──────────────────────────────────────────────────────────────

# Claves de registro WEF
WEF_REGISTRY_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-ForwardedEvents"),
]

# Claves de registro PowerShell Logging
PS_LOGGING_KEYS = {
    "ScriptBlockLogging": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging"
    ),
    "ModuleLogging": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "EnableModuleLogging"
    ),
    "Transcription": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
        "EnableTranscripting"
    ),
    "TranscriptionPath": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
        "OutputDirectory"
    ),
    "TranscriptionInvocation": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
        "EnableInvocationHeader"
    ),
}

# También verificar en HKCU (configuración de usuario)
PS_LOGGING_KEYS_USER = {
    "ScriptBlockLogging_User": (
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging"
    ),
    "Transcription_User": (
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
        "EnableTranscripting"
    ),
}


class EventLogMonitor:
    SKILL_NAME = "event_log_monitor"

    def __init__(self, engine):
        self.engine               = engine
        self.wef_active           = False
        self.wef_servers          = []
        self.wef_subscription_mgr = []
        self.ps_transcription     = False
        self.ps_transcript_path   = ""
        self.ps_scriptblock       = False
        self.ps_module_logging    = False
        self.transcript_files     = []
        self.forwarded_log_size   = 0
        self.gpo_source           = {}

    def run(self):
        print("[EventLog] Iniciando detección de WEF y PS Logging...")
        self._check_wef()
        self._check_forwarded_events_log()
        self._check_ps_logging()
        self._find_transcript_files()
        self._report()

    # ── Windows Event Forwarding ───────────────────────────────────────────────

    def _check_wef(self):
        """Detecta si WEF está activo y a qué servidores envía logs."""

        # Método 1: Registro de SubscriptionManager
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
            )
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    self.wef_subscription_mgr.append({
                        "name":  name,
                        "value": str(value),
                    })
                    self.wef_active = True
                    # Extraer URL del servidor
                    if "Server=" in str(value) or "http" in str(value).lower():
                        self.wef_servers.append(str(value))
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except OSError:
            pass

        # Método 2: WecUtil para listar suscripciones activas
        try:
            result = subprocess.run(
                ["wecutil", "es"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                subscriptions = [
                    s.strip() for s in result.stdout.strip().split("\n")
                    if s.strip()
                ]
                if subscriptions:
                    self.wef_active = True
                    print(
                        f"[EventLog] WEF suscripciones activas: "
                        f"{len(subscriptions)} — {subscriptions}"
                    )
                    # Obtener detalle de cada suscripción
                    for sub in subscriptions[:3]:
                        try:
                            detail = subprocess.run(
                                ["wecutil", "gs", sub],
                                capture_output=True, text=True, timeout=10
                            )
                            if detail.returncode == 0:
                                for line in detail.stdout.split("\n"):
                                    if "address" in line.lower() or "server" in line.lower():
                                        self.wef_servers.append(line.strip())
                        except Exception:
                            pass
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[EventLog] Error comprobando WEF: {e}")

        # Método 3: Verificar servicio Windows Event Collector
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Service Wecsvc -ErrorAction SilentlyContinue | "
                 "Select-Object Status, StartType | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                svc = json.loads(result.stdout)
                status = str(svc.get("Status", ""))
                if status in ("4", "Running"):
                    self.wef_active = True
                    print(f"[EventLog] Servicio Wecsvc: ACTIVO")
        except Exception:
            pass

        if not self.wef_active:
            print("[EventLog] WEF: no detectado")
        else:
            print(
                f"[EventLog] WEF: ACTIVO — "
                f"servidores: {self.wef_servers or 'no identificados'}"
            )

    def _check_forwarded_events_log(self):
        """Comprueba el tamaño del log ForwardedEvents."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WinEvent -ListLog 'ForwardedEvents' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object LogName, RecordCount, FileSize, "
                 "LastWriteTime | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                record_count = data.get("RecordCount", 0) or 0
                file_size    = data.get("FileSize", 0) or 0
                self.forwarded_log_size = file_size
                if record_count and int(record_count) > 0:
                    self.wef_active = True
                    print(
                        f"[EventLog] ForwardedEvents: "
                        f"{record_count} registros, "
                        f"{self._human_size(int(file_size))}"
                    )
        except Exception:
            pass

    # ── PowerShell Logging ─────────────────────────────────────────────────────

    def _check_ps_logging(self):
        """Detecta PowerShell Transcription, ScriptBlock y Module Logging."""
        all_keys = {**PS_LOGGING_KEYS, **PS_LOGGING_KEYS_USER}

        for setting_name, (hive, key_path, value_name) in all_keys.items():
            try:
                key   = winreg.OpenKey(hive, key_path)
                value, _ = winreg.QueryValueEx(key, value_name)
                winreg.CloseKey(key)

                enabled = bool(int(value)) if str(value).isdigit() else bool(value)
                hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                self.gpo_source[setting_name] = {
                    "enabled": enabled,
                    "value":   value,
                    "source":  f"{hive_name}\\{key_path}",
                }

                if "ScriptBlock" in setting_name and enabled:
                    self.ps_scriptblock = True
                elif "ModuleLogging" in setting_name and enabled:
                    self.ps_module_logging = True
                elif "Transcription" in setting_name and "Path" not in setting_name \
                        and "Invocation" not in setting_name and enabled:
                    self.ps_transcription = True
                elif "TranscriptionPath" in setting_name and value:
                    self.ps_transcript_path = str(value)

            except OSError:
                pass

        # Si no hay política, verificar si está habilitado en profile
        if not self.ps_transcription:
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "if (Get-PSReadLineOption -ErrorAction SilentlyContinue) "
                     "{ (Get-PSReadLineOption).HistorySavePath } else { '' }"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    history_path = result.stdout.strip()
                    if history_path and Path(history_path).exists():
                        self.gpo_source["PSReadLine_History"] = {
                            "path": history_path,
                            "note": "Historial de comandos PSReadLine (local, no GPO)"
                        }
            except Exception:
                pass

        active = []
        if self.ps_transcription:
            active.append("Transcription")
        if self.ps_scriptblock:
            active.append("ScriptBlockLogging")
        if self.ps_module_logging:
            active.append("ModuleLogging")

        if active:
            print(f"[EventLog] PS Logging activo: {', '.join(active)}")
            if self.ps_transcript_path:
                print(f"[EventLog] Transcripts en: {self.ps_transcript_path}")
        else:
            print("[EventLog] PS Logging/Transcription: no detectado por GPO")

    def _find_transcript_files(self):
        """Busca archivos de transcript de PowerShell en rutas conocidas."""
        transcript_paths = [
            Path(self.ps_transcript_path) if self.ps_transcript_path else None,
            Path(os.environ.get("USERPROFILE", "")) / "Documents",
            Path("C:/") / "Transcripts",
            Path("C:/") / "ProgramData" / "Transcripts",
        ]

        for base_path in transcript_paths:
            if not base_path or not base_path.exists():
                continue
            try:
                for f in base_path.rglob("PowerShell_transcript*.txt"):
                    try:
                        stat = f.stat()
                        self.transcript_files.append({
                            "path":     str(f),
                            "name":     f.name,
                            "size":     self._human_size(stat.st_size),
                            "modified": datetime.fromtimestamp(
                                stat.st_mtime
                            ).strftime("%Y-%m-%d %H:%M"),
                        })
                    except OSError:
                        pass
                    if len(self.transcript_files) >= 20:
                        break
            except (PermissionError, OSError):
                pass

        if self.transcript_files:
            print(
                f"[EventLog] Transcripts encontrados: "
                f"{len(self.transcript_files)}"
            )

    # ── Utilidades ─────────────────────────────────────────────────────────────

    def _human_size(self, size_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    # ── Reporte ────────────────────────────────────────────────────────────────

    def _report(self):
        from core.audit_engine import AuditFinding

        # ── Hallazgo 1: WEF activo ─────────────────────────────────────────────
        if self.wef_active:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="wef_active",
                title=(
                    "Windows Event Forwarding activo — logs enviados a servidor remoto"
                    + (f": {self.wef_servers[0][:60]}"
                       if self.wef_servers else "")
                ),
                description=(
                    "WEF está configurado para reenviar logs de eventos de Windows "
                    "a un servidor centralizado corporativo. "
                    + (f"Servidores destino detectados: {', '.join(self.wef_servers[:3])}."
                       if self.wef_servers else
                       "Servidor destino no identificado (requiere elevación).")
                ),
                risk_level="red",
                technical_risk=(
                    "WEF puede reenviar Security, System, PowerShell y Application logs. "
                    "Incluye eventos de inicio de sesión, comandos ejecutados, "
                    "accesos a archivos y toda la actividad técnica del trabajador. "
                    + (f"Log ForwardedEvents: {self._human_size(self.forwarded_log_size)}."
                       if self.forwarded_log_size else "")
                ),
                legal_risk=(
                    "El reenvío centralizado de logs de actividad constituye "
                    "tratamiento de datos personales del trabajador. "
                    "Requiere información previa bajo LOPDGDD art. 87 y RGPD art. 13. "
                    "Si los logs se usan para evaluar el desempeño, "
                    "requiere DPIA bajo RGPD art. 35."
                ),
                what_it_is=(
                    "Windows Event Forwarding es una función que replica logs "
                    "del equipo del trabajador a un servidor centralizado "
                    "de la empresa en tiempo real."
                ),
                what_it_is_not=(
                    "No es grabación de pantalla ni keylogging. "
                    "Pero permite reconstruir toda la actividad técnica "
                    "del trabajador desde los logs del sistema."
                ),
                raw_data={
                    "wef_active":          self.wef_active,
                    "wef_servers":         self.wef_servers,
                    "subscription_mgr":    self.wef_subscription_mgr,
                    "forwarded_log_bytes": self.forwarded_log_size,
                }
            ))

        # ── Hallazgo 2: PS Transcription activa ───────────────────────────────
        if self.ps_transcription:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="ps_transcription_active",
                title=(
                    "PowerShell Transcription activa — todos los comandos grabados"
                    + (f" en {self.ps_transcript_path}" if self.ps_transcript_path else "")
                ),
                description=(
                    "La transcripción de PowerShell está habilitada por política GPO. "
                    "Todos los comandos ejecutados en PowerShell quedan grabados "
                    "en archivos de texto."
                    + (f" Ruta de transcripts: {self.ps_transcript_path}"
                       if self.ps_transcript_path else "")
                ),
                risk_level="red",
                technical_risk=(
                    "Los transcripts incluyen: comandos ejecutados, parámetros, "
                    "salidas, credenciales pasadas como texto plano, rutas de archivos "
                    "y toda la actividad de terminal del trabajador."
                    + (f" Transcripts encontrados: {len(self.transcript_files)}."
                       if self.transcript_files else "")
                ),
                legal_risk=(
                    "La grabación completa de la actividad de terminal constituye "
                    "monitorización intensiva del trabajador. "
                    "Requiere información previa expresa bajo LOPDGDD art. 87. "
                    "Si los transcripts se usan para evaluación, requiere DPIA."
                ),
                what_it_is=(
                    "PowerShell Transcription graba en un archivo de texto "
                    "todos los comandos que el trabajador ejecuta en PowerShell, "
                    "incluyendo entradas y salidas completas."
                ),
                what_it_is_not=(
                    "No graba la actividad fuera de PowerShell. "
                    "Pero en entornos de desarrollo cubre prácticamente "
                    "toda la actividad técnica del trabajador."
                ),
                raw_data={
                    "transcript_path":  self.ps_transcript_path,
                    "transcript_files": self.transcript_files[:10],
                    "gpo_source":       self.gpo_source,
                }
            ))

        # ── Hallazgo 3: ScriptBlock Logging ───────────────────────────────────
        if self.ps_scriptblock:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="ps_scriptblock_logging",
                title="PowerShell ScriptBlock Logging activo — código registrado en Event Viewer",
                description=(
                    "ScriptBlock Logging está habilitado. Cada bloque de código "
                    "PowerShell ejecutado queda registrado en el Event Viewer "
                    "(canal Microsoft-Windows-PowerShell/Operational, Event ID 4104)."
                ),
                risk_level="orange",
                technical_risk=(
                    "ScriptBlock Logging registra el código fuente completo "
                    "de cada script ejecutado. En combinación con WEF, "
                    "estos logs se envían al servidor centralizado corporativo."
                ),
                legal_risk=(
                    "El registro del código ejecutado por el trabajador "
                    "puede constituir perfilado de actividad técnica. "
                    "Requiere información previa bajo LOPDGDD art. 87."
                ),
                what_it_is=(
                    "ScriptBlock Logging registra el código PowerShell completo "
                    "en el Event Viewer, incluyendo scripts desofuscados."
                ),
                what_it_is_not=(
                    "Es una medida de seguridad estándar en entornos corporativos "
                    "para detectar uso malicioso de PowerShell. "
                    "El problema es si no se informó al trabajador."
                ),
                raw_data={"gpo_source": self.gpo_source}
            ))

        # ── Hallazgo 4: Transcripts encontrados ───────────────────────────────
        if self.transcript_files:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="ps_transcripts_found",
                title=(
                    f"Archivos de transcript de PowerShell encontrados: "
                    f"{len(self.transcript_files)}"
                ),
                description=(
                    "Se han encontrado archivos de transcript de PowerShell "
                    "en el sistema. Contienen el historial completo de "
                    "comandos ejecutados con sus salidas."
                ),
                risk_level="orange",
                technical_risk=(
                    "Primeros transcripts: " +
                    ", ".join(
                        f["name"] for f in self.transcript_files[:3]
                    )
                ),
                legal_risk=(
                    "Los transcripts son evidencia forense de la actividad "
                    "técnica del trabajador. Su existencia confirma que "
                    "la monitorización ha estado activa."
                ),
                what_it_is=(
                    "Archivos de texto generados por PS Transcription "
                    "con el registro completo de sesiones de PowerShell."
                ),
                what_it_is_not=(
                    "No implica que alguien los haya leído. "
                    "Pero están disponibles para el empleador."
                ),
                raw_data={"transcript_files": self.transcript_files}
            ))

        # ── Hallazgo 5: Sin WEF ni PS Logging detectado ────────────────────────
        if (not self.wef_active and not self.ps_transcription
                and not self.ps_scriptblock):
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="wef_ps_not_detected",
                title="WEF y PowerShell Logging no detectados",
                description=(
                    "No se ha detectado Windows Event Forwarding ni "
                    "PowerShell Transcription/ScriptBlock Logging activos "
                    "por política GPO en este equipo."
                ),
                risk_level="green",
                technical_risk=(
                    "Sin WEF activo los logs del equipo permanecen locales. "
                    "Sin PS Transcription los comandos no se graban en archivo. "
                    "Nota: la ausencia de detección no garantiza ausencia total "
                    "— puede requerir elevación para confirmación completa."
                ),
                legal_risk=(
                    "Sin estas capacidades activas el riesgo de monitorización "
                    "centralizada de la actividad técnica es bajo."
                ),
                what_it_is=(
                    "Resultado de la comprobación de políticas GPO de "
                    "Windows Event Forwarding y PowerShell Logging."
                ),
                what_it_is_not=(
                    "No descarta que estas capacidades estén activas "
                    "a nivel de servidor o red corporativa."
                ),
                raw_data={
                    "wef_checked":        True,
                    "ps_logging_checked": True,
                    "gpo_source":         self.gpo_source,
                }
            ))

        print(
            f"[EventLog] Completado — "
            f"WEF: {'activo' if self.wef_active else 'no detectado'}, "
            f"PS Transcription: {'activa' if self.ps_transcription else 'no'}, "
            f"ScriptBlock: {'activo' if self.ps_scriptblock else 'no'}, "
            f"Transcripts: {len(self.transcript_files)}"
        )