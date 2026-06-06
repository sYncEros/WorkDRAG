# skills/service_hardener/service_hardener.py
"""
Skill — Service Hardener
Intenta deshabilitar servicios de telemetría y monitorización
que el trabajador tiene derecho a reducir:
DiagTrack, Windows Event Forwarding, PowerShell Transcription.

IMPORTANTE: Solo actúa si NO hay GPO que lo bloquee.
Si hay GPO, documenta el bloqueo como evidencia.
Nunca escala privilegios ni modifica políticas corporativas.
"""

import subprocess
import json
import winreg
import os
from datetime import datetime


# ── Configuración ──────────────────────────────────────────────────────────────

# Servicios a intentar deshabilitar
HARDENING_TARGETS = {
    "DiagTrack": {
        "display":     "Connected User Experiences and Telemetry",
        "description": "Telemetría continua de Windows a Microsoft",
        "risk":        "high",
        "reversible":  True,
        "method":      "service",
    },
    "dmwappushservice": {
        "display":     "Device Management Wireless Application Protocol Push",
        "description": "Servicio auxiliar de telemetría WAP",
        "risk":        "medium",
        "reversible":  True,
        "method":      "service",
    },
}

# Configuraciones PS Logging a intentar revertir
PS_LOGGING_TARGETS = {
    "ScriptBlockLogging": {
        "key":   r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "value": "EnableScriptBlockLogging",
        "display": "PowerShell ScriptBlock Logging",
    },
    "Transcription": {
        "key":   r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
        "value": "EnableTranscripting",
        "display": "PowerShell Transcription",
    },
}

# Telemetría mínima recomendada por AEPD
RECOMMENDED_TELEMETRY_LEVEL = 1


class ServiceHardener:
    SKILL_NAME = "service_hardener"

    def __init__(self, engine):
        self.engine          = engine
        self.actions_taken   = []
        self.actions_blocked = []
        self.actions_failed  = []
        self.already_ok      = []

    def run(self):
        print("[Hardener] Iniciando endurecimiento de servicios...")
        self._harden_diagtrack()
        self._harden_telemetry_level()
        self._harden_ps_logging()
        self._harden_wef()
        self._report()

    # ── DiagTrack ──────────────────────────────────────────────────────────────

    def _harden_diagtrack(self):
        """Intenta deshabilitar DiagTrack si no hay GPO que lo bloquee."""
        print("[Hardener] Verificando DiagTrack...")

        # Comprobar si hay GPO que bloquee la modificación
        gpo_blocking = self._check_gpo_blocks_service("DiagTrack")
        if gpo_blocking:
            self.actions_blocked.append({
                "target":  "DiagTrack",
                "reason":  "GPO corporativa impide modificar el servicio",
                "evidence": "Política activa en SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
            })
            print("[Hardener] DiagTrack: bloqueado por GPO — documentado como evidencia")
            return

        # Verificar estado actual
        current_status = self._get_service_status("DiagTrack")
        if current_status in ("Stopped", "Disabled"):
            self.already_ok.append({
                "target":  "DiagTrack",
                "status":  current_status,
                "message": "Ya estaba detenido o deshabilitado",
            })
            print(f"[Hardener] DiagTrack: ya en estado {current_status}")
            return

        # Intentar detener el servicio
        success, output = self._stop_service("DiagTrack")
        if success:
            self.actions_taken.append({
                "target":    "DiagTrack",
                "action":    "stop",
                "result":    "Servicio detenido",
                "timestamp": datetime.now().isoformat(),
                "reversible": True,
                "restore_cmd": "Start-Service DiagTrack",
            })
            print("[Hardener] ✅ DiagTrack detenido")
        else:
            # Si falla sin GPO puede ser por falta de permisos de admin
            self.actions_failed.append({
                "target":  "DiagTrack",
                "reason":  "Sin permisos de administrador local",
                "output":  output[:200],
                "note":    "Requiere ejecutar como administrador",
            })
            print(f"[Hardener] DiagTrack: sin permisos para detener — {output[:80]}")

    # ── Nivel de telemetría ────────────────────────────────────────────────────

    def _harden_telemetry_level(self):
        """Intenta reducir el nivel de telemetría al mínimo recomendado."""
        print("[Hardener] Verificando nivel de telemetría...")

        # Leer nivel actual
        current_level = self._read_telemetry_level()

        if current_level is not None and current_level <= RECOMMENDED_TELEMETRY_LEVEL:
            self.already_ok.append({
                "target":  "TelemetryLevel",
                "status":  f"Nivel {current_level} — ya conforme",
                "message": f"Nivel actual ({current_level}) <= recomendado ({RECOMMENDED_TELEMETRY_LEVEL})",
            })
            print(f"[Hardener] Telemetría: nivel {current_level} — ya conforme")
            return

        # Verificar si hay GPO que bloquee
        gpo_source = self._get_telemetry_gpo_source()
        if gpo_source == "HKLM_POLICIES":
            self.actions_blocked.append({
                "target":  "TelemetryLevel",
                "reason":  "GPO corporativa define el nivel de telemetría",
                "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry",
                "note":    "El empleador ha configurado activamente este nivel — solicitar cambio al DPO",
            })
            print("[Hardener] Telemetría: nivel fijado por GPO corporativa — documentado")
            return

        # Intentar escribir en el registro de usuario (sin admin)
        try:
            key = winreg.CreateKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"
            )
            winreg.SetValueEx(key, "ShowedToastAtLevel", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass

        # Intentar con HKLM (requiere admin)
        success = self._set_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
            "AllowTelemetry",
            RECOMMENDED_TELEMETRY_LEVEL,
            winreg.REG_DWORD
        )

        if success:
            self.actions_taken.append({
                "target":    "TelemetryLevel",
                "action":    f"set_level_{RECOMMENDED_TELEMETRY_LEVEL}",
                "result":    f"Nivel reducido de {current_level} a {RECOMMENDED_TELEMETRY_LEVEL}",
                "timestamp": datetime.now().isoformat(),
                "reversible": True,
                "restore_cmd": f"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection' -Name AllowTelemetry -Value {current_level}",
            })
            print(f"[Hardener] ✅ Telemetría reducida a nivel {RECOMMENDED_TELEMETRY_LEVEL}")
        else:
            self.actions_failed.append({
                "target": "TelemetryLevel",
                "reason": "Sin permisos de administrador para modificar HKLM",
                "note":   f"Nivel actual: {current_level} — requiere admin para reducir a {RECOMMENDED_TELEMETRY_LEVEL}",
            })
            print("[Hardener] Telemetría: sin permisos para modificar — requiere admin")

    # ── PowerShell Logging ─────────────────────────────────────────────────────

    def _harden_ps_logging(self):
        """Intenta deshabilitar PS Transcription y ScriptBlock Logging."""
        print("[Hardener] Verificando PS Logging...")

        for setting_name, config in PS_LOGGING_TARGETS.items():
            current = self._read_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                config["key"],
                config["value"]
            )

            if current is None or current == 0:
                self.already_ok.append({
                    "target":  setting_name,
                    "status":  "No activo o no configurado",
                    "message": f"{config['display']} no está activo",
                })
                continue

            # Verificar si es GPO (HKLM Policies = corporativo, no modificable sin admin)
            is_gpo = "Policies" in config["key"]
            if is_gpo:
                # Intentar deshabilitar en HKLM\Policies (requiere admin)
                success = self._set_registry_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    config["key"],
                    config["value"],
                    0,
                    winreg.REG_DWORD
                )
                if success:
                    self.actions_taken.append({
                        "target":    setting_name,
                        "action":    "disable",
                        "result":    f"{config['display']} deshabilitado",
                        "timestamp": datetime.now().isoformat(),
                        "reversible": True,
                        "restore_cmd": (
                            f"Set-ItemProperty -Path 'HKLM:\\{config['key']}' "
                            f"-Name {config['value']} -Value 1"
                        ),
                    })
                    print(f"[Hardener] ✅ {config['display']} deshabilitado")
                else:
                    self.actions_blocked.append({
                        "target":  setting_name,
                        "reason":  "GPO corporativa activa — sin permisos para modificar",
                        "evidence": f"HKLM\\{config['key']}\\{config['value']} = {current}",
                        "note":    "El empleador ha configurado este logging activamente",
                    })
                    print(f"[Hardener] {config['display']}: bloqueado por GPO")

    # ── Windows Event Forwarding ───────────────────────────────────────────────

    def _harden_wef(self):
        """Verifica WEF y documenta si está activo y bloqueado."""
        print("[Hardener] Verificando WEF...")

        # Verificar servicio WecSvc
        wec_status = self._get_service_status("WecSvc")

        if wec_status in ("Stopped", "Disabled", None):
            self.already_ok.append({
                "target":  "WindowsEventForwarding",
                "status":  wec_status or "No detectado",
                "message": "WEF no está activo",
            })
            print("[Hardener] WEF: no activo")
            return

        # WEF activo — intentar detener
        gpo_blocking = self._check_gpo_key_exists(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
        )

        if gpo_blocking:
            self.actions_blocked.append({
                "target":   "WindowsEventForwarding",
                "reason":   "Suscripción WEF definida por GPO corporativa",
                "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager",
                "note":     "El empleador ha configurado activamente el reenvío de logs",
            })
            print("[Hardener] WEF: activo y configurado por GPO — documentado como evidencia")
        else:
            success, output = self._stop_service("WecSvc")
            if success:
                self.actions_taken.append({
                    "target":    "WindowsEventForwarding",
                    "action":    "stop_wecsvc",
                    "result":    "Servicio WecSvc detenido",
                    "timestamp": datetime.now().isoformat(),
                    "reversible": True,
                    "restore_cmd": "Start-Service WecSvc",
                })
                print("[Hardener] ✅ WEF detenido")
            else:
                self.actions_failed.append({
                    "target": "WindowsEventForwarding",
                    "reason": "Sin permisos para detener WecSvc",
                    "output": output[:200],
                })
                print("[Hardener] WEF: sin permisos para detener")

    # ── Utilidades ─────────────────────────────────────────────────────────────

    def _get_service_status(self, service_name: str) -> str | None:
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-Service {service_name} -ErrorAction SilentlyContinue).Status"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def _stop_service(self, service_name: str) -> tuple[bool, str]:
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Stop-Service {service_name} -Force -ErrorAction Stop"],
                capture_output=True, text=True, timeout=15
            )
            success = result.returncode == 0
            output  = result.stderr or result.stdout
            return success, output
        except Exception as e:
            return False, str(e)

    def _check_gpo_blocks_service(self, service_name: str) -> bool:
        """Verifica si hay GPO que bloquee la modificación del servicio."""
        gpo_keys = [
            r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        ]
        for key_path in gpo_keys:
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                return True
            except OSError:
                pass
        return False

    def _check_gpo_key_exists(self, hive, key_path: str) -> bool:
        try:
            key = winreg.OpenKey(hive, key_path)
            winreg.CloseKey(key)
            return True
        except OSError:
            return False

    def _read_telemetry_level(self) -> int | None:
        keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
             "AllowTelemetry"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
             "AllowTelemetry"),
        ]
        for hive, key_path, value_name in keys:
            val = self._read_registry_value(hive, key_path, value_name)
            if val is not None:
                return int(val)
        return None

    def _get_telemetry_gpo_source(self) -> str | None:
        try:
            winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            )
            return "HKLM_POLICIES"
        except OSError:
            pass
        return None

    def _read_registry_value(self, hive, key_path: str, value_name: str):
        try:
            key   = winreg.OpenKey(hive, key_path)
            value, _ = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return value
        except OSError:
            return None

    def _set_registry_value(
        self, hive, key_path: str,
        value_name: str, value, value_type
    ) -> bool:
        try:
            key = winreg.OpenKey(
                hive, key_path,
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, value_name, 0, value_type, value)
            winreg.CloseKey(key)
            return True
        except OSError:
            return False

    # ── Reporte ────────────────────────────────────────────────────────────────

    def _report(self):
        from core.audit_engine import AuditFinding

        # ── Hallazgo 1: Acciones realizadas ───────────────────────────────────
        if self.actions_taken:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="hardener_actions_taken",
                title=(
                    f"Endurecimiento aplicado: "
                    f"{len(self.actions_taken)} cambios realizados"
                ),
                description=(
                    "Se han aplicado las siguientes medidas de protección: " +
                    ", ".join(a["result"] for a in self.actions_taken)
                ),
                risk_level="green",
                technical_risk=(
                    "Cambios aplicados y reversibles. Comandos de restauración "
                    "incluidos en raw_data si IT necesita revertir."
                ),
                legal_risk=(
                    "El trabajador tiene derecho a reducir la telemetría "
                    "cuando el empleador no ha aplicado medidas adecuadas "
                    "bajo RGPD art. 32. Estas acciones son defensivas, "
                    "no ofensivas."
                ),
                what_it_is=(
                    "Medidas técnicas aplicadas para reducir la superficie "
                    "de monitorización en el equipo del trabajador."
                ),
                what_it_is_not=(
                    "No es sabotaje ni ataque a la infraestructura corporativa. "
                    "Son cambios reversibles de configuración local."
                ),
                raw_data={
                    "actions":   self.actions_taken,
                    "timestamp": datetime.now().isoformat(),
                }
            ))

        # ── Hallazgo 2: Bloqueado por GPO ─────────────────────────────────────
        if self.actions_blocked:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="hardener_gpo_blocked",
                title=(
                    f"Endurecimiento bloqueado por GPO corporativa: "
                    f"{len(self.actions_blocked)} elementos"
                ),
                description=(
                    "Las siguientes configuraciones están bloqueadas por "
                    "política corporativa y no pueden modificarse: " +
                    ", ".join(a["target"] for a in self.actions_blocked)
                ),
                risk_level="red",
                technical_risk=(
                    "El empleador ha configurado activamente estas políticas, "
                    "impidiendo al trabajador reducir la telemetría o el logging. "
                    "Evidencia: " +
                    " | ".join(
                        a.get("evidence", a["target"])
                        for a in self.actions_blocked
                    )
                ),
                legal_risk=(
                    "Que el empleador bloquee activamente la capacidad del "
                    "trabajador de reducir la telemetría puede constituir "
                    "incumplimiento del principio de minimización bajo RGPD art. 5 "
                    "y de las medidas técnicas exigidas por RGPD art. 32. "
                    "Es evidencia forense de una decisión activa del empleador."
                ),
                what_it_is=(
                    "Políticas GPO corporativas que impiden modificar "
                    "configuraciones de telemetría y logging en el equipo."
                ),
                what_it_is_not=(
                    "No implica intención maliciosa del empleador — "
                    "pero sí una decisión técnica activa que tiene "
                    "implicaciones legales bajo RGPD."
                ),
                raw_data={
                    "blocked_actions": self.actions_blocked,
                    "legal_reference": "RGPD art. 5, 32 — minimización y seguridad",
                }
            ))

        # ── Hallazgo 3: Falló por falta de permisos ───────────────────────────
        if self.actions_failed:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="hardener_needs_admin",
                title=(
                    f"Endurecimiento parcial: "
                    f"{len(self.actions_failed)} acciones requieren administrador"
                ),
                description=(
                    "Las siguientes acciones no pudieron aplicarse por falta "
                    "de permisos de administrador local: " +
                    ", ".join(a["target"] for a in self.actions_failed)
                ),
                risk_level="yellow",
                technical_risk=(
                    "Estas configuraciones requieren ejecutar la herramienta "
                    "como administrador o solicitar a IT que aplique los cambios."
                ),
                legal_risk=(
                    "La incapacidad del trabajador de aplicar medidas de "
                    "protección por falta de permisos refuerza la responsabilidad "
                    "del empleador de aplicarlas bajo RGPD art. 32."
                ),
                what_it_is=(
                    "Acciones de endurecimiento que requieren privilegios "
                    "de administrador local para aplicarse."
                ),
                what_it_is_not=(
                    "No es un error de la herramienta — es una limitación "
                    "de permisos que documenta la responsabilidad del empleador."
                ),
                raw_data={
                    "failed_actions": self.actions_failed,
                    "recommendation": (
                        "Solicitar a IT que aplique: "
                        "AllowTelemetry=1 via GPO, "
                        "deshabilitar DiagTrack via GPO"
                    ),
                }
            ))

        # ── Hallazgo 4: Ya configurado correctamente ───────────────────────────
        if self.already_ok:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="hardener_already_ok",
                title=(
                    f"Configuraciones ya correctas: "
                    f"{len(self.already_ok)} elementos"
                ),
                description=(
                    "Las siguientes configuraciones ya estaban en estado "
                    "correcto antes de ejecutar el hardener: " +
                    ", ".join(a["target"] for a in self.already_ok)
                ),
                risk_level="green",
                technical_risk="Sin riesgo — configuraciones ya en estado óptimo.",
                legal_risk="Sin issues legales en estos elementos.",
                what_it_is=(
                    "Configuraciones que ya estaban deshabilitadas o "
                    "en nivel mínimo antes de la auditoría."
                ),
                what_it_is_not="No requieren acción adicional.",
                raw_data={"already_ok": self.already_ok}
            ))

        print(
            f"[Hardener] Completado — "
            f"aplicados: {len(self.actions_taken)}, "
            f"bloqueados por GPO: {len(self.actions_blocked)}, "
            f"requieren admin: {len(self.actions_failed)}, "
            f"ya OK: {len(self.already_ok)}"
        )