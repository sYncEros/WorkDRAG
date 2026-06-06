# skills/diagtrack_inspector/diagtrack_inspector.py
"""
Skill — DiagTrack Inspector
Audita en profundidad el servicio DiagTrack (Connected User Experiences
and Telemetry): estado, nivel configurado, endpoints de destino,
logs de transmisión recientes y datos recopilados.
"""

import subprocess
import json
import winreg
import os
from pathlib import Path
from datetime import datetime


# ── Configuración ──────────────────────────────────────────────────────────────

DIAGTRACK_SERVICE = "DiagTrack"

TELEMETRY_LEVELS = {
    0: ("Seguridad", "green",  "Mínimo — solo datos de seguridad críticos"),
    1: ("Básico",    "yellow", "Básico — datos de dispositivo y calidad"),
    2: ("Mejorado",  "orange", "Mejorado — datos de uso de apps y servicios"),
    3: ("Completo",  "red",    "Completo — todos los datos de diagnóstico"),
}

# Endpoints conocidos de telemetría Microsoft
TELEMETRY_ENDPOINTS = {
    "vortex.data.microsoft.com":       "Telemetría principal de Windows",
    "telemetry.microsoft.com":         "Telemetría general",
    "watson.telemetry.microsoft.com":  "Watson — informes de errores",
    "oca.telemetry.microsoft.com":     "Online Crash Analysis",
    "settings-win.data.microsoft.com": "Configuración de telemetría",
    "umwatsonc.events.data.microsoft.com": "Watson eventos corporativos",
    "ceuswatcab01.blob.core.windows.net":  "Blob storage telemetría",
    "ceuswatcab02.blob.core.windows.net":  "Blob storage telemetría",
    "watsonc.events.data.microsoft.com":   "Watson eventos",
}

# Rutas de logs de DiagTrack
DIAGTRACK_LOG_PATHS = [
    Path(os.environ.get("PROGRAMDATA", "")) /
    "Microsoft/Diagnosis/ETLLogs/AutoLogger",
    Path(os.environ.get("PROGRAMDATA", "")) /
    "Microsoft/Diagnosis/ETLLogs",
    Path(os.environ.get("PROGRAMDATA", "")) /
    "Microsoft/Diagnosis",
]

# Claves de registro de telemetría
TELEMETRY_REGISTRY_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
     "AllowTelemetry"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
     "AllowTelemetry"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
     "MaxTelemetryAllowed"),
]


class DiagTrackInspector:
    SKILL_NAME = "diagtrack_inspector"

    def __init__(self, engine):
        self.engine          = engine
        self.service_status  = None
        self.service_running = False
        self.telemetry_level = None
        self.telemetry_source = ""
        self.log_files       = []
        self.active_connections = []
        self.gpo_blocking    = False

    def run(self):
        print("[DiagTrack] Iniciando inspección de telemetría...")
        self._check_service_status()
        self._check_telemetry_level()
        self._check_log_files()
        self._check_active_connections()
        self._report()

    # ── Estado del servicio ────────────────────────────────────────────────────

    def _check_service_status(self):
        """Comprueba el estado del servicio DiagTrack."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Service DiagTrack | "
                 "Select-Object Name, Status, StartType, DisplayName | "
                 "ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                self.service_status  = data
                self.service_running = str(data.get("Status", "")).strip() in ("4", "Running", "Ejecutando")
                start_type = str(data.get("StartType", ""))
                print(
                    f"[DiagTrack] Servicio: "
                    f"{'🔴 ACTIVO' if self.service_running else '🟢 Detenido'} "
                    f"| StartType: {start_type}"
                )
        except subprocess.TimeoutExpired:
            print("[DiagTrack] Timeout comprobando servicio")
        except Exception as e:
            print(f"[DiagTrack] Error comprobando servicio: {e}")

    # ── Nivel de telemetría ────────────────────────────────────────────────────

    def _check_telemetry_level(self):
        """Lee el nivel de telemetría configurado y si hay GPO restrictiva."""
        level_found = None
        source      = ""

        for hive, key_path, value_name in TELEMETRY_REGISTRY_KEYS:
            try:
                key   = winreg.OpenKey(hive, key_path)
                value, _ = winreg.QueryValueEx(key, value_name)
                winreg.CloseKey(key)
                level_found = int(value)
                source      = key_path
                # Si viene de Policies es GPO
                if "Policies" in key_path:
                    self.gpo_blocking = (level_found <= 1)
                break
            except OSError:
                pass

        if level_found is None:
            # Sin política configurada = nivel completo por defecto
            level_found = 3
            source      = "Sin política — nivel por defecto (completo)"

        self.telemetry_level  = level_found
        self.telemetry_source = source

        level_info = TELEMETRY_LEVELS.get(level_found, (str(level_found), "red", "Desconocido"))
        print(
            f"[DiagTrack] Nivel: {level_info[0]} ({level_found}) "
            f"{'— GPO restrictiva activa' if self.gpo_blocking else '— sin restricción GPO'}"
        )

    # ── Archivos de log ────────────────────────────────────────────────────────

    def _check_log_files(self):
        """Detecta y analiza archivos de log ETL de DiagTrack."""
        for log_path in DIAGTRACK_LOG_PATHS:
            if not log_path.exists():
                continue
            try:
                for f in log_path.rglob("*.etl"):
                    try:
                        stat = f.stat()
                        self.log_files.append({
                            "path":     str(f),
                            "name":     f.name,
                            "size":     self._human_size(stat.st_size),
                            "modified": datetime.fromtimestamp(
                                stat.st_mtime
                            ).strftime("%Y-%m-%d %H:%M"),
                        })
                    except OSError:
                        pass
            except (PermissionError, OSError):
                pass

        if self.log_files:
            total = sum(
                f.stat().st_size
                for lf in self.log_files
                for f in [Path(lf["path"])]
                if Path(lf["path"]).exists()
            )
            print(
                f"[DiagTrack] Logs ETL encontrados: {len(self.log_files)} "
                f"({self._human_size(total)})"
            )
        else:
            print("[DiagTrack] Sin acceso a logs ETL (requiere elevación)")

    # ── Conexiones activas ─────────────────────────────────────────────────────

    def _check_active_connections(self):
        """Detecta conexiones de red activas de DiagTrack."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "$p = Get-Process DiagTrack -ErrorAction SilentlyContinue; "
                 "if ($p) { "
                 "  Get-NetTCPConnection -OwningProcess $p.Id "
                 "  -ErrorAction SilentlyContinue | "
                 "  Where-Object { $_.State -eq 'Established' } | "
                 "  Select-Object LocalPort, RemoteAddress, RemotePort, State | "
                 "  ConvertTo-Json "
                 "} else { '[]' }"],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0 and result.stdout.strip():
                data = result.stdout.strip()
                if data == "[]":
                    return
                conns = json.loads(data)
                if isinstance(conns, dict):
                    conns = [conns]
                for conn in (conns or []):
                    remote_ip = str(conn.get("RemoteAddress", ""))
                    self.active_connections.append({
                        "remote_ip":   remote_ip,
                        "remote_port": conn.get("RemotePort"),
                        "local_port":  conn.get("LocalPort"),
                        "state":       conn.get("State"),
                    })
            if self.active_connections:
                print(
                    f"[DiagTrack] Conexiones activas: "
                    f"{len(self.active_connections)}"
                )
        except Exception as e:
            print(f"[DiagTrack] Error comprobando conexiones: {e}")

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

        level_info = TELEMETRY_LEVELS.get(
            self.telemetry_level,
            (str(self.telemetry_level), "red", "Desconocido")
        )
        level_name, level_risk, level_desc = level_info

        # ── Hallazgo 1: Estado del servicio y nivel ────────────────────────────
        if self.service_running:
            risk = level_risk

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="diagtrack_active",
                title=(
                    f"DiagTrack activo — Telemetría nivel {level_name} "
                    f"({self.telemetry_level})"
                    + (" — sin restricción GPO" if not self.gpo_blocking
                       else " — GPO restrictiva activa")
                ),
                description=(
                    f"El servicio DiagTrack está en ejecución con nivel de "
                    f"telemetría '{level_name}': {level_desc}. "
                    + ("No existe política GPO que restrinja el nivel. "
                       "Se aplica el nivel por defecto (Completo)."
                       if not self.gpo_blocking else
                       f"Existe política GPO configurando nivel {self.telemetry_level}.")
                ),
                risk_level=risk,
                technical_risk=(
                    f"Nivel {self.telemetry_level} — {level_desc}. "
                    f"Fuente de configuración: {self.telemetry_source}. "
                    + (f"Conexiones activas: {len(self.active_connections)}."
                       if self.active_connections else
                       "Sin conexiones activas en este momento.")
                ),
                legal_risk=(
                    "DiagTrack recopila y envía datos de actividad del trabajador "
                    "a Microsoft en EEUU de forma continua. El empleador como "
                    "responsable del tratamiento debe garantizar base legal "
                    "adecuada bajo RGPD cap. V y tener DPA vigente con Microsoft."
                ),
                what_it_is=(
                    "DiagTrack (Connected User Experiences and Telemetry) es el "
                    "servicio de Windows que recopila datos de diagnóstico y uso "
                    "y los envía a Microsoft periódicamente."
                ),
                what_it_is_not=(
                    "No es un spyware instalado por la empresa. Es un componente "
                    "de Windows. El problema es que el empleador no ha aplicado "
                    "política GPO para reducir el nivel de telemetría al mínimo."
                ),
                raw_data={
                    "service_status":      self.service_status,
                    "service_running":     self.service_running,
                    "telemetry_level":     self.telemetry_level,
                    "telemetry_level_name": level_name,
                    "telemetry_source":    self.telemetry_source,
                    "gpo_restricting":     self.gpo_blocking,
                    "active_connections":  self.active_connections,
                    "log_files_count":     len(self.log_files),
                }
            ))

        # ── Hallazgo 2: Sin política GPO restrictiva ───────────────────────────
        if not self.gpo_blocking and self.service_running:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="diagtrack_no_policy",
                title="Sin política GPO que restrinja telemetría de Windows",
                description=(
                    "No existe ninguna política GPO que limite el nivel de "
                    "telemetría. Windows opera en nivel Completo por defecto, "
                    "enviando el máximo volumen de datos a Microsoft."
                ),
                risk_level="red",
                technical_risk=(
                    "El nivel Completo incluye: historial de navegación, "
                    "contenido de documentos abiertos, uso de aplicaciones, "
                    "actividad del usuario, diagnóstico de errores con contexto "
                    "completo incluyendo memoria y archivos abiertos."
                ),
                legal_risk=(
                    "La ausencia de política restrictiva implica que el empleador "
                    "no ha tomado medidas técnicas para minimizar la transferencia "
                    "internacional de datos del trabajador, incumpliendo RGPD art. 32 "
                    "y el principio de minimización del art. 5."
                ),
                what_it_is=(
                    "La ausencia de GPO AllowTelemetry=0 o AllowTelemetry=1 "
                    "significa que Windows usa su configuración por defecto "
                    "que es el nivel más alto de telemetría."
                ),
                what_it_is_not=(
                    "No es una decisión activa del empleador de espiar al trabajador. "
                    "Es una omisión de medidas de protección que le corresponde adoptar."
                ),
                raw_data={
                    "telemetry_level":  self.telemetry_level,
                    "registry_checked": [k[1] for k in TELEMETRY_REGISTRY_KEYS],
                }
            ))

        # ── Hallazgo 3: Logs ETL presentes ────────────────────────────────────
        if self.log_files:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="diagtrack_logs",
                title=(
                    f"Logs de telemetría DiagTrack presentes: "
                    f"{len(self.log_files)} archivos ETL"
                ),
                description=(
                    "Se han encontrado archivos de log ETL de DiagTrack. "
                    "Estos archivos contienen el historial de datos "
                    "recopilados antes de ser enviados a Microsoft."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Los archivos ETL contienen eventos de telemetría "
                    "pendientes de envío o ya enviados. Requieren herramientas "
                    "especializadas para su lectura (tracerpt, ETW viewers)."
                ),
                legal_risk=(
                    "La existencia de logs de telemetría es evidencia forense "
                    "del tratamiento de datos en curso. Pueden ser relevantes "
                    "para acreditar el alcance real de la recopilación."
                ),
                what_it_is=(
                    "Archivos Event Trace Log generados por DiagTrack "
                    "que contienen eventos de diagnóstico y telemetría."
                ),
                what_it_is_not=(
                    "No son accesibles directamente sin herramientas especializadas. "
                    "Su contenido exacto requiere análisis forense avanzado."
                ),
                raw_data={"log_files": self.log_files[:10]}
            ))

        # ── Hallazgo 4: Conexiones activas ────────────────────────────────────
        if self.active_connections:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="diagtrack_connections",
                title=(
                    f"DiagTrack con {len(self.active_connections)} "
                    f"conexiones activas a Microsoft"
                ),
                description=(
                    "DiagTrack tiene conexiones TCP establecidas en este "
                    "momento, transmitiendo datos de telemetría activamente."
                ),
                risk_level="orange",
                technical_risk=(
                    "Conexiones a: " +
                    ", ".join(
                        c["remote_ip"] for c in self.active_connections
                    )
                ),
                legal_risk=(
                    "Transmisión activa de datos a servidores de Microsoft "
                    "en EEUU. Transferencia internacional que requiere "
                    "base legal adecuada bajo RGPD cap. V."
                ),
                what_it_is=(
                    "Conexiones TCP establecidas desde el proceso DiagTrack "
                    "hacia servidores de Microsoft en el momento de la auditoría."
                ),
                what_it_is_not=(
                    "No implica que se estén enviando datos del trabajador "
                    "en este momento exacto — puede ser tráfico de configuración."
                ),
                raw_data={"connections": self.active_connections}
            ))

        print(
            f"[DiagTrack] Completado — "
            f"servicio: {'activo' if self.service_running else 'detenido'}, "
            f"nivel: {self.telemetry_level} ({TELEMETRY_LEVELS.get(self.telemetry_level, ('?',))[0]}), "
            f"logs: {len(self.log_files)}, "
            f"conexiones: {len(self.active_connections)}"
        )