# skills/rdp_log_exporter/rdp_log_exporter.py
"""
Skill — RDP Log Exporter
Extrae y analiza el historial completo de accesos remotos (RDP):
usuarios, IPs de origen, timestamps, duración y accesos fuera de horario.
Genera evidencia forense exportable con hash SHA-256.
"""

import subprocess
import json
import hashlib
import datetime
import os
from pathlib import Path


# ── Configuración ──────────────────────────────────────────────────────────────

# Horario laboral estándar — accesos fuera de este rango son alertas
WORK_HOURS_START = 8   # 08:00
WORK_HOURS_END   = 18  # 18:00
WORK_DAYS        = [0, 1, 2, 3, 4]  # Lunes a Viernes

# IPs privadas — accesos desde fuera son más sospechosos
PRIVATE_IP_PREFIXES = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.30.", "172.31.", "192.168.", "127."
]

LOCAL_IP_VALUES = {"", "-", "::1", "127.0.0.1", "LOCAL"}

# Event IDs relevantes para RDP
RDP_EVENT_IDS = {
    4624: "Inicio de sesión exitoso",
    4625: "Inicio de sesión fallido",
    4634: "Cierre de sesión",
    4647: "Cierre de sesión iniciado por usuario",
    4778: "Sesión RDP reconectada",
    4779: "Sesión RDP desconectada",
    1149: "Autenticación RDP exitosa (TerminalServices-RemoteConnectionManager)",
}

# Tipos de inicio de sesión relevantes
LOGON_TYPES = {
    3:  "Red",
    10: "Remoto interactivo (RDP)",
    7:  "Desbloqueo",
}

DAYS_BACK = 720  # Histórico de los últimos 720 días


class RDPLogExporter:
    SKILL_NAME = "rdp_log_exporter"

    def __init__(self, engine):
        self.engine = engine
        self.rdp_events   = []
        self.failed_events = []
        self.network_logons = []
        self.lsm_raw_events = []
        self.after_hours  = []
        self.external_ips = []
        self.telemetry = {
            "security_access": None,
            "security_access_error": "",
            "rcm_1149_events": 0,
            "rcm_available_ids": [],
            "lsm_raw_events": 0,
            "lsm_filtered_events": 0,
        }

    def run(self):
        print("[RDP] Iniciando exportación de logs de acceso remoto...")
        self._preflight_security_access()
        self._collect_rdp_events()
        self._collect_failed_attempts()
        self._collect_reconnections()
        self._collect_network_logons()
        self._analyze_and_report()

    def _preflight_security_access(self):
        """Verifica si el proceso actual puede leer el canal Security."""
        try:
            probe = subprocess.run(
                ["wevtutil", "qe", "Security", "/c:1", "/rd:true", "/f:text"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if probe.returncode == 0:
                self.telemetry["security_access"] = True
                self.telemetry["security_access_error"] = ""
                return

            err = (probe.stderr or "") + "\n" + (probe.stdout or "")
            self.telemetry["security_access"] = False
            self.telemetry["security_access_error"] = err.strip()[:500]
            print("[RDP] Advertencia: acceso limitado al log Security")
        except Exception as e:
            self.telemetry["security_access"] = False
            self.telemetry["security_access_error"] = str(e)
            print(f"[RDP] Advertencia: no se pudo validar acceso a Security: {e}")

    # ── Recolección de eventos ─────────────────────────────────────────────────

    def _collect_rdp_events(self):
        """Recopila conexiones RDP reales desde todos los logs relevantes."""

        # ── Log 1: TerminalServices RemoteConnectionManager — conexiones entrantes reales
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                f"$since = (Get-Date).AddDays(-{DAYS_BACK}); "
                "Get-WinEvent -FilterHashtable @{"
                "LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational';"
                "Id=1149; StartTime=$since"
                "} -ErrorAction SilentlyContinue -MaxEvents 500 | "
                "Select-Object TimeCreated,"
                "@{N='User';E={$_.Properties[0].Value}},"
                "@{N='Domain';E={$_.Properties[1].Value}},"
                "@{N='IP';E={$_.Properties[2].Value}},"
                "@{N='EventId';E={$_.Id}} |"
                "ConvertTo-Json -Depth 2"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                events = [self._normalize_event(e) for e in (data or [])]
                self.telemetry["rcm_1149_events"] = len(events)
                # Solo IPs no locales — estas son conexiones remotas reales
                remote = [e for e in events if e["ip"] not in ("LOCAL", "", "-", "::1", "127.0.0.1")]
                local  = [e for e in events if e["ip"] in ("LOCAL", "", "-", "::1", "127.0.0.1")]
                print(f"[RDP] RemoteConnectionManager — remotas: {len(remote)}, locales: {len(local)}")
                self.rdp_events.extend(remote)
            else:
                self.telemetry["rcm_1149_events"] = 0
        except subprocess.TimeoutExpired:
            print("[RDP] Timeout RemoteConnectionManager")
        except Exception as e:
            print(f"[RDP] Error RemoteConnectionManager: {e}")

        # Telemetría adicional: IDs disponibles en RCM para explicar ausencias de 1149
        try:
            ids_result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' "
                 "-ErrorAction SilentlyContinue -MaxEvents 2000 | "
                 "Group-Object Id | Sort-Object Count -Descending | "
                 "Select-Object -ExpandProperty Name | ConvertTo-Json -Depth 2"],
                capture_output=True,
                text=True,
                timeout=25,
            )
            if ids_result.returncode == 0 and ids_result.stdout.strip():
                ids_data = json.loads(ids_result.stdout)
                if isinstance(ids_data, list):
                    self.telemetry["rcm_available_ids"] = [int(x) for x in ids_data if str(x).isdigit()]
                elif str(ids_data).isdigit():
                    self.telemetry["rcm_available_ids"] = [int(ids_data)]
        except Exception:
            pass

        # ── Log 2: Security 4624 LogonType 10 — todas las cuentas
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                f"$since = (Get-Date).AddDays(-{DAYS_BACK}); "
                "Get-WinEvent -FilterHashtable @{"
                "LogName='Security'; Id=4624; StartTime=$since"
                "} -ErrorAction SilentlyContinue -MaxEvents 1000 | "
                "Where-Object { $_.Properties[8].Value -eq 10 } | "
                "Select-Object TimeCreated,"
                "@{N='User';E={$_.Properties[5].Value}},"
                "@{N='Domain';E={$_.Properties[6].Value}},"
                "@{N='IP';E={$_.Properties[18].Value}},"
                "@{N='LogonType';E={$_.Properties[8].Value}},"
                "@{N='EventId';E={$_.Id}} |"
                "ConvertTo-Json -Depth 2"],
                capture_output=True, text=True, timeout=45
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                events = [
                    self._normalize_event(e) for e in (data or [])
                    if str(e.get("User", "")).strip() not in
                    ["", "-", "SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE"]
                ]
                # Separar remotas de locales
                remote = [e for e in events if e["ip"] not in ("LOCAL", "", "-", "::1", "127.0.0.1")]
                local  = [e for e in events if e["ip"] in ("LOCAL", "", "-", "::1", "127.0.0.1")]
                print(f"[RDP] Security 4624/Type10 — remotas: {len(remote)}, locales: {len(local)}, usuarios: {list({e['user'] for e in events})}")
                # Añadir remotas sin deduplicar — cada evento cuenta
                self.rdp_events.extend(remote)
                # Añadir locales solo si son cuentas distintas a la tuya
                own_user = None
                own_user = os.environ.get("USERNAME", "").lower()
                for e in local:
                    if e["user"].split("\\")[-1].lower() != own_user:
                        self.rdp_events.append(e)
        except subprocess.TimeoutExpired:
            print("[RDP] Timeout Security log")
        except Exception as e:
            print(f"[RDP] Error Security log: {e}")

        # ── Log 3: LocalSessionManager 21/25 — solo otras cuentas
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                f"$since = (Get-Date).AddDays(-{DAYS_BACK}); "
                "Get-WinEvent -FilterHashtable @{"
                "LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';"
                "Id=@(21,25); StartTime=$since"
                "} -ErrorAction SilentlyContinue -MaxEvents 200 | "
                "Select-Object TimeCreated,"
                "@{N='User';E={$_.Properties[0].Value}},"
                "@{N='IP';E={$_.Properties[2].Value}},"
                "@{N='EventId';E={$_.Id}} |"
                "ConvertTo-Json -Depth 2"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                own_user = os.environ.get("USERNAME", "").lower()
                events = [self._normalize_event(e) for e in (data or [])]
                self.lsm_raw_events = events
                self.telemetry["lsm_raw_events"] = len(events)
                # Solo otras cuentas — las tuyas ya están descartadas
                others = [
                    e for e in events
                    if e["user"].split("\\")[-1].lower() != own_user
                ]
                self.telemetry["lsm_filtered_events"] = len(others)
                print(f"[RDP] LocalSessionManager — otras cuentas: {len(others)}")
                self.rdp_events.extend(others)
        except Exception as e:
            print(f"[RDP] Error LocalSessionManager: {e}")

        print(f"[RDP] Total conexiones remotas o de terceros: {len(self.rdp_events)}")

    def _collect_failed_attempts(self):
        """Recopila intentos de inicio de sesión fallidos."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"$since = (Get-Date).AddDays(-{DAYS_BACK}); "
                 "Get-WinEvent -FilterHashtable @{"
                 "LogName='Security'; Id=4625; StartTime=$since"
                 "} -ErrorAction SilentlyContinue -MaxEvents 200 | "
                 "Select-Object TimeCreated, "
                 "@{N='User';E={$_.Properties[5].Value}}, "
                 "@{N='IP';E={$_.Properties[19].Value}}, "
                 "@{N='Reason';E={$_.Properties[9].Value}} | "
                 "ConvertTo-Json -Depth 2"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                self.failed_events = [
                    self._normalize_event(e) for e in (data or [])
                ]
                print(f"[RDP] Intentos fallidos: {len(self.failed_events)}")
        except Exception as e:
            print(f"[RDP] Error leyendo intentos fallidos: {e}")

    def _collect_reconnections(self):
        """Recopila reconexiones y desconexiones de sesiones RDP."""
        for event_id in [4778, 4779]:
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"$since = (Get-Date).AddDays(-{DAYS_BACK}); "
                     f"Get-WinEvent -FilterHashtable @{{"
                     f"LogName='Security'; Id={event_id}; StartTime=$since"
                     f"}} -ErrorAction SilentlyContinue -MaxEvents 100 | "
                     "Select-Object TimeCreated, "
                     "@{N='User';E={$_.Properties[0].Value}}, "
                     "@{N='IP';E={$_.Properties[2].Value}} | "
                     "ConvertTo-Json -Depth 2"],
                    capture_output=True, text=True, timeout=20
                )
                if result.returncode == 0 and result.stdout.strip():
                    data = json.loads(result.stdout)
                    if isinstance(data, dict):
                        data = [data]
                    label = (
                        "Reconexión" if event_id == 4778
                        else "Desconexión"
                    )
                    for e in (data or []):
                        e["event_type"] = label
                        e["event_id"]   = event_id
                    self.rdp_events.extend([
                        self._normalize_event(e) for e in (data or [])
                    ])
            except Exception:
                pass

    def _collect_network_logons(self):
        """Recopila inicios de sesión de red (no RDP) con IP de origen."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"$since = (Get-Date).AddDays(-{DAYS_BACK}); "
                 "Get-WinEvent -FilterHashtable @{"
                 "LogName='Security'; Id=4624; StartTime=$since"
                 "} -ErrorAction SilentlyContinue -MaxEvents 1200 | "
                 "Where-Object { "
                 "$_.Properties.Count -gt 18 -and "
                 "$_.Properties[8].Value -in @(3,9) -and "
                 "$_.Properties[18].Value -and "
                 "$_.Properties[18].Value -notin @('-', '::1', '127.0.0.1', 'LOCAL')"
                 " } | "
                 "Select-Object TimeCreated, "
                 "@{N='User';E={$_.Properties[5].Value}}, "
                 "@{N='Domain';E={$_.Properties[6].Value}}, "
                 "@{N='IP';E={$_.Properties[18].Value}}, "
                 "@{N='LogonType';E={$_.Properties[8].Value}} | "
                 "ConvertTo-Json -Depth 2"],
                capture_output=True, text=True, timeout=45
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]

                norm = [self._normalize_event(e) for e in (data or [])]
                for e in norm:
                    lt = e.get("logon_type")
                    e["event_type"] = f"Inicio de sesión de red (tipo {lt})"
                    e["event_id"] = 4624

                self.network_logons = norm
                print(
                    f"[RDP] Señales de acceso remoto no-RDP "
                    f"(logon tipo 3/9): {len(self.network_logons)}"
                )
        except subprocess.TimeoutExpired:
            print("[RDP] Timeout leyendo logons de red (4624 tipo 3/9)")
        except Exception as e:
            print(f"[RDP] Error leyendo logons de red: {e}")

    # ── Análisis ────────────────────────────────────────────────────────────────

    def _normalize_event(self, raw: dict) -> dict:
        """Normaliza un evento de log a formato estándar."""
        ts_raw = str(raw.get("TimeCreated", "") or "")
        ts     = self._parse_timestamp(ts_raw)
        ip     = str(raw.get("IP", "") or "").strip()
        logon_type_raw = raw.get("LogonType", "")
        try:
            logon_type = int(logon_type_raw)
        except Exception:
            logon_type = None

        return {
            "timestamp":   ts,
            "timestamp_raw": ts_raw,
            "user":        str(raw.get("User", "") or "").strip(),
            "domain":      str(raw.get("Domain", "") or "").strip(),
            "ip":          ip,
            "event_type":  raw.get("event_type", "Inicio de sesión"),
            "event_id":    raw.get("event_id", 4624),
            "logon_type":  logon_type,
            "after_hours": self._is_after_hours(ts),
            "external_ip": self._is_external_ip(ip),
            "reason":      str(raw.get("Reason", "") or ""),
        }

    def _parse_timestamp(self, ts_raw: str) -> str:
        """Normaliza timestamps de PowerShell a ISO 8601."""
        if not ts_raw or ts_raw == "None":
            return ""
        # Formato /Date(1234567890000)/
        if "/Date(" in ts_raw:
            try:
                ms = int(ts_raw.replace("/Date(", "").replace(")/", ""))
                dt = datetime.datetime.fromtimestamp(ms / 1000)
                return dt.isoformat()
            except Exception:
                pass
        return ts_raw[:19] if len(ts_raw) >= 19 else ts_raw

    def _is_after_hours(self, ts: str) -> bool:
        """Detecta si el acceso fue fuera del horario laboral."""
        if not ts:
            return False
        try:
            dt = datetime.datetime.fromisoformat(ts)
            is_weekend  = dt.weekday() not in WORK_DAYS
            is_off_hours = (
                dt.hour < WORK_HOURS_START or
                dt.hour >= WORK_HOURS_END
            )
            return is_weekend or is_off_hours
        except Exception:
            return False

    def _is_external_ip(self, ip: str) -> bool:
        """Detecta si la IP es externa a la red corporativa."""
        if self._is_local_ip(ip):
            return False
        return not any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)

    def _is_local_ip(self, ip: str) -> bool:
        """Detecta si una IP indica origen local/no enrutable útil para forense."""
        return str(ip or "").strip().upper() in {
            x.upper() for x in LOCAL_IP_VALUES
        }

    # ── Reporte ─────────────────────────────────────────────────────────────────

    def _analyze_and_report(self):
        """Analiza los eventos y genera hallazgos."""
        from core.audit_engine import AuditFinding

        after_hours  = [e for e in self.rdp_events if e["after_hours"]]
        external_ips = [e for e in self.rdp_events if e["external_ip"]]
        local_rdp_events = [
            e for e in self.rdp_events if self._is_local_ip(e.get("ip", ""))
        ]
        local_only_rdp = (
            bool(self.rdp_events) and
            len(local_rdp_events) == len(self.rdp_events)
        )

        network_external = [
            e for e in self.network_logons if e.get("external_ip")
        ]
        network_users = list({
            e["user"] for e in self.network_logons if e.get("user")
        })
        network_ips = list({
            e["ip"] for e in self.network_logons if e.get("ip")
        })

        unique_users = list({e["user"] for e in self.rdp_events if e["user"]})
        unique_ips   = list({e["ip"]   for e in self.rdp_events if e["ip"]})

        # ── Hallazgo 0: Cobertura/limitaciones de telemetría ────────────────
        if not self.rdp_events and not self.failed_events and not self.network_logons:
            security_access = self.telemetry.get("security_access")
            risk = "orange" if security_access is False else "yellow"
            lsm_users = list({e.get("user", "") for e in self.lsm_raw_events if e.get("user")})
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="rdp_telemetry_coverage_gap",
                title="Sin eventos RDP atribuibles: posible limitación de cobertura en logs",
                description=(
                    "No se detectaron eventos en los canales objetivo (1149/4624-10/4625) "
                    "durante el periodo analizado. Esto puede deberse a falta de privilegios "
                    "sobre Security, ausencia real de esos eventos o filtros que excluyen actividad local propia."
                ),
                risk_level=risk,
                technical_risk=(
                    "La ausencia de telemetría limita la atribución forense de accesos remotos. "
                    "El resultado '0 eventos' no equivale a ausencia absoluta de actividad."
                ),
                legal_risk=(
                    "Un informe sin cobertura suficiente puede ser débil en contexto pericial. "
                    "Debe declararse expresamente la limitación y solicitar adquisición adicional "
                    "(ejecución elevada/políticas de auditoría)."
                ),
                what_it_is=(
                    "Hallazgo metodológico de cobertura: explica por qué no hay detecciones concluyentes "
                    "en canales RDP/Security con la evidencia disponible."
                ),
                what_it_is_not=(
                    "No es prueba de inexistencia de accesos remotos; es una advertencia de visibilidad "
                    "forense insuficiente con el contexto actual."
                ),
                raw_data={
                    "security_access": security_access,
                    "security_access_error": self.telemetry.get("security_access_error", ""),
                    "rcm_1149_events": self.telemetry.get("rcm_1149_events", 0),
                    "rcm_available_ids": self.telemetry.get("rcm_available_ids", []),
                    "lsm_raw_events": self.telemetry.get("lsm_raw_events", 0),
                    "lsm_filtered_events": self.telemetry.get("lsm_filtered_events", 0),
                    "lsm_users_sample": lsm_users[:10],
                    "days_analyzed": DAYS_BACK,
                }
            ))

        # ── Hallazgo 1: Resumen de accesos RDP ────────────────────────────────
        if self.rdp_events:
            risk = "green"
            if after_hours:
                risk = "orange"
            if external_ips:
                risk = "red"

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="rdp_access_history",
                title=f"Historial RDP: {len(self.rdp_events)} accesos "
                      f"en {DAYS_BACK} días"
                      + (f" — {len(after_hours)} fuera de horario"
                         if after_hours else "")
                      + (" — IPs EXTERNAS detectadas"
                         if external_ips else ""),
                description=(
                    f"Se han registrado {len(self.rdp_events)} eventos "
                    f"de acceso remoto en los últimos {DAYS_BACK} días. "
                    f"Usuarios distintos: {len(unique_users)}. "
                    f"IPs distintas: {len(unique_ips)}."
                ),
                risk_level=risk,
                technical_risk=(
                    f"Accesos registrados desde {len(unique_ips)} IPs "
                    f"distintas. "
                    + (f"{len(external_ips)} accesos desde IPs externas "
                       f"a la red corporativa. "
                       if external_ips else "")
                    + (f"{len(after_hours)} accesos fuera del horario "
                       f"laboral ({WORK_HOURS_START}h-{WORK_HOURS_END}h, "
                       f"L-V)."
                       if after_hours else "")
                ),
                legal_risk=(
                    "El registro de accesos RDP es evidencia forense "
                    "directa de quién ha accedido al equipo del trabajador "
                    "y cuándo. "
                    "Accesos fuera de horario sin notificación pueden "
                    "constituir vigilancia encubierta bajo LOPDGDD art. 87."
                ),
                what_it_is=(
                    "Log de accesos remotos al escritorio del trabajador "
                    "extraído del Event Viewer de Windows, con timestamps, "
                    "usuarios e IPs de origen."
                ),
                what_it_is_not=(
                    "No implica que todos los accesos sean ilegítimos. "
                    "El soporte técnico usa RDP. El problema es el acceso "
                    "sin notificación previa al trabajador."
                ),
                raw_data={
                    "total_events":    len(self.rdp_events),
                    "unique_users":    unique_users,
                    "unique_ips":      unique_ips,
                    "after_hours":     len(after_hours),
                    "external_ips":    len(external_ips),
                    "days_analyzed":   DAYS_BACK,
                    "events_sample":   self.rdp_events[:25],
                }
            ))

        # ── Hallazgo 1b: Solo origen LOCAL en trazas RDP ────────────────────
        if local_only_rdp:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="rdp_local_only_activity",
                title=(
                    "Eventos RDP detectados solo con origen LOCAL "
                    f"({len(local_rdp_events)} eventos)"
                ),
                description=(
                    "Todos los eventos RDP recuperados en este análisis "
                    "aparecen con 'Dirección de red de origen: LOCAL'."
                ),
                risk_level="yellow",
                technical_risk=(
                    "La telemetría disponible no muestra IP remota ni "
                    "cuentas de terceros para esos eventos. Esto limita la "
                    "atribución forense de accesos externos por RDP."
                ),
                legal_risk=(
                    "No puede concluirse acceso remoto de terceros solo con "
                    "estos eventos. Se recomienda contraste con otras fuentes "
                    "de auditoría para trazabilidad completa."
                ),
                what_it_is=(
                    "Indicador de que las sesiones registradas por Terminal "
                    "Services son locales/reconectadas con origen LOCAL."
                ),
                what_it_is_not=(
                    "No demuestra por sí mismo que no haya existido acceso "
                    "remoto por otros canales o herramientas."
                ),
                raw_data={
                    "total_rdp_events": len(self.rdp_events),
                    "local_origin_events": len(local_rdp_events),
                    "sample": local_rdp_events[:20],
                }
            ))

        # ── Hallazgo 2: Accesos fuera de horario ──────────────────────────────
        if after_hours:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="rdp_after_hours",
                title=f"Accesos RDP fuera de horario laboral "
                      f"({len(after_hours)} eventos)",
                description=(
                    f"Se han detectado {len(after_hours)} accesos remotos "
                    f"fuera del horario laboral estándar "
                    f"({WORK_HOURS_START}h-{WORK_HOURS_END}h, L-V)."
                ),
                risk_level="orange",
                technical_risk=(
                    "Accesos remotos al equipo fuera de horario pueden "
                    "indicar vigilancia del trabajador en tiempo personal, "
                    "o acceso a datos del trabajador sin su presencia."
                ),
                legal_risk=(
                    "La monitorización fuera del horario laboral tiene "
                    "restricciones específicas bajo LOPDGDD art. 88 "
                    "(derecho a la desconexión digital). "
                    "El acceso al equipo fuera de horario sin conocimiento "
                    "del trabajador puede vulnerar este derecho."
                ),
                what_it_is=(
                    "Accesos remotos registrados en días festivos, "
                    "fines de semana o fuera del horario habitual de trabajo."
                ),
                what_it_is_not=(
                    "Puede ser mantenimiento programado de IT. "
                    "Requiere justificación documentada para cada acceso."
                ),
                raw_data={
                    "after_hours_events": after_hours[:20],
                    "work_hours":         f"{WORK_HOURS_START}h-{WORK_HOURS_END}h L-V",
                }
            ))

        # ── Hallazgo 3: IPs externas ───────────────────────────────────────────
        if external_ips:
            external_unique = list({e["ip"] for e in external_ips})
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="rdp_external_access",
                title=f"Accesos RDP desde IPs externas "
                      f"({len(external_unique)} IPs distintas)",
                description=(
                    f"Se han detectado accesos RDP desde "
                    f"{len(external_unique)} IPs externas a la red "
                    f"corporativa: {', '.join(external_unique[:5])}"
                    + (" y más..." if len(external_unique) > 5 else "")
                ),
                risk_level="red",
                technical_risk=(
                    "Accesos desde IPs externas implican que el equipo "
                    "está expuesto a Internet o accesible via VPN desde "
                    "ubicaciones no corporativas. "
                    "Aumenta significativamente la superficie de riesgo."
                ),
                legal_risk=(
                    "Accesos desde IPs externas sin conocimiento del "
                    "trabajador tienen mayor gravedad legal. "
                    "Requieren justificación específica y documentada. "
                    "LOPDGDD art. 87 y posiblemente CP art. 197 "
                    "si no hay autorización."
                ),
                what_it_is=(
                    "Accesos RDP registrados desde direcciones IP "
                    "fuera de la red corporativa interna."
                ),
                what_it_is_not=(
                    "Puede ser VPN de soporte remoto legítima. "
                    "Cada IP externa necesita justificación documentada."
                ),
                raw_data={
                    "external_ip_events":  external_ips[:20],
                    "unique_external_ips": external_unique,
                }
            ))

        # ── Hallazgo 4: Intentos fallidos ─────────────────────────────────────
        if self.failed_events:
            # Detecta si hay muchos intentos desde la misma IP
            ip_count = {}
            for e in self.failed_events:
                ip = e.get("ip", "unknown")
                ip_count[ip] = ip_count.get(ip, 0) + 1

            brute_force_ips = {
                ip: count for ip, count in ip_count.items()
                if count >= 5
            }

            risk = "red" if brute_force_ips else "yellow"
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="rdp_failed_attempts",
                title=f"Intentos de acceso RDP fallidos "
                      f"({len(self.failed_events)})"
                      + (" — posible fuerza bruta"
                         if brute_force_ips else ""),
                description=(
                    f"Se han registrado {len(self.failed_events)} intentos "
                    f"de acceso remoto fallidos en los últimos "
                    f"{DAYS_BACK} días."
                    + (f" IPs con múltiples intentos: "
                       f"{dict(list(brute_force_ips.items())[:3])}"
                       if brute_force_ips else "")
                ),
                risk_level=risk,
                technical_risk=(
                    "Múltiples intentos fallidos desde la misma IP "
                    "indican ataque de fuerza bruta. "
                    "El equipo está expuesto a ataques de acceso remoto."
                ),
                legal_risk=(
                    "La exposición del equipo a ataques externos implica "
                    "que el empleador no ha aplicado medidas de seguridad "
                    "adecuadas bajo RGPD art. 32."
                ),
                what_it_is=(
                    "Intentos de inicio de sesión remoto que fallaron, "
                    "por contraseña incorrecta o cuenta bloqueada."
                ),
                what_it_is_not=(
                    "No todos los intentos fallidos son ataques. "
                    "Pueden ser errores de usuarios legítimos."
                ),
                raw_data={
                    "total_failed":     len(self.failed_events),
                    "brute_force_ips":  brute_force_ips,
                    "events_sample":    self.failed_events[:15],
                }
            ))

        # ── Hallazgo 5: Señales remotas no-RDP (logon red tipo 3/9) ─────────
        if self.network_logons:
            risk = "orange" if network_external else "yellow"
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="non_rdp_remote_signals",
                title=(
                    "Señales de acceso remoto no-RDP detectadas "
                    f"({len(self.network_logons)} eventos de red)"
                    + (" — con IPs externas" if network_external else "")
                ),
                description=(
                    "Se detectaron inicios de sesión en Security (4624) "
                    "tipo 3/9 con IP de origen, útiles para atribución "
                    "forense aunque no sean sesiones RDP interactivas."
                ),
                risk_level=risk,
                technical_risk=(
                    "La presencia de logons de red confirma actividad remota "
                    "sobre recursos del equipo. Si hay IPs externas, aumenta "
                    "la exposición y el riesgo de acceso no autorizado."
                ),
                legal_risk=(
                    "Estos eventos pueden ser relevantes para acreditar "
                    "accesos remotos no transparentes para el trabajador, "
                    "según el contexto y políticas internas."
                ),
                what_it_is=(
                    "Eventos 4624 tipo 3/9 (red/credenciales) con IP de "
                    "origen distinta de LOCAL/loopback."
                ),
                what_it_is_not=(
                    "No equivalen automáticamente a control remoto de "
                    "pantalla; incluyen también accesos a recursos de red."
                ),
                raw_data={
                    "total_network_logons": len(self.network_logons),
                    "unique_users": network_users,
                    "unique_ips": network_ips,
                    "external_events": len(network_external),
                    "events_sample": self.network_logons[:25],
                }
            ))

        # ── Exportar evidencia forense ─────────────────────────────────────────
        evidence_path = self._export_evidence()
        if evidence_path:
            print(f"[RDP] Evidencia exportada: {evidence_path}")

        print(
            f"[RDP] Completado — "
            f"{len(self.rdp_events)} accesos, "
            f"{len(after_hours)} fuera de horario, "
            f"{len(external_ips)} IPs externas, "
            f"{len(self.failed_events)} fallidos"
        )

    def _export_evidence(self) -> Path | None:
        """Exporta los logs como evidencia forense con hash SHA-256."""
        try:
            evidence_dir = Path("evidence") / "rdp_logs"
            evidence_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path  = evidence_dir / f"rdp_log_{timestamp}.json"

            data = {
                "generated_at":    datetime.datetime.now().isoformat(),
                "days_analyzed":   DAYS_BACK,
                "total_events":    len(self.rdp_events),
                "failed_attempts": len(self.failed_events),
                "network_logons":  len(self.network_logons),
                "telemetry":       self.telemetry,
                "after_hours":     len([e for e in self.rdp_events
                                        if e["after_hours"]]),
                "external_ips":    len([e for e in self.rdp_events
                                        if e["external_ip"]]),
                "events":          self.rdp_events,
                "failed_events":   self.failed_events,
                "network_events":  self.network_logons,
            }

            content     = json.dumps(data, ensure_ascii=False, indent=2)
            file_hash   = hashlib.sha256(content.encode()).hexdigest()
            data["integrity_hash"] = file_hash

            out_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            return out_path
        except Exception as e:
            print(f"[RDP] Error exportando evidencia: {e}")
            return None