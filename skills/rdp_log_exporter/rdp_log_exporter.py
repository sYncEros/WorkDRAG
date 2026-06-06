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
from pathlib import Path


# ── Configuración ──────────────────────────────────────────────────────────────

# Horario laboral estándar — accesos fuera de este rango son alertas
WORK_HOURS_START = 8   # 08:00
WORK_HOURS_END   = 20  # 20:00
WORK_DAYS        = [0, 1, 2, 3, 4]  # Lunes a Viernes

# IPs privadas — accesos desde fuera son más sospechosos
PRIVATE_IP_PREFIXES = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.30.", "172.31.", "192.168.", "127."
]

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

DAYS_BACK = 90  # Histórico de los últimos 90 días


class RDPLogExporter:
    SKILL_NAME = "rdp_log_exporter"

    def __init__(self, engine):
        self.engine = engine
        self.rdp_events   = []
        self.failed_events = []
        self.after_hours  = []
        self.external_ips = []

    def run(self):
        print("[RDP] Iniciando exportación de logs de acceso remoto...")
        self._collect_rdp_events()
        self._collect_failed_attempts()
        self._collect_reconnections()
        self._analyze_and_report()

    # ── Recolección de eventos ─────────────────────────────────────────────────

    def _collect_rdp_events(self):
        """Recopila inicios de sesión RDP exitosos (tipo 10)."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"$since = (Get-Date).AddDays(-{DAYS_BACK}); "
                 "Get-WinEvent -FilterHashtable @{"
                 "LogName='Security'; Id=4624; StartTime=$since"
                 "} -ErrorAction SilentlyContinue -MaxEvents 500 | "
                 "Where-Object { $_.Message -match 'Type.*10' } | "
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
                self.rdp_events = [
                    self._normalize_event(e) for e in (data or [])
                    if e.get("User") and e.get("User") not in
                    ["-", "SYSTEM", "ANONYMOUS LOGON"]
                ]
                print(f"[RDP] Eventos RDP exitosos: {len(self.rdp_events)}")
        except subprocess.TimeoutExpired:
            print("[RDP] Timeout leyendo eventos RDP — log muy grande")
        except Exception as e:
            print(f"[RDP] Error leyendo eventos RDP: {e}")

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

    # ── Análisis ────────────────────────────────────────────────────────────────

    def _normalize_event(self, raw: dict) -> dict:
        """Normaliza un evento de log a formato estándar."""
        ts_raw = str(raw.get("TimeCreated", "") or "")
        ts     = self._parse_timestamp(ts_raw)
        ip     = str(raw.get("IP", "") or "").strip()

        return {
            "timestamp":   ts,
            "timestamp_raw": ts_raw,
            "user":        str(raw.get("User", "") or "").strip(),
            "domain":      str(raw.get("Domain", "") or "").strip(),
            "ip":          ip,
            "event_type":  raw.get("event_type", "Inicio de sesión"),
            "event_id":    raw.get("event_id", 4624),
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
        if not ip or ip in ["-", "::1", "127.0.0.1", "LOCAL"]:
            return False
        return not any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)

    # ── Reporte ─────────────────────────────────────────────────────────────────

    def _analyze_and_report(self):
        """Analiza los eventos y genera hallazgos."""
        from core.audit_engine import AuditFinding

        after_hours  = [e for e in self.rdp_events if e["after_hours"]]
        external_ips = [e for e in self.rdp_events if e["external_ip"]]
        unique_users = list({e["user"] for e in self.rdp_events if e["user"]})
        unique_ips   = list({e["ip"]   for e in self.rdp_events if e["ip"]})

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
                "after_hours":     len([e for e in self.rdp_events
                                        if e["after_hours"]]),
                "external_ips":    len([e for e in self.rdp_events
                                        if e["external_ip"]]),
                "events":          self.rdp_events,
                "failed_events":   self.failed_events,
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