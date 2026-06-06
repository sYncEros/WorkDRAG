# core/audit_engine.py
"""Motor de auditoría principal que orquesta todos los skills."""

import json
import sqlite3
import hashlib
import datetime
import traceback
from contextlib import contextmanager
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

# Rutas base
BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / "evidence" / "audit.db"
EXPORTS_PATH = BASE_DIR / "exports"


@dataclass
class AuditFinding:
    skill: str
    category: str
    title: str
    description: str
    risk_level: str          # verde / amarillo / naranja / rojo
    technical_risk: str
    legal_risk: str
    what_it_is: str
    what_it_is_not: str
    raw_data: dict
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().isoformat()


class AuditEngine:
    def __init__(self):
        self.findings: list[AuditFinding] = []
        self.db = DB_PATH
        self._init_db()
        EXPORTS_PATH.mkdir(exist_ok=True)

    @contextmanager
    def _connect_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        DB_PATH.parent.mkdir(exist_ok=True)
        with self._connect_db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill TEXT,
                    category TEXT,
                    title TEXT,
                    description TEXT,
                    risk_level TEXT,
                    technical_risk TEXT,
                    legal_risk TEXT,
                    what_it_is TEXT,
                    what_it_is_not TEXT,
                    raw_data TEXT,
                    timestamp TEXT,
                    hash TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT,
                    finished_at TEXT,
                    total_findings INTEGER,
                    max_risk TEXT,
                    session_hash TEXT
                )
            """)
            conn.commit()

    def add_finding(self, finding: AuditFinding):
        """Añade un hallazgo y lo persiste en SQLite con hash de integridad."""
        raw = json.dumps(finding.raw_data, ensure_ascii=False)
        content = f"{finding.skill}{finding.title}{finding.timestamp}{raw}"
        finding_hash = hashlib.sha256(content.encode()).hexdigest()

        self.findings.append(finding)

        with self._connect_db() as conn:
            conn.execute("""
                INSERT INTO findings 
                (skill, category, title, description, risk_level, technical_risk,
                 legal_risk, what_it_is, what_it_is_not, raw_data, timestamp, hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                finding.skill, finding.category, finding.title,
                finding.description, finding.risk_level, finding.technical_risk,
                finding.legal_risk, finding.what_it_is, finding.what_it_is_not,
                raw, finding.timestamp, finding_hash
            ))
            conn.commit()

    def run_all_skills(self, skills: list = None):
        """Ejecuta los skills disponibles y recopila hallazgos."""
        from skills.mdm_audit.mdm_scanner import MDMAudit
        from skills.surveillance_audit.surveillance_scanner import SurveillanceAudit
        from skills.persistence_audit.persistence_scanner import PersistenceAudit
        from skills.network_monitor.network_scanner import NetworkMonitor
        from skills.activity_monitor.activity_scanner import ActivityMonitor
        from skills.privacy_audit.privacy_scanner import PrivacyAudit
        from skills.ai_telemetry_audit.ai_telemetry_scanner import AITelemetryAudit
        from skills.cloud_sync_audit.cloud_sync_scanner import CloudSyncAudit
        from skills.browser_audit.browser_scanner import BrowserAudit
        from skills.hardening_audit.hardening_scanner import HardeningAudit
        from skills.identity_audit.identity_scanner import IdentityAudit
        from skills.git_identity_audit.git_identity_scanner import GitIdentityAudit
        from skills.scheduled_tasks_audit.scheduled_tasks_scanner import ScheduledTasksAudit
        from skills.usb_audit.usb_scanner import USBAudit
        from skills.email_audit.email_scanner import EmailAudit
        from skills.third_party_apps_audit.third_party_scanner import ThirdPartyAppsAudit
        from skills.user_behavior_audit.behavior_scanner import UserBehaviorAudit
        from skills.data_exfiltration_audit.exfiltration_scanner import DataExfiltrationAudit
        from skills.incident_response.playbook_generator import IncidentResponsePlaybook
        from skills.event_viewer_audit.event_viewer_scanner import EventViewerAudit
        from skills.rdp_log_exporter.rdp_log_exporter import RDPLogExporter
        from skills.addon_audit.addon_scanner import AddonAudit
        from skills.onedrive_mapper.onedrive_mapper import OneDriveMapper
        from skills.diagtrack_inspector.diagtrack_inspector import DiagTrackInspector
        from skills.event_log_monitor.event_log_monitor import EventLogMonitor
        from skills.clipboard_watcher.clipboard_watcher import ClipboardWatcher
        from skills.dpa_checker.dpa_checker import DPAChecker
        from skills.service_hardener.service_hardener import ServiceHardener

        available = {
            "mdm":                 MDMAudit,
            "surveillance":        SurveillanceAudit,
            "persistence":         PersistenceAudit,
            "network":             NetworkMonitor,
            "activity":            ActivityMonitor,
            "privacy":             PrivacyAudit,
            "ai_telemetry":        AITelemetryAudit,
            "cloud_sync":          CloudSyncAudit,
            "browser":             BrowserAudit,
            "hardening":           HardeningAudit,
            "identity":            IdentityAudit,
            "git_identity":        GitIdentityAudit,
            "scheduled_tasks":     ScheduledTasksAudit,
            "usb":                 USBAudit,
            "email":               EmailAudit,
            "third_party_apps":    ThirdPartyAppsAudit,
            "user_behavior":       UserBehaviorAudit,
            "data_exfiltration":   DataExfiltrationAudit,
            "incident_response":   IncidentResponsePlaybook,
            "event_viewer":        EventViewerAudit,
            "rdp_logs":            RDPLogExporter,
            "addon_audit":         AddonAudit,
            "onedrive_mapper":     OneDriveMapper,
            "diagtrack_inspector": DiagTrackInspector,
            "event_log_monitor":   EventLogMonitor,
            "clipboard_watcher":   ClipboardWatcher,
            "dpa_checker":         DPAChecker,
            "service_hardener":    ServiceHardener,
        }

        to_run = skills or list(available.keys())
        session_start = datetime.datetime.now().isoformat()

        for name in to_run:
            if name in available:
                print(f"[*] Ejecutando skill: {name}")
                started_at = datetime.datetime.now()
                try:
                    skill = available[name](self)
                    skill.run()
                    elapsed = (datetime.datetime.now() - started_at).total_seconds()
                    print(f"[+] Skill completada: {name} ({elapsed:.1f}s)")
                except KeyboardInterrupt as e:
                    elapsed = (datetime.datetime.now() - started_at).total_seconds()
                    print(
                        f"[!] Skill interrumpida: '{name}' tras {elapsed:.1f}s "
                        f"(se continúa con la siguiente)"
                    )

                    self.add_finding(AuditFinding(
                        skill="audit_engine",
                        category="skill_execution_interrupted",
                        title=f"Skill interrumpida: {name}",
                        description=(
                            f"La skill '{name}' fue interrumpida y no pudo "
                            f"completarse, pero la auditoría continuó."
                        ),
                        risk_level="yellow",
                        technical_risk=(
                            "Una skill interrumpida puede dejar huecos en la "
                            "cobertura técnica del informe."
                        ),
                        legal_risk=(
                            "El informe puede quedar incompleto para ciertas "
                            "áreas de cumplimiento."
                        ),
                        what_it_is=(
                            "Interrupción técnica de una skill durante "
                            "la ejecución del pipeline."
                        ),
                        what_it_is_not=(
                            "No implica por sí mismo actividad maliciosa; "
                            "indica ejecución incompleta de esa parte."
                        ),
                        raw_data={
                            "skill": name,
                            "error_type": type(e).__name__,
                            "error_message": str(e),
                            "elapsed_seconds": round(elapsed, 2),
                        }
                    ))
                except Exception as e:
                    elapsed = (datetime.datetime.now() - started_at).total_seconds()
                    print(f"[!] Error en skill '{name}' tras {elapsed:.1f}s: {e}")

                    self.add_finding(AuditFinding(
                        skill="audit_engine",
                        category="skill_execution_error",
                        title=f"Error al ejecutar skill: {name}",
                        description=(
                            f"La skill '{name}' lanzó una excepción y no pudo "
                            f"completar su ejecución."
                        ),
                        risk_level="orange",
                        technical_risk=(
                            "Una skill fallida puede dejar huecos en la auditoría "
                            "y ocultar indicadores relevantes."
                        ),
                        legal_risk=(
                            "El informe puede ser incompleto si una skill clave "
                            "no llega a ejecutarse."
                        ),
                        what_it_is=(
                            "Error técnico durante la ejecución de un módulo "
                            "de auditoría."
                        ),
                        what_it_is_not=(
                            "No implica por sí mismo una intrusión; "
                            "indica un problema del proceso de auditoría."
                        ),
                        raw_data={
                            "skill": name,
                            "error_type": type(e).__name__,
                            "error_message": str(e),
                            "elapsed_seconds": round(elapsed, 2),
                            "traceback": traceback.format_exc(),
                        }
                    ))
            else:
                print(f"[!] Skill no reconocida, se omite: {name}")

        session_end = datetime.datetime.now().isoformat()
        max_risk = self._compute_max_risk()

        with self._connect_db() as conn:
            conn.execute("""
                INSERT INTO audit_sessions 
                (started_at, finished_at, total_findings, max_risk, session_hash)
                VALUES (?,?,?,?,?)
            """, (
                session_start, session_end,
                len(self.findings), max_risk,
                hashlib.sha256(session_start.encode()).hexdigest()
            ))
            conn.commit()

    def _compute_max_risk(self) -> str:
        order = ["green", "yellow", "orange", "red"]
        if not self.findings:
            return "green"
        levels = [f.risk_level for f in self.findings]
        return max(levels, key=lambda x: order.index(x) if x in order else 0)

    # ── Esquema JSON ───────────────────────────────────────────────

    FINDING_SCHEMA = {
        "required_fields": [
            "skill", "category", "title", "description",
            "risk_level", "technical_risk", "legal_risk",
            "what_it_is", "what_it_is_not", "raw_data", "timestamp",
        ],
        "valid_risk_levels": {"green", "yellow", "orange", "red"},
    }

    REPORT_SCHEMA = {
        "required_fields": [
            "generated_at", "total_findings", "max_risk",
            "findings", "integrity_hash",
        ],
        "valid_max_risks": {"green", "yellow", "orange", "red"},
    }

    def validate_schema(self, report: dict) -> list[str]:
        """Valida el esquema de un informe exportado. Devuelve lista de errores."""
        errors = []

        for field in self.REPORT_SCHEMA["required_fields"]:
            if field not in report:
                errors.append(f"Campo de informe faltante: '{field}'")

        if report.get("max_risk") not in self.REPORT_SCHEMA["valid_max_risks"]:
            errors.append(
                f"max_risk inválido: '{report.get('max_risk')}'. "
                f"Valores válidos: {self.REPORT_SCHEMA['valid_max_risks']}"
            )

        if not isinstance(report.get("total_findings"), int):
            errors.append("total_findings debe ser un entero")

        findings = report.get("findings", [])
        if not isinstance(findings, list):
            errors.append("findings debe ser una lista")
            return errors

        if report.get("total_findings") != len(findings):
            errors.append(
                f"total_findings ({report.get('total_findings')}) "
                f"no coincide con len(findings) ({len(findings)})"
            )

        for i, finding in enumerate(findings):
            for field in self.FINDING_SCHEMA["required_fields"]:
                if field not in finding:
                    errors.append(
                        f"Finding[{i}] '{finding.get('title', '?')}': "
                        f"campo faltante '{field}'"
                    )
            if finding.get("risk_level") not in self.FINDING_SCHEMA["valid_risk_levels"]:
                errors.append(
                    f"Finding[{i}] risk_level inválido: "
                    f"'{finding.get('risk_level')}'"
                )
            if not isinstance(finding.get("raw_data"), dict):
                errors.append(
                    f"Finding[{i}] raw_data debe ser dict, "
                    f"es {type(finding.get('raw_data')).__name__}"
                )

        return errors

    def export_json(self, filename: str = None) -> Path:
        """Exporta todos los hallazgos a JSON firmado."""
        data = {
            "generated_at": datetime.datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "max_risk": self._compute_max_risk(),
            "findings": [asdict(f) for f in self.findings]
        }
        content = json.dumps(data, ensure_ascii=False, indent=2)
        file_hash = hashlib.sha256(content.encode()).hexdigest()
        data["integrity_hash"] = file_hash

        stem = filename or f"audit_{datetime.date.today()}"
        out = EXPORTS_PATH / f"{stem}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        # Validar esquema del informe generado
        schema_errors = self.validate_schema(data)
        if schema_errors:
            print(f"[!] Advertencias de esquema ({len(schema_errors)}):")
            for err in schema_errors:
                print(f"    - {err}")
        print(f"[+] Exportado: {out}")
        return out

    def summary(self):
        """Imprime resumen en consola."""
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="Worker Digital Rights Audit — Resultados")
        table.add_column("Skill", style="cyan")
        table.add_column("Hallazgo", style="white")
        table.add_column("Riesgo", style="bold")

        colors = {
            "green": "green", "yellow": "yellow",
            "orange": "dark_orange", "red": "red"
        }

        for f in self.findings:
            color = colors.get(f.risk_level, "white")
            table.add_row(
                f.skill, f.title,
                f"[{color}]{f.risk_level.upper()}[/{color}]"
            )

        console.print(table)
        console.print(
            f"\n[bold]Total hallazgos:[/bold] {len(self.findings)} | "
            f"[bold]Riesgo máximo:[/bold] {self._compute_max_risk().upper()}"
        )