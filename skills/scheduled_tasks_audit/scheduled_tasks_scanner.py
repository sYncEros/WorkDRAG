# skills/scheduled_tasks_audit/scheduled_tasks_scanner.py
"""
Skill — Auditoría Profunda de Tareas Programadas
Analiza quién creó cada tarea, cuándo, qué ejecuta, historial de runs
y si el ejecutable tiene firma digital válida.
"""

import json
import os
import subprocess
import winreg
from pathlib import Path
from datetime import datetime
from core.capability_intel import get_sources, gpresult_summary, fltmc_summary


class ScheduledTasksAudit:
    SKILL_NAME = "scheduled_tasks_audit"

    # Palabras clave que indican posible monitorización
    MONITORING_KEYWORDS = [
        "monitor", "agent", "telemetry", "track", "log", "audit",
        "watch", "sensor", "insight", "collect", "record", "capture",
        "observe", "edr", "dlp", "xdr", "falcon", "sentinel",
        "tanium", "netskope", "zscaler", "activtrak", "teramind",
        "hubstaff", "veriato", "keylog", "screenshot", "screen",
        "activity", "behavior", "spy", "surveil",
    ]

    # Rutas corporativas y de telemetría conocidas
    SUSPICIOUS_PATH_FRAGMENTS = [
        "programdata\\microsoft\\windows defender",
        "activtrak", "teramind", "hubstaff", "veriato",
        "observeit", "ekran", "work examiner",
        "netskope", "zscaler", "tanium", "crowdstrike",
        "sentinelone", "cybereason",
    ]

    INTERPRETER_EXECUTABLES = {
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe",
    }

    SUSPICIOUS_ARGUMENT_PATTERNS = [
        "-encodedcommand", "frombase64string", "iex",
        "invoke-expression", "downloadstring", "downloadfile",
        "http://", "https://", "\\\\", "/c", "-nop", "-w hidden",
    ]

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[ScheduledTasks] Iniciando auditoría profunda de tareas programadas...")
        tasks = self._get_all_tasks()
        if not tasks:
            print("[ScheduledTasks] No se pudieron obtener tareas.")
            return

        self._analyze_non_microsoft_tasks(tasks)
        self._analyze_capability_based_tasks(tasks)
        self._analyze_monitoring_tasks(tasks)
        self._analyze_interpreter_tasks(tasks)
        self._analyze_recent_tasks(tasks)
        self._analyze_unsigned_executables(tasks)
        self._analyze_task_history(tasks)
        print(f"[ScheduledTasks] Completado — {len(tasks)} tareas analizadas.")

    # ── Análisis por capacidad (independiente de fabricante) ─────

    def _analyze_capability_based_tasks(self, tasks: list[dict]):
        from core.audit_engine import AuditFinding

        capability_hits = []

        for task in tasks:
            if str(task.get("TaskPath", "")).startswith("\\Microsoft\\"):
                continue

            score = 0
            reasons = []

            run_as = str(task.get("RunAsUser", "") or "").lower()
            if any(x in run_as for x in ["system", "localsystem", "nt authority\\system"]):
                score += 2
                reasons.append("ejecución como SYSTEM")

            run_level = str(task.get("RunLevel", "") or "").lower()
            if "highest" in run_level:
                score += 2
                reasons.append("RunLevel=Highest")

            exe = self._extract_executable(task)
            sig = self._check_signature(exe) if exe else None
            if sig and sig.get("status") not in ("Valid", "NotApplicable"):
                score += 2
                reasons.append(f"firma no válida ({sig.get('status')})")

            if exe:
                exe_low = exe.lower()
                if any(x in exe_low for x in ["\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\"]):
                    score += 1
                    reasons.append("ejecutable en ruta de usuario/escritura frecuente")

            state = str(task.get("State", "") or "").lower()
            if state in ("running", "ready"):
                score += 1
                reasons.append(f"estado activo ({task.get('State')})")

            if score >= 4:
                capability_hits.append({
                    "task": task.get("TaskName"),
                    "path": task.get("TaskPath"),
                    "author": task.get("Author"),
                    "run_as": task.get("RunAsUser"),
                    "run_level": task.get("RunLevel"),
                    "state": task.get("State"),
                    "executable": exe,
                    "signature": sig,
                    "score": score,
                    "reasons": reasons,
                })

        if not capability_hits:
            return

        sources = get_sources(
            "endpoint_monitoring_capabilities",
            "event_and_logging_capabilities",
        )
        triangulation = {
            "gpresult": gpresult_summary(),
            "fltmc_filters": fltmc_summary(),
        }

        risk = "orange"
        if any(h["score"] >= 6 for h in capability_hits):
            risk = "red"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_capability_risk",
            title=f"Tareas con capacidad técnica elevada detectadas ({len(capability_hits)})",
            description=(
                "Detección por capacidad (privilegios, firma y ruta de ejecución), "
                "sin depender de nombres de fabricante o palabras clave."
            ),
            risk_level=risk,
            technical_risk=(
                "Tareas fuera de Microsoft ejecutándose con privilegios altos y/o "
                "binarios sin firma aumentan el riesgo de ejecución persistente "
                "de software no autorizado."
            ),
            legal_risk=(
                "En contexto laboral, estas capacidades exigen justificación, "
                "trazabilidad y comunicación previa cuando impliquen monitorización "
                "del trabajador."
            ),
            what_it_is=(
                "Análisis de capacidad operativa de tareas programadas: qué pueden "
                "hacer técnicamente, no cómo se llaman."
            ),
            what_it_is_not=(
                "No prueba por sí solo un uso ilegítimo; requiere contraste con "
                "finalidad corporativa y documentación de cambios."
            ),
            raw_data={
                "hits": capability_hits,
                "threshold": 4,
                "max_score": max(h["score"] for h in capability_hits),
                "independent_sources": sources,
                "triangulation": triangulation,
            }
        ))

    # ── Obtención de todas las tareas ──────────────────────────────

    def _get_all_tasks(self) -> list[dict]:
        """Obtiene todas las tareas programadas con detalle forense completo."""
        script = """
$tasks = Get-ScheduledTask | ForEach-Object {
    $task = $_
    $info = $null
    try { $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue } catch {}
    $actions = $task.Actions | ForEach-Object {
        @{ Type = $_.CieType; Execute = $_.Execute; Arguments = $_.Arguments; WorkingDir = $_.WorkingDirectory }
    }
    $triggers = $task.Triggers | ForEach-Object {
        @{ Type = $_.GetType().Name; Enabled = $_.Enabled }
    }
    @{
        TaskName       = $task.TaskName
        TaskPath       = $task.TaskPath
        State          = [string]$task.State
        Author         = $task.Author
        Date           = $task.Date
        Description    = $task.Description
        RunAsUser      = $task.Principal.UserId
        RunLevel       = [string]$task.Principal.RunLevel
        Actions        = $actions
        Triggers       = $triggers
        LastRunTime    = if ($info) { [string]$info.LastRunTime } else { $null }
        LastResult     = if ($info) { $info.LastTaskResult } else { $null }
        NextRunTime    = if ($info) { [string]$info.NextRunTime } else { $null }
        NumberOfMissed = if ($info) { $info.NumberOfMissedRuns } else { $null }
    }
}
$tasks | ConvertTo-Json -Depth 5
"""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True, text=True, timeout=90
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data or []
        except Exception as e:
            print(f"[ScheduledTasks] Error obteniendo tareas: {e}")
        return []

    # ── Análisis de tareas fuera del espacio Microsoft ─────────────

    def _analyze_non_microsoft_tasks(self, tasks: list[dict]):
        from core.audit_engine import AuditFinding

        non_ms = [
            t for t in tasks
            if not str(t.get("TaskPath", "")).startswith("\\Microsoft\\")
        ]

        if not non_ms:
            return

        # Enriquecer con info de firma
        enriched = []
        for task in non_ms:
            exe = self._extract_executable(task)
            signature = self._check_signature(exe) if exe else None
            action_details = self._extract_action_details(task)
            enriched.append({
                "name": task.get("TaskName"),
                "path": task.get("TaskPath"),
                "author": task.get("Author"),
                "created": task.get("Date"),
                "run_as": task.get("RunAsUser"),
                "run_level": task.get("RunLevel"),
                "state": task.get("State"),
                "executable": exe,
                "signature": signature,
                "last_run": task.get("LastRunTime"),
                "last_result": task.get("LastResult"),
                "next_run": task.get("NextRunTime"),
                "missed_runs": task.get("NumberOfMissed"),
                "actions": action_details,
            })

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_non_microsoft",
            title=f"Tareas programadas fuera del espacio Microsoft ({len(non_ms)})",
            description=(
                "Se han detectado tareas programadas no pertenecientes a Microsoft. "
                "Incluyen autor, fecha de creación, usuario de ejecución y estado de firma digital."
            ),
            risk_level="yellow",
            technical_risk=(
                "Las tareas de terceros se ejecutan periódicamente con los privilegios "
                "del usuario configurado. Pueden incluir software de monitorización, "
                "agentes de telemetría o herramientas de administración remota."
            ),
            legal_risk=(
                "Si alguna tarea ejecuta software de monitorización del trabajador "
                "sin información previa, puede vulnerar LOPDGDD art. 87 y ET art. 20bis."
            ),
            what_it_is=(
                "Tareas del Programador de tareas de Windows creadas por software "
                "instalado en el equipo, no por el propio sistema operativo."
            ),
            what_it_is_not=(
                "No toda tarea de terceros es vigilancia. Actualizadores de software, "
                "backups y mantenimiento de aplicaciones usan tareas programadas legítimamente."
            ),
            raw_data={"tasks": enriched, "total": len(non_ms)}
        ))

    # ── Tareas con indicadores de monitorización ───────────────────

    def _analyze_monitoring_tasks(self, tasks: list[dict]):
        from core.audit_engine import AuditFinding

        suspicious = []
        for task in tasks:
            name = str(task.get("TaskName", "")).lower()
            desc = str(task.get("Description", "")).lower()
            exe = self._extract_executable(task) or ""
            action_details = self._extract_action_details(task)
            action_text = " ".join(a.get("command_line", "") for a in action_details).lower()
            combined = name + " " + desc + " " + exe.lower() + " " + action_text

            if any(k in combined for k in self.MONITORING_KEYWORDS):
                suspicious.append({
                    "name": task.get("TaskName"),
                    "path": task.get("TaskPath"),
                    "author": task.get("Author"),
                    "created": task.get("Date"),
                    "run_as": task.get("RunAsUser"),
                    "executable": exe,
                    "actions": action_details,
                    "matched_keywords": [
                        k for k in self.MONITORING_KEYWORDS if k in combined
                    ],
                    "last_run": task.get("LastRunTime"),
                    "last_result": task.get("LastResult"),
                })

        if not suspicious:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_monitoring",
            title=f"Tareas con indicadores de monitorización ({len(suspicious)})",
            description=(
                "Tareas programadas con nombres, descripciones o ejecutables "
                "que contienen palabras clave asociadas a software de vigilancia."
            ),
            risk_level="orange",
            technical_risk=(
                "Estas tareas pueden ejecutar periódicamente agentes de monitorización, "
                "recolección de logs o envío de telemetría a servidores externos."
            ),
            legal_risk=(
                "La ejecución periódica de software de monitorización sin "
                "información previa puede vulnerar LOPDGDD art. 87, ET art. 20bis "
                "y la doctrina Barbulescu II del TEDH."
            ),
            what_it_is=(
                "Tareas cuyo nombre o ejecutable contienen términos asociados "
                "a monitorización, telemetría o vigilancia corporativa."
            ),
            what_it_is_not=(
                "No toda coincidencia implica espionaje. Muchas herramientas "
                "legítimas usan estos términos: antivirus, SIEM, auditoría de TI."
            ),
            raw_data={"suspicious_tasks": suspicious}
        ))

    # ── Tareas con intérpretes y argumentos potencialmente riesgosos ──────────

    def _analyze_interpreter_tasks(self, tasks: list[dict]):
        from core.audit_engine import AuditFinding

        risky = []
        for task in tasks:
            if str(task.get("TaskPath", "")).startswith("\\Microsoft\\"):
                continue

            actions = self._extract_action_details(task)
            risky_actions = [
                a for a in actions
                if a.get("is_interpreter") and a.get("suspicious_patterns")
            ]
            if not risky_actions:
                continue

            risky.append({
                "name": task.get("TaskName"),
                "path": task.get("TaskPath"),
                "author": task.get("Author"),
                "created": task.get("Date"),
                "run_as": task.get("RunAsUser"),
                "run_level": task.get("RunLevel"),
                "risky_actions": risky_actions,
                "last_run": task.get("LastRunTime"),
                "last_result": task.get("LastResult"),
            })

        if not risky:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_interpreters",
            title=(
                f"Tareas de terceros que usan intérpretes con argumentos sensibles ({len(risky)})"
            ),
            description=(
                "Se detectaron tareas que ejecutan intérpretes del sistema "
                "(PowerShell, cmd, wscript, etc.) con argumentos potencialmente "
                "sensibles (comandos codificados, descargas remotas o ejecución oculta)."
            ),
            risk_level="orange",
            technical_risk=(
                "El uso programado de intérpretes permite ejecutar scripts dinámicos "
                "más difíciles de auditar que binarios estáticos."
            ),
            legal_risk=(
                "Si esos scripts implementan observación del trabajador sin "
                "transparencia previa, puede haber impacto en LOPDGDD art. 87 "
                "y ET art. 20bis."
            ),
            what_it_is=(
                "Evidencia técnica de tareas no-Microsoft que usan intérpretes "
                "con patrones de argumento que merecen revisión forense."
            ),
            what_it_is_not=(
                "No implica por sí mismo malware o espionaje; muchos scripts "
                "administrativos corporativos usan intérpretes legítimamente."
            ),
            raw_data={"interpreter_tasks": risky}
        ))

    # ── Tareas creadas recientemente (últimas 72h) ─────────────────

    def _analyze_recent_tasks(self, tasks: list[dict]):
        from core.audit_engine import AuditFinding

        recent = []
        now = datetime.now()

        for task in tasks:
            date_str = task.get("Date") or ""
            if not date_str:
                continue
            try:
                # Formatos posibles: "2025-05-28T10:30:00" o "2025-05-28T10:30:00.0000000"
                created = datetime.fromisoformat(date_str[:19])
                delta = (now - created).total_seconds() / 3600
                if delta <= 72:
                    recent.append({
                        "name": task.get("TaskName"),
                        "path": task.get("TaskPath"),
                        "author": task.get("Author"),
                        "created": date_str,
                        "hours_ago": round(delta, 1),
                        "run_as": task.get("RunAsUser"),
                        "executable": self._extract_executable(task),
                    })
            except (ValueError, TypeError):
                pass

        if not recent:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_recent",
            title=f"Tareas programadas creadas en las últimas 72h ({len(recent)})",
            description=(
                "Se han detectado tareas programadas de reciente creación. "
                "Pueden ser evidencia de instalación reciente de software de monitorización."
            ),
            risk_level="orange",
            technical_risk=(
                "La creación reciente de tareas puede coincidir con instalación "
                "de agentes corporativos o software de monitorización. "
                "Es información forense relevante para establecer la línea temporal."
            ),
            legal_risk=(
                "Si la instalación es posterior a la relación laboral sin informar, "
                "puede constituir cambio unilateral de condiciones bajo LOPDGDD art. 87."
            ),
            what_it_is=(
                "Tareas creadas en las últimas 72 horas. Útil como evidencia "
                "forense para determinar cuándo se instaló software nuevo."
            ),
            what_it_is_not=(
                "No toda tarea reciente es problemática. Actualizaciones y "
                "software instalado recientemente también crea tareas."
            ),
            raw_data={"recent_tasks": recent}
        ))

    # ── Ejecutables sin firma digital ──────────────────────────────

    def _analyze_unsigned_executables(self, tasks: list[dict]):
        from core.audit_engine import AuditFinding

        unsigned = []
        seen = set()

        for task in tasks:
            # Solo tareas fuera del espacio Microsoft
            if str(task.get("TaskPath", "")).startswith("\\Microsoft\\"):
                continue

            exe = self._extract_executable(task)
            if not exe or exe in seen:
                continue
            seen.add(exe)

            sig = self._check_signature(exe)
            if sig and sig.get("status") not in ("Valid", "NotApplicable"):
                unsigned.append({
                    "task": task.get("TaskName"),
                    "executable": exe,
                    "signature_status": sig.get("status"),
                    "signer": sig.get("signer"),
                })

        if not unsigned:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_unsigned",
            title=f"Ejecutables de tareas sin firma digital válida ({len(unsigned)})",
            description=(
                "Tareas programadas que ejecutan binarios sin firma digital "
                "o con firma no válida. Mayor riesgo de software no autorizado."
            ),
            risk_level="orange",
            technical_risk=(
                "Los ejecutables sin firma no pueden ser verificados como "
                "software legítimo de un fabricante conocido. Pueden haber sido "
                "modificados o no provenir de un proveedor de software reconocido."
            ),
            legal_risk=(
                "Software de monitorización sin firma puede ser especialmente "
                "problemático: el empleador debe poder justificar la procedencia "
                "y función de cada herramienta de monitorización instalada."
            ),
            what_it_is=(
                "Ejecutables que arrancan periódicamente vía tareas programadas "
                "pero no tienen certificado de firma digital verificable."
            ),
            what_it_is_not=(
                "Algunos scripts legítimos (.ps1, .bat, .vbs) y "
                "software open-source no llevan firma digital."
            ),
            raw_data={"unsigned": unsigned}
        ))

    # ── Historial de ejecución con errores ─────────────────────────

    def _analyze_task_history(self, tasks: list[dict]):
        from core.audit_engine import AuditFinding

        failed = []
        very_active = []

        for task in tasks:
            if str(task.get("TaskPath", "")).startswith("\\Microsoft\\"):
                continue

            missed = task.get("NumberOfMissed")
            last_result = task.get("LastResult")

            # Código de error de Windows Task Scheduler (distinto de 0 = éxito o 267009 = running)
            if last_result is not None:
                try:
                    code = int(last_result)
                    if code not in (0, 267009, 267011):  # success, running, disabled
                        failed.append({
                            "task": task.get("TaskName"),
                            "path": task.get("TaskPath"),
                            "last_result_code": code,
                            "last_result_hex": hex(code & 0xFFFFFFFF),
                            "last_run": task.get("LastRunTime"),
                            "missed_runs": missed,
                        })
                except (TypeError, ValueError):
                    pass

        if not failed:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_errors",
            title=f"Tareas programadas con historial de errores ({len(failed)})",
            description=(
                "Tareas de terceros que han finalizado con códigos de error. "
                "Puede indicar software mal instalado, eliminado parcialmente "
                "o intentos de ejecución de software no disponible."
            ),
            risk_level="yellow",
            technical_risk=(
                "Las ejecuciones fallidas pueden indicar restos de software "
                "desinstalado que aún intenta ejecutarse periódicamente, "
                "o software instalado incorrectamente."
            ),
            legal_risk=(
                "Bajo, salvo que el software con errores sea un agente de "
                "monitorización cuya instalación no fue informada al trabajador."
            ),
            what_it_is=(
                "Tareas programadas cuya última ejecución terminó con un "
                "código de error distinto de cero (éxito)."
            ),
            what_it_is_not=(
                "No implica necesariamente software malicioso. "
                "Muchos instaladores dejan tareas obsoletas tras una desinstalación."
            ),
            raw_data={"failed_tasks": failed}
        ))

    # ── Utilidades ─────────────────────────────────────────────────

    def _extract_executable(self, task: dict) -> str | None:
        """Extrae el ejecutable principal de las acciones de la tarea."""
        actions = task.get("Actions") or []
        if isinstance(actions, dict):
            actions = [actions]
        for action in actions:
            exe = action.get("Execute") or ""
            if exe:
                return exe.strip('"').strip("'")
        return None

    def _extract_action_details(self, task: dict) -> list[dict]:
        """Normaliza acciones con command line completo y señales de riesgo."""
        actions = task.get("Actions") or []
        if isinstance(actions, dict):
            actions = [actions]

        details = []
        for action in actions:
            execute = str(action.get("Execute") or "").strip().strip('"').strip("'")
            arguments = str(action.get("Arguments") or "").strip()
            working_dir = str(action.get("WorkingDir") or "").strip()

            command_line = " ".join(part for part in [execute, arguments] if part).strip()
            basename = os.path.basename(execute).lower() if execute else ""
            is_interpreter = basename in self.INTERPRETER_EXECUTABLES

            suspicious_patterns = []
            lower_cmd = command_line.lower()
            for pattern in self.SUSPICIOUS_ARGUMENT_PATTERNS:
                if pattern in lower_cmd:
                    suspicious_patterns.append(pattern)

            details.append({
                "execute": execute,
                "arguments": arguments,
                "working_dir": working_dir,
                "command_line": command_line,
                "is_interpreter": is_interpreter,
                "interpreter": basename if is_interpreter else None,
                "suspicious_patterns": suspicious_patterns,
            })

        return details

    def _check_signature(self, exe_path: str) -> dict | None:
        """Verifica la firma digital de un ejecutable."""
        if not exe_path:
            return None
        # Solo verificar ficheros, no comandos del sistema
        if not any(exe_path.lower().endswith(ext) for ext in (".exe", ".dll", ".sys", ".ps1")):
            return None

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"$sig = Get-AuthenticodeSignature -FilePath '{exe_path}' -ErrorAction SilentlyContinue; "
                 f"if ($sig) {{ @{{ Status = [string]$sig.Status; Signer = $sig.SignerCertificate.Subject }} | ConvertTo-Json }} else {{ '{{\"Status\":\"NotFound\"}}' }}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                return {
                    "status": data.get("Status", "Unknown"),
                    "signer": data.get("Signer"),
                }
        except Exception:
            pass
        return {"status": "CheckFailed", "signer": None}
