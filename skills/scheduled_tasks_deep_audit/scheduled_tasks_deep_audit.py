# skills/scheduled_tasks_deep_audit/scheduled_tasks_deep_audit.py
"""
Skill — Scheduled Tasks Deep Audit
Auditoría forense profunda de tareas programadas.
Va más allá de la enumeración básica: verifica existencia de ejecutables,
detecta tareas protegidas, analiza creadores, horarios y patrones de riesgo.

Casos específicos documentados en investigación WorkDRAG:
- Tareas apuntando a rutas inexistentes (PaperQueen → C:\\pqtmp\\)
- Tareas protegidas inaccesibles a usuario estándar (npcapwatchdog)
- Tareas creadas en fechas correlacionadas con eventos de riesgo

Operación: solo lectura, sin elevación de privilegios.
Fuentes: Get-ScheduledTask, schtasks, registro, filesystem.
"""

import os
import re
import json
import hashlib
import datetime
import subprocess
import winreg
from pathlib import Path
from typing import Optional


# ── Configuración ─────────────────────────────────────────────────────────────

# Prefijos de tareas corporativas/sistema conocidas — no se alertan
KNOWN_SAFE_PREFIXES = [
    r"\Microsoft\\",
    r"\Microsoft\",
    r"Microsoft\",
]

KNOWN_SAFE_TASK_NAMES = {
    "adobe acrobat update task",
    "adobeaarmupdate",
    "git for windows updater",
    "user_feed_synchronization",
    "googleupdatetaskuser",
    "googleupdatetaskmachine",
    "ccleaner update",
    "dropbox update task",
    "onedrive per-machine startup task",
    "mozilla default browser agent",
}

# Nombres de tareas de monitorización conocidas
KNOWN_MONITORING_TASKS = {
    "npcapwatchdog": {
        "tool": "npcap",
        "risk": "orange",
        "note": "Watchdog para driver de captura de paquetes de red",
    },
    "nexthink": {
        "tool": "Nexthink Collector",
        "risk": "orange",
        "note": "Tarea de monitorización Nexthink",
    },
    "crowdstrike": {
        "tool": "CrowdStrike Falcon",
        "risk": "yellow",
        "note": "Tarea de actualización/mantenimiento CrowdStrike",
    },
    "zscaler": {
        "tool": "Zscaler",
        "risk": "yellow",
        "note": "Tarea de mantenimiento Zscaler",
    },
    "snow": {
        "tool": "Snow Inventory Agent",
        "risk": "yellow",
        "note": "Tarea de inventario Snow Software",
    },
    "logmein": {
        "tool": "LogMeIn Rescue",
        "risk": "orange",
        "note": "Tarea de LogMeIn Rescue",
    },
}

# Horario laboral — creación fuera de rango es señal
WORK_HOURS_START = 7
WORK_HOURS_END = 22
WORK_DAYS = [0, 1, 2, 3, 4]


# ── Utilidades ────────────────────────────────────────────────────────────────

def _ps(cmd: str, timeout: int = 20) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _file_exists(path_str: Optional[str]) -> bool:
    if not path_str:
        return False
    # Expandir variables de entorno
    try:
        expanded = os.path.expandvars(path_str.strip().strip('"'))
        return Path(expanded).exists()
    except Exception:
        return False


def _clean_path(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    return raw.strip().strip('"').strip()


def _is_unusual_time(dt: datetime.datetime) -> bool:
    if dt.weekday() >= 5:
        return True
    return dt.hour < WORK_HOURS_START or dt.hour >= WORK_HOURS_END


def _weekday_name(dt: datetime.datetime) -> str:
    return ["lunes", "martes", "miércoles", "jueves",
            "viernes", "sábado", "domingo"][dt.weekday()]


def _is_known_safe(task_name: str, task_path: str) -> bool:
    name_lower = task_name.lower()
    if name_lower in KNOWN_SAFE_TASK_NAMES:
        return True
    path_lower = task_path.lower()
    for prefix in KNOWN_SAFE_PREFIXES:
        if prefix.lower() in path_lower:
            return True
    return False


def _match_monitoring_tool(task_name: str) -> Optional[dict]:
    name_lower = task_name.lower()
    for keyword, info in KNOWN_MONITORING_TASKS.items():
        if keyword.lower() in name_lower:
            return info
    return None


# ── Recolección de tareas ─────────────────────────────────────────────────────

def _get_all_tasks_powershell() -> list[dict]:
    """
    Obtiene todas las tareas programadas via Get-ScheduledTask.
    Incluye acciones, triggers, estado y metadatos.
    """
    output = _ps(
        "Get-ScheduledTask | "
        "Select-Object TaskName, TaskPath, State, Description, "
        "@{N='Execute';E={if($_.Actions){$_.Actions[0].Execute}else{''}}}, "
        "@{N='Arguments';E={if($_.Actions){$_.Actions[0].Arguments}else{''}}}, "
        "@{N='WorkingDir';E={if($_.Actions){$_.Actions[0].WorkingDirectory}else{''}}}, "
        "@{N='TriggerStart';E={if($_.Triggers){$_.Triggers[0].StartBoundary}else{''}}}, "
        "@{N='TriggerType';E={if($_.Triggers){$_.Triggers[0].GetType().Name}else{''}}}, "
        "@{N='RunAs';E={$_.Principal.UserId}}, "
        "@{N='RunLevel';E={$_.Principal.RunLevel}} | "
        "ConvertTo-Json -Depth 3",
        timeout=30,
    )

    if not output:
        return []

    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data or []
    except Exception:
        return []


def _get_protected_tasks() -> list[str]:
    """
    Detecta tareas que existen pero no son accesibles al usuario actual.
    Usa schtasks que puede revelar tareas ocultas a Get-ScheduledTask.
    """
    protected = []

    # Intentar listar todas las tareas con schtasks
    try:
        r = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/nh"],
            capture_output=True, text=True, timeout=20
        )
        schtasks_names = set()
        for line in r.stdout.splitlines():
            parts = line.split(",")
            if parts:
                name = parts[0].strip().strip('"')
                if name:
                    schtasks_names.add(name.lower())
    except Exception:
        schtasks_names = set()

    # Comparar con las que Get-ScheduledTask devolvió
    # Las que están en schtasks pero no en PS son candidatas protegidas
    # (esto se hace en el análisis posterior)
    return list(schtasks_names)


def _probe_task_protection(task_name: str) -> bool:
    """
    Verifica si una tarea específica está protegida (acceso denegado).
    """
    output = _ps(
        f"schtasks /query /fo LIST /v /tn '{task_name}' 2>&1"
    )
    return (
        "acceso denegado" in output.lower() or
        "access denied" in output.lower()
    )


def _get_task_from_xml(task_name: str, task_path: str) -> Optional[dict]:
    """
    Intenta leer la definición XML de una tarea directamente desde disco.
    Solo funciona para tareas en C:\\Windows\\System32\\Tasks\\.
    """
    # Construir ruta del archivo XML
    xml_base = Path(r"C:\Windows\System32\Tasks")
    task_path_clean = task_path.strip("\\").replace("\\", os.sep)
    xml_file = xml_base / task_path_clean / task_name

    if not xml_file.exists():
        # Intentar directamente con el nombre
        xml_file = xml_base / task_name
        if not xml_file.exists():
            return None

    try:
        content = xml_file.read_text(encoding="utf-8", errors="replace")
        return {
            "xml_path": str(xml_file),
            "xml_size": xml_file.stat().st_size,
            "xml_modified": datetime.datetime.fromtimestamp(
                xml_file.stat().st_mtime
            ).isoformat(),
            "xml_created": datetime.datetime.fromtimestamp(
                xml_file.stat().st_ctime
            ).isoformat(),
            "sha256": _hash_file(xml_file),
            # Extraer fecha de creación del XML si está disponible
            "date_from_xml": _extract_date_from_xml(content),
        }
    except Exception:
        return None


def _extract_date_from_xml(xml_content: str) -> Optional[str]:
    """Extrae la fecha de registro de la tarea desde el XML."""
    match = re.search(r"<Date>([^<]+)</Date>", xml_content)
    if match:
        return match.group(1).strip()
    match = re.search(r"<RegistrationInfo>.*?<Date>([^<]+)</Date>",
                      xml_content, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def _hash_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# ── Análisis de tareas ────────────────────────────────────────────────────────

def _analyze_task(task: dict) -> dict:
    """
    Analiza una tarea y devuelve un objeto enriquecido con flags y riesgo.
    """
    name = str(task.get("TaskName", "") or "")
    path = str(task.get("TaskPath", "") or "")
    state = str(task.get("State", "") or "")
    execute = _clean_path(str(task.get("Execute", "") or ""))
    arguments = str(task.get("Arguments", "") or "")
    working_dir = _clean_path(str(task.get("WorkingDir", "") or ""))
    trigger_start = str(task.get("TriggerStart", "") or "")
    trigger_type = str(task.get("TriggerType", "") or "")
    run_as = str(task.get("RunAs", "") or "")
    run_level = str(task.get("RunLevel", "") or "")
    description = str(task.get("Description", "") or "")

    flags = []
    risk = "green"

    # ── Verificar si el ejecutable existe ──────────────────────────────────
    execute_exists = None
    if execute:
        execute_exists = _file_exists(execute)
        if not execute_exists:
            flags.append(
                f"ejecutable_no_existe: '{execute}'"
            )
            risk = "orange"

    # Verificar working directory si existe
    if working_dir:
        if not _file_exists(working_dir):
            flags.append(
                f"directorio_trabajo_no_existe: '{working_dir}'"
            )

    # ── Detectar herramienta de monitorización conocida ────────────────────
    monitoring_info = _match_monitoring_tool(name)
    if monitoring_info:
        flags.append(
            f"tarea_monitorización: {monitoring_info['tool']} — "
            f"{monitoring_info['note']}"
        )
        tool_risk = monitoring_info["risk"]
        risk_order = {"green": 0, "yellow": 1, "orange": 2, "red": 3}
        if risk_order.get(tool_risk, 0) > risk_order.get(risk, 0):
            risk = tool_risk

    # ── Analizar Run Level (privilegios elevados) ──────────────────────────
    if "highest" in run_level.lower() or run_level == "1":
        flags.append("ejecuta_con_privilegios_maximos")
        if risk == "green":
            risk = "yellow"

    # ── Analizar Run As ────────────────────────────────────────────────────
    if run_as:
        run_as_lower = run_as.lower()
        if "system" in run_as_lower:
            flags.append("ejecuta_como_system")
            if risk in ("green", "yellow"):
                risk = "yellow"
        elif "admin" in run_as_lower or "emeal-it" in run_as_lower \
                or "local-admin" in run_as_lower:
            flags.append(f"ejecuta_como_cuenta_admin: {run_as}")
            if risk in ("green", "yellow"):
                risk = "orange"

    # ── Analizar trigger/horario ───────────────────────────────────────────
    trigger_dt = None
    unusual_trigger = False
    if trigger_start:
        try:
            # Parsear formato ISO con posible timezone
            ts_clean = re.sub(r"[+-]\d{2}:\d{2}$", "", trigger_start)
            trigger_dt = datetime.datetime.fromisoformat(ts_clean)
            if _is_unusual_time(trigger_dt):
                unusual_trigger = True
                flags.append(
                    f"trigger_horario_inusual: "
                    f"{_weekday_name(trigger_dt)} "
                    f"{trigger_dt.strftime('%Y-%m-%d %H:%M')}"
                )
        except Exception:
            pass

    # ── Analizar argumentos sospechosos ───────────────────────────────────
    if arguments:
        args_lower = arguments.lower()
        suspicious_args = []
        if "-enc" in args_lower or "-encodedcommand" in args_lower:
            suspicious_args.append("comando_codificado_base64")
        if "bypass" in args_lower:
            suspicious_args.append("bypass_politica_ejecucion")
        if "hidden" in args_lower or "-windowstyle hidden" in args_lower:
            suspicious_args.append("ventana_oculta")
        if "downloadstring" in args_lower or "invoke-webrequest" in args_lower:
            suspicious_args.append("descarga_desde_red")
        if suspicious_args:
            for s in suspicious_args:
                flags.append(f"argumento_sospechoso: {s}")
            risk = "red"

    # ── Leer XML de la tarea para obtener fecha de creación ───────────────
    xml_info = _get_task_from_xml(name, path)

    # Determinar fecha de creación más precisa
    creation_date = None
    if xml_info and xml_info.get("date_from_xml"):
        creation_date = xml_info["date_from_xml"]
    elif xml_info and xml_info.get("xml_created"):
        creation_date = xml_info["xml_created"]

    return {
        "name": name,
        "path": path,
        "state": state,
        "execute": execute,
        "execute_exists": execute_exists,
        "arguments": arguments,
        "working_dir": working_dir,
        "trigger_start": trigger_start,
        "trigger_type": trigger_type,
        "run_as": run_as,
        "run_level": run_level,
        "description": description,
        "flags": flags,
        "risk": risk,
        "monitoring_info": monitoring_info,
        "unusual_trigger": unusual_trigger,
        "creation_date": creation_date,
        "xml_info": xml_info,
    }


# ── Skill principal ───────────────────────────────────────────────────────────

class ScheduledTasksDeepAudit:
    SKILL_NAME = "scheduled_tasks_deep_audit"

    def __init__(self, engine):
        self.engine = engine
        self.all_tasks = []
        self.non_microsoft_tasks = []
        self.anomalous_tasks = []
        self.protected_tasks = []
        self.monitoring_tasks = []

    def run(self):
        print("[TasksDeep] Iniciando auditoría profunda de tareas programadas...")

        # Recopilar tareas
        raw_tasks = _get_all_tasks_powershell()
        print(f"[TasksDeep] Tareas encontradas: {len(raw_tasks)}")

        # Filtrar y analizar tareas no-Microsoft
        for task in raw_tasks:
            name = str(task.get("TaskName", "") or "")
            path = str(task.get("TaskPath", "") or "")

            if _is_known_safe(name, path):
                continue

            analyzed = _analyze_task(task)
            self.non_microsoft_tasks.append(analyzed)

            if analyzed["flags"]:
                self.anomalous_tasks.append(analyzed)
            if analyzed["monitoring_info"]:
                self.monitoring_tasks.append(analyzed)

        print(
            f"[TasksDeep] No-Microsoft: {len(self.non_microsoft_tasks)} | "
            f"Con anomalías: {len(self.anomalous_tasks)} | "
            f"Monitorización: {len(self.monitoring_tasks)}"
        )

        # Detectar tareas protegidas
        self._detect_protected_tasks()

        # Generar hallazgos
        self._report_missing_executables()
        self._report_monitoring_tasks()
        self._report_protected_tasks()
        self._report_high_privilege_tasks()
        self._report_general_non_microsoft()

        print(
            f"[TasksDeep] Completado — "
            f"{len(self.non_microsoft_tasks)} tareas no-Microsoft auditadas"
        )

    def _detect_protected_tasks(self):
        """
        Detecta tareas que existen pero no son accesibles al usuario estándar.
        """
        # Lista de tareas conocidas que suelen estar protegidas
        candidates = [
            "npcapwatchdog",
            "CsInstallService",
        ]

        for task_name in candidates:
            if _probe_task_protection(task_name):
                self.protected_tasks.append({
                    "name": task_name,
                    "protected": True,
                    "accessible": False,
                })
                print(f"[TasksDeep] Tarea protegida detectada: {task_name}")

    # ── Hallazgos ──────────────────────────────────────────────────────────────

    def _report_missing_executables(self):
        """Hallazgo: tareas que apuntan a ejecutables o rutas inexistentes."""
        from core.audit_engine import AuditFinding

        missing = [
            t for t in self.non_microsoft_tasks
            if t["execute_exists"] is False
        ]

        if not missing:
            return

        task_list = []
        for t in missing:
            task_list.append({
                "name": t["name"],
                "execute": t["execute"],
                "working_dir": t["working_dir"],
                "trigger_start": t["trigger_start"],
                "creation_date": t["creation_date"],
                "flags": t["flags"],
                "run_as": t["run_as"],
            })

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_missing_executable",
            title=(
                f"{len(missing)} tarea(s) programada(s) apuntando a "
                "ejecutables o rutas inexistentes"
            ),
            description=(
                f"Se han detectado {len(missing)} tarea(s) programada(s) "
                "que referencian ejecutables o directorios que no existen "
                "en disco. Esto puede indicar herramientas desinstaladas "
                "sin limpiar sus tareas, software que crea rutas dinámicas, "
                "o tareas configuradas para futura activación. "
                f"Tareas afectadas: "
                f"{', '.join(t['name'] for t in missing)}."
            ),
            risk_level="orange",
            technical_risk=(
                "Una tarea con ejecutable inexistente puede activarse cuando "
                "la ruta sea creada — por instalación de software, "
                "por acción remota o por script. "
                "Si la ruta es creada por un agente externo, la tarea se "
                "ejecuta automáticamente sin intervención adicional."
            ),
            legal_risk=(
                "Tareas sin ejecutable identificable dificultan la auditoría "
                "forense y no permiten determinar la finalidad del tratamiento. "
                "El responsable del tratamiento debe poder explicar la "
                "existencia y propósito de cada tarea programada en el equipo "
                "del trabajador — RGPD art. 5.1.a (transparencia)."
            ),
            what_it_is=(
                "Tareas programadas de Windows que están configuradas para "
                "ejecutar un archivo o script que actualmente no existe en "
                "el sistema de archivos."
            ),
            what_it_is_not=(
                "No implica necesariamente actividad maliciosa. Puede ser "
                "software desinstalado sin limpiar sus tareas, o herramientas "
                "que crean sus archivos en el momento de ejecutarse."
            ),
            raw_data={
                "missing_executable_tasks": task_list,
                "count": len(missing),
            },
        ))

    def _report_monitoring_tasks(self):
        """Hallazgo: tareas de herramientas de monitorización conocidas."""
        from core.audit_engine import AuditFinding

        if not self.monitoring_tasks:
            return

        # Agrupar por herramienta
        by_tool = {}
        for t in self.monitoring_tasks:
            tool = t["monitoring_info"]["tool"]
            if tool not in by_tool:
                by_tool[tool] = []
            by_tool[tool].append(t)

        for tool_name, tasks in by_tool.items():
            risk = max(
                (t["monitoring_info"]["risk"] for t in tasks),
                key=lambda r: {"green": 0, "yellow": 1,
                               "orange": 2, "red": 3}.get(r, 0),
                default="yellow"
            )

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="scheduled_tasks_monitoring_tool",
                title=(
                    f"Tarea programada de monitorización: {tool_name} "
                    f"({len(tasks)} tarea(s))"
                ),
                description=(
                    f"Se han detectado {len(tasks)} tarea(s) programada(s) "
                    f"asociada(s) a '{tool_name}'. "
                    f"{tasks[0]['monitoring_info']['note']}."
                ),
                risk_level=risk,
                technical_risk=(
                    f"Las tareas de '{tool_name}' garantizan la persistencia "
                    "y funcionamiento continuo del agente de monitorización, "
                    "incluso tras reinicios del sistema."
                ),
                legal_risk=(
                    f"La persistencia de '{tool_name}' mediante tareas "
                    "programadas confirma que la monitorización es continua "
                    "y no puntual. Su base legal debe estar documentada "
                    "y comunicada al trabajador — "
                    "RGPD art. 13, LOPDGDD art. 87."
                ),
                what_it_is=(
                    f"Tarea programada que mantiene activo el agente "
                    f"'{tool_name}' en el equipo."
                ),
                what_it_is_not=(
                    "No es por sí sola prueba de uso indebido. "
                    "Es evidencia de persistencia planificada del agente."
                ),
                raw_data={
                    "tool": tool_name,
                    "tasks": [
                        {
                            "name": t["name"],
                            "execute": t["execute"],
                            "state": t["state"],
                            "run_as": t["run_as"],
                            "creation_date": t["creation_date"],
                            "flags": t["flags"],
                        }
                        for t in tasks
                    ],
                },
            ))

    def _report_protected_tasks(self):
        """Hallazgo: tareas protegidas inaccesibles al usuario estándar."""
        from core.audit_engine import AuditFinding

        if not self.protected_tasks:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_protected",
            title=(
                f"{len(self.protected_tasks)} tarea(s) programada(s) "
                "protegida(s) — acceso denegado a usuario estándar"
            ),
            description=(
                f"Se han detectado {len(self.protected_tasks)} tarea(s) "
                "programada(s) cuya configuración completa no es accesible "
                "al usuario estándar. El sistema confirma su existencia pero "
                "deniega el acceso para leer sus detalles. "
                f"Tareas: {', '.join(t['name'] for t in self.protected_tasks)}."
            ),
            risk_level="orange",
            technical_risk=(
                "Una tarea programada protegida puede ejecutar código con "
                "cualquier privilegio sin que el usuario del equipo pueda "
                "auditar su contenido, horario o ejecutable. "
                "Esto crea un punto ciego forense en la auditoría."
            ),
            legal_risk=(
                "La existencia de tareas programadas cuyo contenido no puede "
                "ser auditado por el trabajador es relevante bajo el principio "
                "de transparencia del RGPD art. 5.1.a. "
                "El responsable del tratamiento debe poder documentar y "
                "justificar la finalidad de cada tarea en el equipo."
            ),
            what_it_is=(
                "Tareas programadas de Windows configuradas con descriptores "
                "de seguridad que impiden su lectura por cuentas sin "
                "privilegios administrativos."
            ),
            what_it_is_not=(
                "No implica actividad maliciosa. Algunas herramientas de "
                "seguridad protegen sus tareas para evitar manipulación. "
                "Pero sí impide auditoría independiente por el trabajador."
            ),
            raw_data={
                "protected_tasks": self.protected_tasks,
                "count": len(self.protected_tasks),
            },
        ))

    def _report_high_privilege_tasks(self):
        """Hallazgo: tareas que se ejecutan con privilegios elevados."""
        from core.audit_engine import AuditFinding

        high_priv = [
            t for t in self.non_microsoft_tasks
            if any(
                "privilegios_max" in f or "cuenta_admin" in f or
                "como_system" in f
                for f in t["flags"]
            )
        ]

        if not high_priv:
            return

        # Excluir las que ya están en monitoring_tasks para no duplicar
        monitoring_names = {t["name"] for t in self.monitoring_tasks}
        high_priv_new = [
            t for t in high_priv
            if t["name"] not in monitoring_names
        ]

        if not high_priv_new:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_high_privilege",
            title=(
                f"{len(high_priv_new)} tarea(s) no-Microsoft con "
                "ejecución privilegiada (SYSTEM / admin)"
            ),
            description=(
                f"Se han detectado {len(high_priv_new)} tarea(s) "
                "programada(s) no estándar que se ejecutan con privilegios "
                "elevados (SYSTEM o cuenta administradora). "
                f"Tareas: "
                f"{', '.join(t['name'] for t in high_priv_new[:5])}."
            ),
            risk_level="orange",
            technical_risk=(
                "Las tareas que se ejecutan como SYSTEM o con privilegios "
                "máximos pueden modificar cualquier parte del sistema sin "
                "restricción. Si son ejecutadas por software de terceros, "
                "amplían significativamente la superficie de acceso al equipo."
            ),
            legal_risk=(
                "Tareas privilegiadas de terceros en el equipo de un "
                "trabajador requieren justificación explícita — "
                "RGPD art. 32 (seguridad del tratamiento), "
                "LOPDGDD art. 87."
            ),
            what_it_is=(
                "Tareas programadas de software no-Microsoft configuradas "
                "para ejecutarse con los máximos privilegios del sistema."
            ),
            what_it_is_not=(
                "No implica uso malicioso. Muchas herramientas legítimas "
                "requieren privilegios elevados para operar. "
                "Requieren revisión y justificación documentada."
            ),
            raw_data={
                "high_privilege_tasks": [
                    {
                        "name": t["name"],
                        "execute": t["execute"],
                        "run_as": t["run_as"],
                        "run_level": t["run_level"],
                        "flags": t["flags"],
                        "creation_date": t["creation_date"],
                    }
                    for t in high_priv_new
                ],
            },
        ))

    def _report_general_non_microsoft(self):
        """
        Hallazgo de resumen: todas las tareas no-Microsoft encontradas.
        Solo si hay alguna que no haya sido cubierta por hallazgos anteriores.
        """
        from core.audit_engine import AuditFinding

        # Solo incluir las que no tienen flags (las con flags ya tienen hallazgo)
        clean_tasks = [
            t for t in self.non_microsoft_tasks
            if not t["flags"] and not t["monitoring_info"]
        ]

        if not clean_tasks:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="scheduled_tasks_non_microsoft_inventory",
            title=(
                f"Inventario: {len(clean_tasks)} tarea(s) programada(s) "
                "no-Microsoft sin anomalías detectadas"
            ),
            description=(
                f"Se han documentado {len(clean_tasks)} tarea(s) "
                "programada(s) de software no-Microsoft para las que no "
                "se han detectado anomalías específicas. "
                "Se incluyen en el informe por completitud forense."
            ),
            risk_level="yellow",
            technical_risk=(
                "Cualquier tarea programada de terceros tiene capacidad de "
                "ejecutar código en el equipo de forma autónoma. "
                "La ausencia de anomalías no garantiza que sean inocuas."
            ),
            legal_risk=(
                "El inventario completo de tareas programadas es parte "
                "del mapa de tratamientos requerido por RGPD art. 30."
            ),
            what_it_is=(
                "Inventario forense de tareas programadas activas en el "
                "equipo que no pertenecen a componentes estándar de Windows."
            ),
            what_it_is_not=(
                "No es un hallazgo de riesgo inmediato. Es documentación "
                "de la superficie de ejecución autónoma del equipo."
            ),
            raw_data={
                "tasks": [
                    {
                        "name": t["name"],
                        "path": t["path"],
                        "execute": t["execute"],
                        "execute_exists": t["execute_exists"],
                        "state": t["state"],
                        "run_as": t["run_as"],
                        "trigger_start": t["trigger_start"],
                        "creation_date": t["creation_date"],
                    }
                    for t in clean_tasks
                ],
                "count": len(clean_tasks),
            },
        ))