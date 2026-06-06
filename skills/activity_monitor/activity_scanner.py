# skills/activity_monitor/activity_scanner.py
"""
Skill — Background Activity Monitor
Detecta actividad persistente, cambios recientes y
patrones de comportamiento sospechoso en segundo plano
"""

import psutil
import subprocess
import json
import datetime
from pathlib import Path


# Procesos con alta CPU sostenida que pueden indicar análisis
CPU_THRESHOLD = 15.0  # % CPU sostenido
MEM_THRESHOLD = 200   # MB

# Procesos de sistema legítimos a ignorar
SYSTEM_PROCESSES = {
    "system", "svchost.exe", "lsass.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe",
    "smss.exe", "registry", "memory compression",
    "antimalware service executable", "windows defender",
}

# Eventos de Windows relevantes para auditoría
SECURITY_EVENT_IDS = {
    4624: "Inicio de sesión exitoso",
    4625: "Inicio de sesión fallido",
    4648: "Inicio de sesión con credenciales explícitas",
    4688: "Nuevo proceso creado",
    4689: "Proceso terminado",
    4698: "Tarea programada creada",
    4702: "Tarea programada modificada",
    4719: "Política de auditoría cambiada",
    7045: "Nuevo servicio instalado",
    4657: "Valor de registro modificado",
}

class ActivityMonitor:
    SKILL_NAME = "activity_monitor"

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[Activity] Iniciando monitor de actividad...")
        self._check_high_resource_processes()
        self._check_recent_security_events()
        self._check_new_services()
        self._check_autostart_changes()
        self._check_background_data_senders()

    # ── Procesos con alto consumo ──────────────────────────────────

    def _check_high_resource_processes(self):
        from core.audit_engine import AuditFinding

        suspicious = []

        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_info",
             "create_time", "exe", "username"]
        ):
            try:
                name = proc.info["name"].lower()
                if any(s in name for s in SYSTEM_PROCESSES):
                    continue

                cpu   = proc.cpu_percent(interval=0.1)
                mem   = (proc.info["memory_info"].rss / 1024 / 1024
                         if proc.info["memory_info"] else 0)

                if cpu > CPU_THRESHOLD or mem > MEM_THRESHOLD:
                    suspicious.append({
                        "pid":      proc.info["pid"],
                        "name":     proc.info["name"],
                        "cpu_pct":  round(cpu, 1),
                        "mem_mb":   round(mem, 1),
                        "exe":      proc.info.get("exe", ""),
                        "user":     proc.info.get("username", ""),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        if suspicious:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="activity_resources",
                title=f"Procesos con alto consumo de recursos "
                      f"({len(suspicious)} detectados)",
                description=(
                    "Se han encontrado procesos con consumo elevado "
                    "sostenido de CPU o memoria que pueden estar "
                    "realizando análisis o transmisión de datos."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Los procesos con alto consumo pueden estar "
                    "procesando o transmitiendo grandes volúmenes "
                    "de datos del sistema."
                ),
                legal_risk=(
                    "Por sí solo no implica ilegalidad. "
                    "Requiere identificación del proceso."
                ),
                what_it_is=(
                    "Procesos que consumen más recursos de lo normal, "
                    "lo que puede indicar actividad de análisis en segundo plano."
                ),
                what_it_is_not=(
                    "Puede ser actividad legítima: compilaciones, "
                    "antivirus escaneando, actualizaciones, backups."
                ),
                raw_data={"processes": suspicious[:15]}
            ))

    # ── Eventos de seguridad recientes ────────────────────────────

    def _check_recent_security_events(self):
        from core.audit_engine import AuditFinding

        events_found = {}
        hours_back = 24

        for event_id, description in SECURITY_EVENT_IDS.items():
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"$since = (Get-Date).AddHours(-{hours_back}); "
                     f"$events = Get-WinEvent -FilterHashtable "
                     f"@{{LogName='Security'; Id={event_id}; "
                     f"StartTime=$since}} -ErrorAction SilentlyContinue "
                     f"-MaxEvents 5; "
                     f"if ($events) {{ $events | Select-Object TimeCreated, "
                     f"Message | ConvertTo-Json -Depth 1 }}"],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    data = json.loads(result.stdout)
                    if data:
                        if isinstance(data, dict):
                            data = [data]
                        events_found[event_id] = {
                            "description": description,
                            "count": len(data),
                            "latest": data[0].get("TimeCreated", "")
                        }
            except Exception:
                pass

        # Eventos críticos que siempre reportamos
        critical_ids = {4698, 4702, 7045, 4719}
        critical_found = {
            k: v for k, v in events_found.items()
            if k in critical_ids
        }

        if critical_found:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="activity_security_events",
                title=f"Eventos de seguridad críticos en las últimas "
                      f"{hours_back}h ({len(critical_found)} tipos)",
                description=(
                    "Se han encontrado eventos de seguridad relevantes "
                    "en el log de Windows que indican cambios en la "
                    "configuración del sistema."
                ),
                risk_level="orange",
                technical_risk=(
                    "Eventos como creación de tareas, instalación de "
                    "servicios o cambios de política pueden indicar "
                    "modificaciones recientes de la infraestructura."
                ),
                legal_risk=(
                    "Los cambios recientes en configuración son "
                    "relevantes para documentar el estado del sistema "
                    "en el momento de la auditoría."
                ),
                what_it_is=(
                    "Eventos del log de seguridad de Windows que registran "
                    "cambios importantes en la configuración del sistema."
                ),
                what_it_is_not=(
                    "No todos los eventos son maliciosos. "
                    "Actualizaciones y configuraciones rutinarias "
                    "también generan estos eventos."
                ),
                raw_data={"critical_events": critical_found,
                          "all_events": events_found}
            ))

        if events_found:
            print(
                f"[Activity] Eventos de seguridad encontrados: "
                f"{list(events_found.keys())}"
            )

    # ── Servicios recientes ────────────────────────────────────────

    def _check_new_services(self):
        from core.audit_engine import AuditFinding

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "$since = (Get-Date).AddDays(-7); "
                 "Get-WinEvent -FilterHashtable "
                 "@{LogName='System'; Id=7045; StartTime=$since} "
                 "-ErrorAction SilentlyContinue -MaxEvents 20 | "
                 "Select-Object TimeCreated, Message | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                events = json.loads(result.stdout)
                if isinstance(events, dict):
                    events = [events]
                if events:
                    self.engine.add_finding(AuditFinding(
                        skill=self.SKILL_NAME,
                        category="activity_new_services",
                        title=f"Servicios instalados en los últimos 7 días "
                              f"({len(events)})",
                        description=(
                            "Se han instalado nuevos servicios de Windows "
                            "recientemente."
                        ),
                        risk_level="yellow",
                        technical_risk=(
                            "Los servicios nuevos pueden incluir agentes "
                            "de monitorización instalados recientemente."
                        ),
                        legal_risk=(
                            "Documentar servicios instalados recientemente "
                            "es relevante para establecer el momento de "
                            "implantación de herramientas de vigilancia."
                        ),
                        what_it_is=(
                            "Registro de servicios de Windows instalados "
                            "en la última semana."
                        ),
                        what_it_is_not=(
                            "Puede ser actualizaciones de Windows, "
                            "software corporativo estándar o drivers."
                        ),
                        raw_data={"new_services": [
                            {"time": e.get("TimeCreated"),
                             "message": str(e.get("Message", ""))[:200]}
                            for e in events
                        ]}
                    ))
        except Exception as e:
            print(f"[Activity] Error leyendo servicios nuevos: {e}")

    # ── Cambios en autostart ───────────────────────────────────────

    def _check_autostart_changes(self):
        from core.audit_engine import AuditFinding

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "$since = (Get-Date).AddDays(-7); "
                 "Get-WinEvent -FilterHashtable "
                 "@{LogName='Security'; Id=4657; StartTime=$since} "
                 "-ErrorAction SilentlyContinue -MaxEvents 10 | "
                 "Where-Object {$_.Message -like '*Run*'} | "
                 "Select-Object TimeCreated, Message | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                events = json.loads(result.stdout)
                if isinstance(events, dict):
                    events = [events]
                if events:
                    self.engine.add_finding(AuditFinding(
                        skill=self.SKILL_NAME,
                        category="activity_autostart_changes",
                        title=f"Cambios en claves de autostart detectados "
                              f"({len(events)} en 7 días)",
                        description=(
                            "Se han modificado claves de registro de "
                            "inicio automático recientemente."
                        ),
                        risk_level="orange",
                        technical_risk=(
                            "Los cambios en autostart indican que se ha "
                            "añadido o modificado software que se ejecuta "
                            "automáticamente al inicio de sesión."
                        ),
                        legal_risk=(
                            "Cambios recientes en autostart son evidencia "
                            "forense relevante sobre cuándo se instaló "
                            "un posible software de monitorización."
                        ),
                        what_it_is=(
                            "Modificaciones en las claves de registro que "
                            "controlan qué programas se inician "
                            "automáticamente."
                        ),
                        what_it_is_not=(
                            "Muchas actualizaciones de software legítimo "
                            "modifican estas claves."
                        ),
                        raw_data={"changes": [
                            {"time": e.get("TimeCreated"),
                             "detail": str(e.get("Message",""))[:300]}
                            for e in events
                        ]}
                    ))
        except Exception as e:
            print(f"[Activity] Error leyendo cambios autostart: {e}")

    # ── Procesos enviando datos ────────────────────────────────────

    def _check_background_data_senders(self):
        from core.audit_engine import AuditFinding

        senders = []
        try:
            conns_by_pid = {}
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED" and conn.pid:
                    if conn.pid not in conns_by_pid:
                        conns_by_pid[conn.pid] = 0
                    conns_by_pid[conn.pid] += 1

            # Procesos con múltiples conexiones salientes
            for pid, count in conns_by_pid.items():
                if count >= 3:
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name().lower()
                        if not any(s in name for s in SYSTEM_PROCESSES):
                            senders.append({
                                "pid": pid,
                                "name": proc.name(),
                                "connections": count,
                                "exe": proc.exe() if hasattr(proc, 'exe') else ""
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception as e:
            print(f"[Activity] Error analizando conexiones: {e}")

        if senders:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="activity_data_senders",
                title=f"Procesos con múltiples conexiones salientes "
                      f"({len(senders)})",
                description=(
                    "Procesos no-sistema con 3 o más conexiones "
                    "salientes simultáneas activas."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Múltiples conexiones simultáneas pueden indicar "
                    "envío de datos a varios servidores en paralelo."
                ),
                legal_risk=(
                    "Requiere identificación de los procesos y sus destinos "
                    "para evaluar el riesgo real."
                ),
                what_it_is=(
                    "Procesos que mantienen varias conexiones de red "
                    "abiertas simultáneamente."
                ),
                what_it_is_not=(
                    "Navegadores y aplicaciones modernas mantienen "
                    "múltiples conexiones por diseño."
                ),
                raw_data={"senders": senders}
            ))

        print(f"[Activity] Completado")