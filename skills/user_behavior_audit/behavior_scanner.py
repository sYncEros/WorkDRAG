# skills/user_behavior_audit/behavior_scanner.py
"""
Skill — Análisis de Comportamiento de Usuario
Detecta qué datos de comportamiento puede estar recopilando el sistema:
patrones de inicio/cierre de sesión, acceso a recursos sensibles,
uso de herramientas de administración, y qué nivel de perfilado
es técnicamente posible a partir de los logs locales.
"""

import subprocess
import json
import winreg
from datetime import datetime, timedelta


class UserBehaviorAudit:
    SKILL_NAME = "user_behavior_audit"

    # Eventos de Windows que registran comportamiento de usuario
    BEHAVIOR_EVENT_IDS = {
        4624: "Inicio de sesión exitoso",
        4625: "Intento de inicio de sesión fallido",
        4634: "Cierre de sesión",
        4647: "Cierre de sesión iniciado por usuario",
        4648: "Inicio de sesión con credenciales explícitas",
        4656: "Intento de acceso a objeto",
        4663: "Acceso a objeto (archivo/carpeta)",
        4688: "Proceso creado",
        4698: "Tarea programada creada",
        4702: "Tarea programada modificada",
    }

    # Herramientas administrativas cuyo uso puede ser registrado
    ADMIN_TOOLS = [
        "powershell", "cmd", "wmic", "net.exe", "netstat",
        "reg.exe", "regedit", "taskmgr", "mmc", "gpedit",
        "eventvwr", "secpol", "lusrmgr", "compmgmt",
        "whoami", "ipconfig", "nslookup", "tracert",
        "robocopy", "xcopy", "sfc", "dism", "cipher"
    ]

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[UserBehavior] Iniciando análisis de comportamiento de usuario...")
        self._analyze_logon_patterns()
        self._analyze_process_audit_policy()
        self._analyze_object_access_audit()
        self._analyze_behavior_monitoring_software()
        self._analyze_activity_logging_capabilities()
        print("[UserBehavior] Completado.")

    # ── Patrones de inicio de sesión ───────────────────────────────

    def _analyze_logon_patterns(self):
        from core.audit_engine import AuditFinding

        script = """
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4624,4634,4647,4625; MaxEvents=200
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = @{}
    $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
    @{
        EventId   = $_.Id
        TimeCreated = [string]$_.TimeCreated
        LogonType = $data['LogonType']
        WorkstationName = $data['WorkstationName']
        IpAddress = $data['IpAddress']
        SubjectUserName = $data['SubjectUserName']
        TargetUserName  = $data['TargetUserName']
    }
}
$events | ConvertTo-Json -Depth 3
"""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True, text=True, timeout=45
            )
            if result.returncode != 0 or not result.stdout.strip():
                return

            events = json.loads(result.stdout)
            if isinstance(events, dict):
                events = [events]

            if not events:
                return

            # Analizar horarios de inicio de sesión
            logon_times = []
            failed_logons = []
            remote_logons = []

            for ev in events:
                time_str = ev.get("TimeCreated", "")
                event_id = ev.get("EventId")
                logon_type = str(ev.get("LogonType") or "")
                ip = ev.get("IpAddress") or ""

                if event_id == 4625:
                    failed_logons.append({
                        "time": time_str,
                        "user": ev.get("TargetUserName"),
                        "workstation": ev.get("WorkstationName"),
                        "ip": ip,
                    })

                # Tipo 10 = RemoteInteractive (RDP)
                if logon_type == "10" and ip and ip not in ("-", "::1", "127.0.0.1"):
                    remote_logons.append({
                        "time": time_str,
                        "user": ev.get("TargetUserName"),
                        "ip": ip,
                        "logon_type": logon_type,
                    })

                if time_str:
                    try:
                        dt = datetime.fromisoformat(time_str[:19])
                        logon_times.append(dt.hour)
                    except (ValueError, TypeError):
                        pass

            # Detectar actividad fuera de horario laboral (antes de 7h o después de 21h)
            out_of_hours = [h for h in logon_times if h < 7 or h > 21]

            findings_data = {
                "total_events_analyzed": len(events),
                "failed_logon_attempts": len(failed_logons),
                "remote_logon_sessions": len(remote_logons),
                "out_of_hours_activity": len(out_of_hours),
                "failed_logons_detail": failed_logons[:10],
                "remote_logons_detail": remote_logons[:10],
            }

            risk = "green"
            concerns = []

            if len(failed_logons) > 5:
                risk = "yellow"
                concerns.append(f"{len(failed_logons)} intentos de inicio de sesión fallidos")

            if remote_logons:
                risk = "orange"
                concerns.append(
                    f"{len(remote_logons)} sesiones RDP remotas desde IPs externas"
                )

            if out_of_hours > 5:
                risk = max(risk, "yellow",
                           key=lambda x: ["green", "yellow", "orange", "red"].index(x))
                concerns.append(f"{len(out_of_hours)} eventos de actividad fuera de horario")

            concern_str = "; ".join(concerns) if concerns else "Sin anomalías detectadas"

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="behavior_logon_patterns",
                title=f"Análisis de patrones de sesión — {concern_str}",
                description=(
                    "Análisis de los eventos de inicio y cierre de sesión registrados "
                    "en el log de seguridad de Windows. Permite identificar patrones "
                    "de acceso inusuales y accesos remotos."
                ),
                risk_level=risk,
                technical_risk=(
                    "Los logs de seguridad de Windows registran automáticamente "
                    "todos los inicios de sesión. Si la empresa monitoriza estos logs, "
                    "tiene acceso a los patrones de horario del trabajador."
                ),
                legal_risk=(
                    "El análisis de patrones de horario de trabajo puede constituir "
                    "tratamiento de datos de comportamiento bajo RGPD. "
                    "Requiere base legal y limitación de finalidad bajo RGPD art. 5."
                ),
                what_it_is=(
                    "Eventos de seguridad de Windows que registran cuándo y desde dónde "
                    "se ha iniciado sesión en el equipo."
                ),
                what_it_is_not=(
                    "No contiene información sobre qué hizo el usuario en la sesión, "
                    "solo los metadatos de inicio y cierre."
                ),
                raw_data=findings_data
            ))

        except Exception as e:
            print(f"[UserBehavior] Error analizando patrones de sesión: {e}")

    # ── Política de auditoría de procesos ──────────────────────────

    def _analyze_process_audit_policy(self):
        from core.audit_engine import AuditFinding

        try:
            result = subprocess.run(
                ["auditpol", "/get", "/category:*", "/r"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                return

            lines = result.stdout.strip().split("\n")
            audit_settings = []
            behavior_categories = [
                "process creation", "process termination",
                "logon", "logoff", "account logon",
                "object access", "file system", "registry",
                "detailed tracking",
            ]

            for line in lines[1:]:  # saltar cabecera
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 4:
                    category = parts[1].lower() if len(parts) > 1 else ""
                    subcategory = parts[2].lower() if len(parts) > 2 else ""
                    setting = parts[3] if len(parts) > 3 else ""
                    if any(k in category + subcategory for k in behavior_categories):
                        if "success" in setting.lower() or "failure" in setting.lower():
                            audit_settings.append({
                                "category": parts[1].strip() if len(parts) > 1 else "",
                                "subcategory": parts[2].strip() if len(parts) > 2 else "",
                                "setting": setting,
                                "active": "No Auditing" not in setting,
                            })

            active = [s for s in audit_settings if s["active"]]
            if not active:
                return

            process_audit = [
                s for s in active
                if "process" in s["subcategory"].lower()
            ]

            risk = "orange" if process_audit else "yellow"

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="behavior_audit_policy",
                title=f"Política de auditoría de comportamiento activa "
                      f"({len(active)} categorías)",
                description=(
                    "Se han detectado políticas de auditoría de Windows activas "
                    "que registran actividad de usuario: creación de procesos, "
                    "acceso a objetos, inicio de sesión."
                ),
                risk_level=risk,
                technical_risk=(
                    "Con auditoría de creación de procesos activa, el sistema "
                    "registra cada programa ejecutado por el usuario con timestamp. "
                    "Esto permite reconstruir toda la actividad del puesto de trabajo."
                ),
                legal_risk=(
                    "La auditoría detallada de procesos y accesos permite perfilar "
                    "completamente el comportamiento del trabajador. "
                    "Bajo RGPD art. 22 y 35, puede requerir DPIA si se usa para "
                    "tomar decisiones automatizadas sobre el empleado."
                ),
                what_it_is=(
                    "Configuración del sistema de auditoría de Windows que determina "
                    "qué eventos se registran en el log de seguridad."
                ),
                what_it_is_not=(
                    "La auditoría es una herramienta de seguridad estándar. "
                    "No implica que los logs se analicen para supervisar empleados."
                ),
                raw_data={
                    "active_audit_settings": active,
                    "process_audit_active": bool(process_audit)
                }
            ))

        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[UserBehavior] Error leyendo política de auditoría: {e}")

    # ── Auditoría de acceso a objetos ─────────────────────────────

    def _analyze_object_access_audit(self):
        from core.audit_engine import AuditFinding

        script = """
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4663; MaxEvents=50
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = @{}
    $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
    @{
        Time       = [string]$_.TimeCreated
        ObjectName = $data['ObjectName']
        ObjectType = $data['ObjectType']
        SubjectUser = $data['SubjectUserName']
        AccessMask = $data['AccessMask']
    }
}
$events | ConvertTo-Json -Depth 2
"""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode != 0 or not result.stdout.strip():
                return

            events = json.loads(result.stdout)
            if not events:
                return
            if isinstance(events, dict):
                events = [events]

            # Filtrar accesos a recursos sensibles
            sensitive_patterns = [
                "\\password", "\\credentials", "\\vault",
                "\\private", "\\secret", "\\confidential",
                ".kdbx", ".p12", ".pfx", ".key",
                "\\ssh\\", "\\gpg\\",
            ]

            sensitive_accesses = [
                ev for ev in events
                if any(
                    p in str(ev.get("ObjectName", "")).lower()
                    for p in sensitive_patterns
                )
            ]

            if not sensitive_accesses and len(events) < 5:
                return

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="behavior_object_access",
                title=f"Eventos de acceso a objetos auditados ({len(events)} recientes)",
                description=(
                    "Se han registrado eventos de acceso a archivos y objetos "
                    "del sistema. Esto indica que la auditoría de acceso a "
                    "objetos está activa y puede usarse para rastrear accesos."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Con auditoría de objetos activa, cada acceso a archivos "
                    "con SACL configurada queda registrado con usuario y timestamp. "
                    "Permite saber exactamente qué archivos abrió el trabajador."
                ),
                legal_risk=(
                    "El registro detallado de acceso a archivos puede ser "
                    "evidencia forense en investigaciones internas. "
                    "El trabajador tiene derecho a saber que se audita su acceso."
                ),
                what_it_is=(
                    "Log de acceso a archivos y objetos del sistema cuando "
                    "la auditoría está configurada sobre esos objetos."
                ),
                what_it_is_not=(
                    "No registra el contenido de los archivos, "
                    "solo los metadatos de acceso: quién, cuándo, qué operación."
                ),
                raw_data={
                    "total_events": len(events),
                    "sensitive_accesses": sensitive_accesses[:10]
                }
            ))

        except Exception as e:
            print(f"[UserBehavior] Error leyendo eventos de acceso: {e}")

    # ── Software de monitorización de comportamiento ───────────────

    def _analyze_behavior_monitoring_software(self):
        from core.audit_engine import AuditFinding

        behavior_software = [
            ("ActivTrak", ["activtrak"]),
            ("Teramind", ["teramind"]),
            ("Hubstaff", ["hubstaff"]),
            ("Veriato / Cerebral", ["veriato", "cerebral"]),
            ("Time Doctor", ["time doctor"]),
            ("InterGuard", ["interguard"]),
            ("WorkTime", ["worktime"]),
            ("DeskTime", ["desktime"]),
            ("Insightful (Workpuls)", ["insightful", "workpuls"]),
            ("Kickidler", ["kickidler"]),
            ("StaffCop", ["staffcop"]),
            ("ObserveIT / Proofpoint ITM", ["observeit", "proofpoint itm"]),
            ("Ekran System", ["ekran"]),
            ("ManageEngine ADAudit", ["adaudit"]),
        ]

        found = []
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\"
                 "CurrentVersion\\Uninstall\\*, "
                 "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\"
                 "CurrentVersion\\Uninstall\\* "
                 "-ErrorAction SilentlyContinue "
                 "| Select-Object DisplayName, Publisher "
                 "| ConvertTo-Json"],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0 and result.stdout.strip():
                installed = json.loads(result.stdout)
                if isinstance(installed, dict):
                    installed = [installed]
                for app in installed:
                    name = str(app.get("DisplayName") or "").lower()
                    for sw_name, patterns in behavior_software:
                        if any(p in name for p in patterns):
                            found.append({
                                "product": sw_name,
                                "installed_name": app.get("DisplayName"),
                                "publisher": app.get("Publisher"),
                            })
        except Exception as e:
            print(f"[UserBehavior] Error buscando software: {e}")

        # Buscar también por procesos en ejecución
        running = []
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Process | Select-Object Name, Path, Company | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                procs = json.loads(result.stdout)
                if isinstance(procs, dict):
                    procs = [procs]
                for proc in procs:
                    pname = str(proc.get("Name") or "").lower()
                    company = str(proc.get("Company") or "").lower()
                    for sw_name, patterns in behavior_software:
                        if any(p in pname or p in company for p in patterns):
                            running.append({
                                "product": sw_name,
                                "process": proc.get("Name"),
                                "path": proc.get("Path"),
                            })
        except Exception as e:
            print(f"[UserBehavior] Error leyendo procesos: {e}")

        if not found and not running:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="behavior_monitoring_software",
            title=f"Software de monitorización de comportamiento detectado "
                  f"({len(found)} instalado, {len(running)} en ejecución)",
            description=(
                "Se ha detectado software específicamente diseñado para monitorizar "
                "el comportamiento de empleados: capturas de pantalla periódicas, "
                "registro de aplicaciones, seguimiento de tiempo activo."
            ),
            risk_level="red",
            technical_risk=(
                "Este tipo de software puede registrar: capturas de pantalla, "
                "aplicaciones usadas, URLs visitadas, pulsaciones de teclado, "
                "tiempo activo por aplicación, webcam en algunos casos, "
                "y enviar todo esto a la plataforma del empleador."
            ),
            legal_risk=(
                "La vigilancia continua mediante este software es extremadamente "
                "invasiva y difícilmente supera el test de proporcionalidad "
                "del TEDH (Barbulescu II). Requiere información muy detallada "
                "previa bajo LOPDGDD art. 87 y ET art. 20bis. "
                "La captura de pantalla puede vulnerar CP art. 197."
            ),
            what_it_is=(
                "Herramientas comerciales de employee monitoring que registran "
                "toda la actividad del trabajador en el ordenador de empresa."
            ),
            what_it_is_not=(
                "Son herramientas de vigilancia específica de empleados, "
                "no herramientas de seguridad corporativa general."
            ),
            raw_data={
                "installed": found,
                "running_processes": running
            }
        ))

    # ── Capacidades de logging de actividad ───────────────────────

    def _analyze_activity_logging_capabilities(self):
        from core.audit_engine import AuditFinding

        capabilities = []

        # Windows Event Forwarding activo
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager",
                0, winreg.KEY_READ
            )
            idx = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, idx)
                    capabilities.append({
                        "capability": "Windows Event Forwarding (WEF)",
                        "detail": f"Logs se envían a: {str(value)[:100]}",
                        "severity": "high",
                    })
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        # PowerShell ScriptBlock Logging activo
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                0, winreg.KEY_READ
            )
            try:
                val, _ = winreg.QueryValueEx(key, "EnableScriptBlockLogging")
                if int(val) == 1:
                    capabilities.append({
                        "capability": "PowerShell ScriptBlock Logging",
                        "detail": "Se registra el contenido de todos los scripts PowerShell ejecutados.",
                        "severity": "medium",
                    })
            except (FileNotFoundError, PermissionError, OSError):
                pass
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        # PowerShell Transcription activo
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
                0, winreg.KEY_READ
            )
            try:
                val, _ = winreg.QueryValueEx(key, "EnableTranscripting")
                if int(val) == 1:
                    out_dir = ""
                    try:
                        out_dir_val, _ = winreg.QueryValueEx(key, "OutputDirectory")
                        out_dir = str(out_dir_val)
                    except (FileNotFoundError, PermissionError, OSError):
                        pass
                    capabilities.append({
                        "capability": "PowerShell Transcription",
                        "detail": f"Toda la sesión PowerShell se guarda en texto. "
                                  f"Directorio: {out_dir or 'por defecto'}",
                        "severity": "high",
                    })
            except (FileNotFoundError, PermissionError, OSError):
                pass
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        # Enhanced logging de AppLocker
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\SrpV2",
                0, winreg.KEY_READ
            )
            capabilities.append({
                "capability": "AppLocker activo",
                "detail": "AppLocker registra qué aplicaciones ejecuta el usuario.",
                "severity": "medium",
            })
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        if not capabilities:
            return

        high = [c for c in capabilities if c["severity"] == "high"]
        risk = "orange" if high else "yellow"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="behavior_logging_capabilities",
            title=f"Capacidades de logging de actividad activas ({len(capabilities)})",
            description=(
                "Se han detectado capacidades del sistema que permiten "
                "registrar y centralizar la actividad del usuario: "
                "reenvío de eventos, transcripción de PowerShell, AppLocker."
            ),
            risk_level=risk,
            technical_risk=(
                "Windows Event Forwarding envía todos los logs de seguridad "
                "a un servidor central corporativo en tiempo real. "
                "PowerShell Transcription guarda literalmente todo lo que "
                "escribe el usuario en PowerShell."
            ),
            legal_risk=(
                "La centralización de logs de actividad para análisis de "
                "comportamiento puede requerir DPIA bajo RGPD art. 35 "
                "si se usa para perfilar o evaluar al trabajador."
            ),
            what_it_is=(
                "Funciones de auditoría avanzada de Windows que registran "
                "y pueden centralizar la actividad del equipo."
            ),
            what_it_is_not=(
                "Estas capacidades son herramientas de seguridad estándar. "
                "No implican análisis de comportamiento por sí solas."
            ),
            raw_data={"capabilities": capabilities}
        ))
