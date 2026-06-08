# skills/network_capture_audit/network_capture_audit.py
"""
Skill — Network Capture Audit
Detecta drivers y herramientas de captura de paquetes de red instalados
en el equipo, analiza su configuración de seguridad, identifica el
origen de instalación y evalúa el riesgo legal para el trabajador.

Herramientas detectadas: npcap, WinPcap, RawCap, y derivados.
Configuraciones auditadas: AdminOnly, LoopbackSupport, modos inseguros.
Origen: Zscaler, Wireshark, nmap, instalación directa.

Operación: solo lectura, sin elevación de privilegios.
Fuentes: registro, filesystem, logs de instalación, tareas programadas.
"""

import os
import json
import hashlib
import datetime
import subprocess
import winreg
from pathlib import Path
from typing import Optional


# ── Herramientas conocidas ────────────────────────────────────────────────────

CAPTURE_TOOLS = {
    "npcap": {
        "registry_services": [
            r"SYSTEM\CurrentControlSet\Services\npcap",
        ],
        "registry_params": [
            r"SYSTEM\CurrentControlSet\Services\npcap\Parameters",
        ],
        "driver_paths": [
            r"C:\WINDOWS\system32\DRIVERS\npcap.sys",
            r"C:\WINDOWS\system32\DRIVERS\npcap_wfp.sys",
        ],
        "install_dirs": [
            r"C:\Program Files\Npcap",
            r"C:\Program Files (x86)\Npcap",
        ],
        "install_log": r"C:\Program Files\Npcap\install.log",
        "npfinstall_log": r"C:\Program Files\Npcap\NPFInstall.log",
        "watchdog_task": "npcapwatchdog",
        "uninstall_key": r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "uninstall_name": "Npcap",
        "capability": (
            "Captura de todos los paquetes de red que pasan por los adaptadores "
            "del equipo. En modo inseguro (AdminOnly=0) cualquier usuario local "
            "puede iniciar capturas sin privilegios de administrador."
        ),
    },
    "WinPcap": {
        "registry_services": [
            r"SYSTEM\CurrentControlSet\Services\NPF",
        ],
        "registry_params": [],
        "driver_paths": [
            r"C:\WINDOWS\system32\DRIVERS\npf.sys",
        ],
        "install_dirs": [
            r"C:\Program Files\WinPcap",
            r"C:\Program Files (x86)\WinPcap",
        ],
        "install_log": None,
        "npfinstall_log": None,
        "watchdog_task": None,
        "uninstall_key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "uninstall_name": "WinPcap",
        "capability": (
            "Librería de captura de paquetes de red legacy. "
            "Permite interceptar tráfico de red a nivel de driver."
        ),
    },
    "RawCap": {
        "registry_services": [],
        "registry_params": [],
        "driver_paths": [],
        "install_dirs": [],
        "install_log": None,
        "npfinstall_log": None,
        "watchdog_task": None,
        "uninstall_key": None,
        "uninstall_name": "RawCap",
        "capability": (
            "Herramienta de captura de paquetes sin instalación de driver. "
            "Más difícil de detectar que npcap/WinPcap."
        ),
    },
}

# Orígenes conocidos de npcap OEM
KNOWN_ORIGINS = {
    r"C:\Program Files\Zscaler\ThirdParty\Npcap": "Zscaler",
    r"C:\Program Files\Wireshark": "Wireshark",
    r"C:\Program Files (x86)\Wireshark": "Wireshark",
    r"C:\Program Files\Nmap": "nmap",
    r"C:\Program Files (x86)\Nmap": "nmap",
}

# Parámetros de seguridad y sus interpretaciones
SECURITY_PARAMS = {
    "AdminOnly": {
        "safe_value": "1",
        "insecure_value": "0",
        "description": "Solo administradores pueden capturar paquetes",
        "insecure_description": (
            "CUALQUIER usuario local puede capturar paquetes de red. "
            "Configuración insegura (INSECURE_NPCAP)."
        ),
    },
    "LoopbackSupport": {
        "safe_value": None,  # No tiene valor inseguro universal
        "description": "Soporte de captura en interfaz loopback",
    },
    "WinPcapCompatible": {
        "safe_value": None,
        "description": "Modo compatible con WinPcap legacy",
    },
    "DltNull": {
        "safe_value": None,
        "description": "Soporte DLT_NULL en capturas loopback",
    },
}


# ── Utilidades ───────────────────────────────────────────────────────────────

def _file_hash(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _reg_key_exists(hive, subkey: str) -> bool:
    try:
        k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        winreg.CloseKey(k)
        return True
    except FileNotFoundError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def _reg_read_all_values(hive, subkey: str) -> dict:
    """Lee todos los valores de una clave de registro."""
    values = {}
    try:
        k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(k, i)
                values[name] = str(data)
                i += 1
            except OSError:
                break
        winreg.CloseKey(k)
    except Exception:
        pass
    return values


def _ps(cmd: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _file_metadata(path: Path) -> Optional[dict]:
    try:
        stat = path.stat()
        return {
            "path": str(path),
            "size_bytes": stat.st_size,
            "created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "sha256": _file_hash(path),
        }
    except Exception:
        return None


# ── Detección ────────────────────────────────────────────────────────────────

def _detect_driver_running(tool_cfg: dict) -> bool:
    """Verifica si el driver está activo en el sistema."""
    for subkey in tool_cfg["registry_services"]:
        if _reg_key_exists(winreg.HKEY_LOCAL_MACHINE, subkey):
            # Leer estado del servicio
            values = _reg_read_all_values(
                winreg.HKEY_LOCAL_MACHINE, subkey
            )
            # Start=1 = boot, Start=2 = auto, Start=3 = manual
            start = values.get("Start", "")
            if start in ("1", "2", "3"):
                return True
    return False


def _detect_driver_file(tool_cfg: dict) -> list[dict]:
    """Detecta archivos de driver en disco."""
    found = []
    for p in tool_cfg["driver_paths"]:
        meta = _file_metadata(Path(p))
        if meta:
            found.append(meta)
    return found


def _detect_install_dir(tool_cfg: dict) -> list[str]:
    """Detecta directorio de instalación."""
    found = []
    for d in tool_cfg["install_dirs"]:
        if Path(d).exists():
            found.append(d)
    return found


def _detect_uninstall_entry(tool_cfg: dict) -> Optional[dict]:
    """Busca entrada en el registro de desinstalación."""
    name_pattern = tool_cfg.get("uninstall_name", "").lower()
    if not name_pattern:
        return None

    for hive, hive_name in [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        (winreg.HKEY_CURRENT_USER, "HKCU"),
    ]:
        for subkey in [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ]:
            try:
                k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(k, i)
                        sub = winreg.OpenKey(k, subkey_name, 0, winreg.KEY_READ)
                        try:
                            display_name, _ = winreg.QueryValueEx(sub, "DisplayName")
                            if name_pattern in str(display_name).lower():
                                result = {"DisplayName": str(display_name)}
                                for field in ["Publisher", "InstallDate",
                                              "DisplayVersion", "InstallLocation"]:
                                    try:
                                        val, _ = winreg.QueryValueEx(sub, field)
                                        result[field] = str(val)
                                    except Exception:
                                        pass
                                winreg.CloseKey(sub)
                                winreg.CloseKey(k)
                                return result
                        except Exception:
                            pass
                        winreg.CloseKey(sub)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(k)
            except Exception:
                pass
    return None


# ── Análisis de configuración de seguridad ───────────────────────────────────

def _read_security_params(tool_cfg: dict) -> dict:
    """Lee parámetros de seguridad del driver desde el registro."""
    params = {}
    for subkey in tool_cfg["registry_params"]:
        values = _reg_read_all_values(winreg.HKEY_LOCAL_MACHINE, subkey)
        params.update(values)
    return params


def _analyze_security(params: dict) -> tuple[list[str], list[str]]:
    """
    Analiza los parámetros de seguridad.
    Devuelve (flags_inseguros, notas_informativas).
    """
    insecure_flags = []
    info_notes = []

    admin_only = params.get("AdminOnly", None)
    if admin_only is not None:
        if str(admin_only) == "0":
            insecure_flags.append(
                "AdminOnly=0: cualquier usuario local puede capturar "
                "paquetes de red sin privilegios de administrador "
                "(INSECURE_NPCAP)"
            )
        elif str(admin_only) == "1":
            info_notes.append(
                "AdminOnly=1: captura restringida a administradores (seguro)"
            )

    loopback = params.get("LoopbackSupport", None)
    if loopback == "1":
        info_notes.append(
            "LoopbackSupport=1: puede capturar tráfico de loopback local"
        )

    winpcap_compat = params.get("WinPcapCompatible", None)
    if winpcap_compat == "1":
        info_notes.append(
            "WinPcapCompatible=1: modo compatible con librería WinPcap legacy"
        )

    edition = params.get("Edition", "")
    if "OEM" in str(edition):
        info_notes.append(
            f"Edition={edition}: instalación OEM (integrada por tercero, "
            "no instalación directa por usuario)"
        )

    return insecure_flags, info_notes


# ── Origen de instalación ────────────────────────────────────────────────────

def _detect_origin(tool_name: str, tool_cfg: dict) -> dict:
    """
    Intenta identificar qué software instaló este driver.
    Para npcap OEM busca en logs de instalación.
    """
    origin = {
        "source": "unknown",
        "source_path": None,
        "install_timestamp": None,
        "command_line": None,
        "via_intune": False,
    }

    # Buscar en carpetas conocidas de orígenes
    for origin_path, origin_name in KNOWN_ORIGINS.items():
        if Path(origin_path).exists():
            # Verificar si hay ejecutable del driver en esa carpeta
            for subdir in [origin_path]:
                for fname in ["npcap-1.80-oem.exe", "npcap-oem.exe",
                              "npcap.exe", "NPFInstall.exe"]:
                    candidate = Path(subdir) / fname
                    if candidate.exists():
                        origin["source"] = origin_name
                        origin["source_path"] = str(candidate)
                        break

    # Leer install.log para obtener command line y timestamp
    install_log = tool_cfg.get("install_log")
    if install_log and Path(install_log).exists():
        try:
            content = Path(install_log).read_text(
                encoding="utf-8", errors="replace"
            )
            # Buscar línea con "Command line:"
            for line in content.splitlines():
                if "Command line:" in line or "command line:" in line.lower():
                    origin["command_line"] = line.strip()
                    # Identificar origen por ruta en command line
                    for path_fragment, name in KNOWN_ORIGINS.items():
                        if path_fragment.lower().replace("\\", "/") in \
                                line.lower().replace("\\", "/"):
                            origin["source"] = name
                            origin["source_path"] = path_fragment
                            break
                    break
        except Exception:
            pass

    # Leer NPFInstall.log para historial de reconfiguración
    npf_log = tool_cfg.get("npfinstall_log")
    if npf_log and Path(npf_log).exists():
        try:
            content = Path(npf_log).read_text(
                encoding="utf-8", errors="replace"
            )
            # Buscar timestamps de InstallDriver/UninstallDriver
            timestamps = []
            for line in content.splitlines():
                if "--> InstallDriver" in line or \
                   "INSECURE_NPCAP" in line or \
                   "_tmain: executing" in line:
                    # Extraer timestamp si lo hay
                    import re
                    match = re.search(r"\[(\d+)\] (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                    if match:
                        timestamps.append({
                            "timestamp": match.group(2),
                            "event": line.strip()[:200],
                        })
            if timestamps:
                origin["install_history"] = timestamps[-10:]  # Últimos 10
                origin["install_timestamp"] = timestamps[-1]["timestamp"]
        except Exception:
            pass

    # Verificar si fue instalado via Intune
    intune_dir = Path(
        r"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
    )
    if intune_dir.exists():
        tool_lower = tool_name.lower()
        for log_file in intune_dir.iterdir():
            if not log_file.is_file():
                continue
            try:
                content = log_file.read_text(
                    encoding="utf-8", errors="replace"
                )
                # Buscar herramienta que instaló npcap
                if tool_lower in content.lower():
                    origin["via_intune"] = True
                    origin["intune_log"] = str(log_file)
                    break
                # Para npcap buscar también el origen conocido
                if origin["source"] != "unknown":
                    if origin["source"].lower() in content.lower():
                        origin["via_intune"] = True
                        origin["intune_log"] = str(log_file)
                        break
            except Exception:
                continue

    return origin


# ── Watchdog task ────────────────────────────────────────────────────────────

def _check_watchdog_task(task_name: Optional[str]) -> Optional[dict]:
    """
    Verifica si existe una tarea programada watchdog para el driver.
    Incluye si la tarea está protegida (acceso denegado).
    """
    if not task_name:
        return None

    result = {
        "task_name": task_name,
        "exists": False,
        "protected": False,
        "state": None,
        "execute": None,
    }

    # Intentar via PowerShell
    ps_output = _ps(
        f"Get-ScheduledTask -TaskName '{task_name}' -ErrorAction SilentlyContinue | "
        "Select-Object TaskName, State, @{N='Execute';E={$_.Actions[0].Execute}} | "
        "ConvertTo-Json -Depth 2"
    )

    if ps_output:
        try:
            data = json.loads(ps_output)
            result["exists"] = True
            result["state"] = str(data.get("State", ""))
            result["execute"] = str(data.get("Execute", ""))
            return result
        except Exception:
            pass

    # Intentar via schtasks (puede dar acceso denegado)
    schtasks_output = _ps(
        f"schtasks /query /fo LIST /v /tn '{task_name}' 2>&1"
    )

    if "acceso denegado" in schtasks_output.lower() or \
       "access denied" in schtasks_output.lower():
        result["exists"] = True  # Existe pero protegida
        result["protected"] = True
        result["state"] = "protegida_acceso_denegado"
        return result

    if schtasks_output and "taskname" in schtasks_output.lower():
        result["exists"] = True
        for line in schtasks_output.splitlines():
            if "estado:" in line.lower() or "status:" in line.lower():
                result["state"] = line.split(":", 1)[-1].strip()
            if "ejecutar:" in line.lower() or "task to run:" in line.lower():
                result["execute"] = line.split(":", 1)[-1].strip()

    return result


# ── Skill principal ───────────────────────────────────────────────────────────

class NetworkCaptureAudit:
    SKILL_NAME = "network_capture_audit"

    def __init__(self, engine):
        self.engine = engine
        self.detected_tools = []

    def run(self):
        print("[NetworkCapture] Iniciando auditoría de captura de red...")

        for tool_name, tool_cfg in CAPTURE_TOOLS.items():
            self._audit_tool(tool_name, tool_cfg)

        total = len(self.detected_tools)
        print(
            f"[NetworkCapture] Completado — "
            f"{total} herramienta(s) de captura de red detectada(s)"
        )

    def _audit_tool(self, tool_name: str, tool_cfg: dict):
        from core.audit_engine import AuditFinding

        # Detección
        driver_running = _detect_driver_running(tool_cfg)
        driver_files = _detect_driver_file(tool_cfg)
        install_dirs = _detect_install_dir(tool_cfg)
        uninstall_entry = _detect_uninstall_entry(tool_cfg)

        detected = (
            driver_running or
            bool(driver_files) or
            bool(install_dirs) or
            bool(uninstall_entry)
        )

        if not detected:
            return

        print(f"[NetworkCapture] Detectado: {tool_name}")
        self.detected_tools.append(tool_name)

        # Configuración de seguridad
        security_params = _read_security_params(tool_cfg)
        insecure_flags, info_notes = _analyze_security(security_params)

        # Origen de instalación
        origin = _detect_origin(tool_name, tool_cfg)

        # Watchdog
        watchdog = _check_watchdog_task(tool_cfg.get("watchdog_task"))

        # Metadatos de archivos de driver
        driver_file_meta = [
            _file_metadata(Path(p))
            for p in tool_cfg["driver_paths"]
            if _file_metadata(Path(p))
        ]

        # Determinar riesgo
        risk = "orange"  # Base: herramienta de captura de red presente
        if insecure_flags:
            risk = "red"  # Modo inseguro
        if origin["via_intune"] and not insecure_flags:
            risk = "orange"  # Instalado por empresa, configuración estándar

        # Construir flags resumen
        flags = []
        if driver_running:
            flags.append("driver_activo_en_ejecucion")
        if insecure_flags:
            for f in insecure_flags:
                flags.append(f)
        if watchdog and watchdog.get("exists"):
            if watchdog.get("protected"):
                flags.append(
                    "tarea_watchdog_protegida: acceso denegado a usuario estándar"
                )
            else:
                flags.append(
                    f"tarea_watchdog_activa: {watchdog.get('task_name')}"
                )
        if origin["source"] != "unknown":
            flags.append(f"origen_identificado: {origin['source']}")
        if origin["via_intune"]:
            flags.append("instalado_via_intune_o_herramienta_corporativa")

        # Descripción
        description_parts = [
            f"Driver de captura de paquetes de red '{tool_name}' detectado."
        ]
        if driver_running:
            description_parts.append("El driver está activo en este momento.")
        if origin["source"] != "unknown":
            description_parts.append(
                f"Origen identificado: instalado como dependencia de "
                f"'{origin['source']}'."
            )
        if insecure_flags:
            description_parts.append(
                "CONFIGURACIÓN INSEGURA: " + "; ".join(insecure_flags)
            )
        if security_params.get("Edition"):
            description_parts.append(
                f"Edición: {security_params['Edition']}."
            )

        # Riesgo técnico
        tech_risk_parts = [tool_cfg["capability"]]
        if insecure_flags:
            tech_risk_parts.append(
                "La configuración actual (AdminOnly=0) permite a cualquier "
                "proceso o usuario sin privilegios administrativos iniciar "
                "capturas de tráfico de red, incluyendo tráfico de otras "
                "aplicaciones del equipo."
            )
        if watchdog and watchdog.get("protected"):
            tech_risk_parts.append(
                "La tarea watchdog está protegida — no puede ser consultada "
                "ni modificada por el usuario estándar, lo que impide "
                "auditar su configuración completa."
            )

        # Riesgo legal
        legal_risk_parts = []
        if insecure_flags:
            legal_risk_parts.append(
                "La configuración insegura (AdminOnly=0) podría usarse para "
                "interceptar comunicaciones sin autorización. Su existencia "
                "no documentada en el equipo de un trabajador requiere "
                "justificación bajo RGPD art. 32 (medidas de seguridad)."
            )
        if not origin["via_intune"] and origin["source"] == "unknown":
            legal_risk_parts.append(
                "Origen desconocido: no se puede determinar quién instaló "
                "esta herramienta ni con qué finalidad. "
                "RGPD art. 5.1.f (integridad y confidencialidad)."
            )
        else:
            legal_risk_parts.append(
                "El responsable del tratamiento debe justificar la necesidad "
                "y proporcionalidad de esta herramienta en el equipo del "
                "trabajador — RGPD art. 32, LOPDGDD art. 87."
            )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="network_capture_driver_detected",
            title=(
                f"Driver de captura de red: {tool_name}"
                + (" — MODO INSEGURO (AdminOnly=0)"
                   if insecure_flags else "")
                + (f" — origen: {origin['source']}"
                   if origin["source"] != "unknown" else "")
            ),
            description=" ".join(description_parts),
            risk_level=risk,
            technical_risk=" ".join(tech_risk_parts),
            legal_risk=" ".join(legal_risk_parts) or
                       "Verificar justificación de uso en política de seguridad.",
            what_it_is=(
                f"'{tool_name}' es un driver de captura de paquetes de red "
                "que opera a nivel de kernel. Permite a herramientas como "
                "Wireshark, Zscaler o nmap interceptar y analizar el tráfico "
                "de red del equipo. Su presencia no es necesariamente "
                "maliciosa — puede ser una dependencia de software legítimo."
            ),
            what_it_is_not=(
                "No implica por sí solo que alguien esté espiando las "
                "comunicaciones del trabajador. La configuración insegura "
                "(AdminOnly=0) amplía la superficie de riesgo, pero no "
                "demuestra uso activo para captura no autorizada."
            ),
            raw_data={
                "tool": tool_name,
                "driver_running": driver_running,
                "driver_files": driver_file_meta,
                "install_dirs": install_dirs,
                "uninstall_entry": uninstall_entry,
                "security_params": security_params,
                "insecure_flags": insecure_flags,
                "info_notes": info_notes,
                "flags": flags,
                "origin": origin,
                "watchdog_task": watchdog,
                "capability": tool_cfg["capability"],
            },
        ))

        # Hallazgo adicional si hay reconfiguración documentada
        self._check_reconfiguration(tool_name, origin, security_params)

    def _check_reconfiguration(
        self, tool_name: str, origin: dict, security_params: dict
    ):
        """
        Si el log de NPFInstall muestra que el driver fue reconfigurado
        a modo inseguro, genera un hallazgo específico con timestamp.
        """
        from core.audit_engine import AuditFinding

        history = origin.get("install_history", [])
        if not history:
            return

        # Buscar eventos de reconfiguración a INSECURE_NPCAP
        reconfig_events = [
            e for e in history
            if "INSECURE_NPCAP" in e.get("event", "")
            or "InstallDriver" in e.get("event", "")
        ]

        if not reconfig_events:
            return

        latest = reconfig_events[-1]

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="network_capture_reconfigured_insecure",
            title=(
                f"{tool_name} reconfigurado a modo inseguro — "
                f"{latest.get('timestamp', 'fecha desconocida')}"
            ),
            description=(
                f"Los logs de instalación registran que '{tool_name}' fue "
                f"reconfigurado explícitamente al componente INSECURE_NPCAP "
                f"el {latest.get('timestamp', 'fecha desconocida')}. "
                f"Esto cambió el parámetro AdminOnly de 1 (seguro) a 0 "
                f"(inseguro), permitiendo captura por usuarios no administradores."
            ),
            risk_level="red",
            technical_risk=(
                "La reconfiguración deliberada a modo inseguro amplía la "
                "superficie de ataque. Cualquier proceso que se ejecute "
                "como usuario estándar puede ahora capturar paquetes de red "
                "sin necesitar privilegios. Esto incluye herramientas "
                "instaladas sin conocimiento del trabajador."
            ),
            legal_risk=(
                "Una reconfiguración deliberada a modo inseguro por parte "
                "del administrador del sistema requiere justificación técnica "
                "documentada. Su ausencia puede ser relevante bajo RGPD art. 32 "
                "(seguridad del tratamiento) y art. 5.1.f (confidencialidad). "
                "Solicitable al DPO como parte de la DPIA requerida por art. 35."
            ),
            what_it_is=(
                "Evento documentado en NPFInstall.log que registra la "
                "instalación explícita del componente INSECURE_NPCAP, "
                "cambiando la configuración de seguridad del driver."
            ),
            what_it_is_not=(
                "No es prueba de captura activa de tráfico. Es evidencia de "
                "que se tomó una decisión técnica que reduce la seguridad "
                "del equipo del trabajador, sin su conocimiento."
            ),
            raw_data={
                "tool": tool_name,
                "reconfiguration_timestamp": latest.get("timestamp"),
                "reconfiguration_event": latest.get("event"),
                "all_reconfig_events": reconfig_events,
                "current_admin_only": security_params.get("AdminOnly"),
                "install_history_sample": history[-5:],
            },
        ))
    