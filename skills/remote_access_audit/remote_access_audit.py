# skills/remote_access_audit/remote_access_audit.py
"""
Skill — Remote Access Audit
Detecta herramientas de acceso remoto instaladas en el equipo,
documenta sesiones con metadatos forenses y evalúa riesgo legal.

Herramientas detectadas: LogMeIn Rescue, TeamViewer, AnyDesk,
Zoho Assist, Splashtop, Windows RDP.

Operación: solo lectura, sin elevación de privilegios.
Fuentes: registro, filesystem, Intune logs.
"""

import os
import json
import hashlib
import datetime
import winreg
from pathlib import Path
from typing import Optional


# ── Configuración ────────────────────────────────────────────────────────────

# Horario laboral estándar — sesiones fuera de rango son alertas
WORK_HOURS_START = 7   # 07:00
WORK_HOURS_END   = 22  # 22:00
WORK_DAYS        = [0, 1, 2, 3, 4]  # Lunes a Viernes

INTUNE_LOG_DIR = Path(
    r"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
)

# Herramientas conocidas con sus rutas y metadatos
KNOWN_TOOLS = {
    "LogMeIn Rescue": {
        "registry_keys": [
            r"SOFTWARE\LogMeIn Rescue",
            r"SOFTWARE\WOW6432Node\LogMeIn Rescue",
        ],
        "programdata_paths": [
            r"C:\ProgramData\LogMeIn Rescue Calling Card",
        ],
        "program_files_paths": [
            r"C:\Program Files (x86)\LogMeIn Rescue Calling Card",
            r"C:\Program Files\LogMeIn Rescue Calling Card",
        ],
        "intune_log_pattern": "LogMeIn Rescue",
        "risk_level": "red",
        "capability": (
            "Control total de escritorio, transferencia de archivos "
            "y ejecución de comandos de forma remota. "
            "Puede operar en modo desatendido sin intervención del trabajador."
        ),
    },
    "TeamViewer": {
        "registry_keys": [
            r"SOFTWARE\TeamViewer",
            r"SOFTWARE\WOW6432Node\TeamViewer",
        ],
        "programdata_paths": [r"C:\ProgramData\TeamViewer"],
        "program_files_paths": [
            r"C:\Program Files\TeamViewer",
            r"C:\Program Files (x86)\TeamViewer",
        ],
        "intune_log_pattern": "TeamViewer",
        "risk_level": "red",
        "capability": (
            "Acceso remoto completo, transferencia de archivos, "
            "grabación de sesiones opcional."
        ),
    },
    "AnyDesk": {
        "registry_keys": [
            r"SOFTWARE\AnyDesk",
            r"SOFTWARE\WOW6432Node\AnyDesk",
        ],
        "programdata_paths": [r"C:\ProgramData\AnyDesk"],
        "program_files_paths": [
            r"C:\Program Files\AnyDesk",
            r"C:\Program Files (x86)\AnyDesk",
        ],
        "intune_log_pattern": "AnyDesk",
        "risk_level": "red",
        "capability": (
            "Acceso remoto completo sin instalación obligatoria. "
            "Puede operar en modo desatendido."
        ),
    },
    "Zoho Assist": {
        "registry_keys": [
            r"SOFTWARE\Zoho Corp\Zoho Assist",
            r"SOFTWARE\WOW6432Node\Zoho Corp",
        ],
        "programdata_paths": [r"C:\ProgramData\Zoho\ZohoAssist"],
        "program_files_paths": [
            r"C:\Program Files\Zoho\ZohoAssist",
            r"C:\Program Files (x86)\Zoho\ZohoAssist",
        ],
        "intune_log_pattern": "Zoho Assist",
        "risk_level": "red",
        "capability": (
            "Soporte remoto, acceso desatendido, grabación de sesiones."
        ),
    },
    "Splashtop": {
        "registry_keys": [
            r"SOFTWARE\Splashtop Inc",
            r"SOFTWARE\WOW6432Node\Splashtop Inc",
        ],
        "programdata_paths": [r"C:\ProgramData\Splashtop"],
        "program_files_paths": [
            r"C:\Program Files\Splashtop",
            r"C:\Program Files (x86)\Splashtop",
        ],
        "intune_log_pattern": "Splashtop",
        "risk_level": "red",
        "capability": (
            "Acceso remoto completo, modo desatendido, grabación de pantalla."
        ),
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
        return True  # Existe pero protegida — también es señal
    except Exception:
        return False


def _is_unusual_time(dt: datetime.datetime) -> bool:
    if dt.weekday() >= 5:
        return True
    return dt.hour < WORK_HOURS_START or dt.hour >= WORK_HOURS_END


def _weekday_name(dt: datetime.datetime) -> str:
    return ["lunes", "martes", "miércoles", "jueves",
            "viernes", "sábado", "domingo"][dt.weekday()]


# ── Detección ────────────────────────────────────────────────────────────────

def _detect_registry(tool_cfg: dict) -> bool:
    for subkey in tool_cfg["registry_keys"]:
        if _reg_key_exists(winreg.HKEY_LOCAL_MACHINE, subkey):
            return True
        if _reg_key_exists(winreg.HKEY_CURRENT_USER, subkey):
            return True
    return False


def _detect_filesystem(tool_cfg: dict) -> tuple[bool, list[str]]:
    found = []
    for p in tool_cfg["programdata_paths"] + tool_cfg["program_files_paths"]:
        if Path(p).exists():
            found.append(p)
    return bool(found), found


def _detect_intune(tool_cfg: dict) -> Optional[dict]:
    pattern = tool_cfg.get("intune_log_pattern")
    if not pattern or not INTUNE_LOG_DIR.exists():
        return None
    for log_file in INTUNE_LOG_DIR.iterdir():
        if not log_file.is_file():
            continue
        try:
            content = log_file.read_text(encoding="utf-8", errors="replace")
            if pattern.lower() in content.lower():
                return {
                    "log_file": str(log_file),
                    "log_mtime": datetime.datetime.fromtimestamp(
                        log_file.stat().st_mtime
                    ).isoformat(),
                    "sha256": _file_hash(log_file),
                }
        except Exception:
            continue
    return None


# ── Lectura de sesiones ──────────────────────────────────────────────────────

def _parse_logmein_sessions(base_path: Path) -> list[dict]:
    """
    Extrae metadatos de sesiones LogMeIn Rescue desde carpetas LMIR*.tmp.
    No intenta descifrar los logs — solo metadatos de filesystem.
    """
    sessions = []
    if not base_path.exists():
        return sessions

    for folder in sorted(base_path.iterdir()):
        if not folder.is_dir() or not folder.name.startswith("LMIR"):
            continue

        created_dt = datetime.datetime.fromtimestamp(folder.stat().st_ctime)
        modified_dt = datetime.datetime.fromtimestamp(folder.stat().st_mtime)

        session = {
            "folder": folder.name,
            "created": created_dt.isoformat(),
            "modified": modified_dt.isoformat(),
            "files": [],
            "flags": [],
        }

        for f in folder.iterdir():
            if f.is_file():
                session["files"].append({
                    "name": f.name,
                    "size_bytes": f.stat().st_size,
                    "created": datetime.datetime.fromtimestamp(
                        f.stat().st_ctime
                    ).isoformat(),
                    "modified": datetime.datetime.fromtimestamp(
                        f.stat().st_mtime
                    ).isoformat(),
                    "sha256": _file_hash(f),
                })

        # Duración estimada por diferencia entre archivos
        mtimes = [f["modified"] for f in session["files"]]
        if len(mtimes) >= 2:
            t0 = datetime.datetime.fromisoformat(min(mtimes))
            t1 = datetime.datetime.fromisoformat(max(mtimes))
            session["duration_seconds"] = int((t1 - t0).total_seconds())
        else:
            session["duration_seconds"] = None

        # Flags de horario inusual
        if _is_unusual_time(created_dt):
            session["flags"].append(
                f"sesion_horario_inusual: {_weekday_name(created_dt)} "
                f"{created_dt.strftime('%H:%M')}"
            )

        # Flag si tiene chatlog (sesión interactiva con técnico)
        if any(f["name"] == "chatlog.dat" for f in session["files"]):
            session["flags"].append("chatlog_presente")

        # Flag si tiene params.txt
        if any(f["name"] == "params.txt" for f in session["files"]):
            session["flags"].append("params_configurados")

        sessions.append(session)

    return sessions


def _parse_generic_sessions(tool_cfg: dict) -> list[dict]:
    """Para herramientas distintas de LogMeIn, busca logs en sus rutas."""
    sessions = []
    for base in tool_cfg["programdata_paths"] + tool_cfg["program_files_paths"]:
        p = Path(base)
        if not p.exists():
            continue
        for log_file in p.rglob("*.log"):
            try:
                stat = log_file.stat()
                mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
                entry = {
                    "log_file": str(log_file),
                    "size_bytes": stat.st_size,
                    "modified": mtime.isoformat(),
                    "sha256": _file_hash(log_file),
                    "flags": [],
                }
                if _is_unusual_time(mtime):
                    entry["flags"].append(
                        f"log_modificado_horario_inusual: "
                        f"{_weekday_name(mtime)} {mtime.strftime('%H:%M')}"
                    )
                sessions.append(entry)
            except Exception:
                continue
    return sessions


# ── Skill principal ──────────────────────────────────────────────────────────

class RemoteAccessAudit:
    SKILL_NAME = "remote_access_audit"

    def __init__(self, engine):
        self.engine = engine
        self.detected_tools = []

    def run(self):
        print("[RemoteAccess] Iniciando auditoría de acceso remoto...")

        for tool_name, tool_cfg in KNOWN_TOOLS.items():
            self._audit_tool(tool_name, tool_cfg)

        # RDP siempre se audita por separado
        self._audit_rdp()

        total = len(self.detected_tools)
        print(
            f"[RemoteAccess] Completado — "
            f"{total} herramienta(s) de acceso remoto detectada(s)"
        )

    # ── Auditoría por herramienta ─────────────────────────────────────────────

    def _audit_tool(self, tool_name: str, tool_cfg: dict):
        from core.audit_engine import AuditFinding

        detected_by = []

        if _detect_registry(tool_cfg):
            detected_by.append("registry")

        fs_detected, fs_paths = _detect_filesystem(tool_cfg)
        if fs_detected:
            detected_by.append("filesystem")

        if not detected_by:
            return  # No detectada

        print(f"[RemoteAccess] Detectado: {tool_name} ({', '.join(detected_by)})")
        self.detected_tools.append(tool_name)

        intune_info = _detect_intune(tool_cfg)
        installed_via_intune = intune_info is not None

        # Sesiones
        sessions = []
        if tool_name == "LogMeIn Rescue":
            for base in tool_cfg["programdata_paths"]:
                sessions.extend(_parse_logmein_sessions(Path(base)))
        else:
            sessions = _parse_generic_sessions(tool_cfg)

        unusual_sessions = [
            s for s in sessions
            if any("inusual" in flag for flag in s.get("flags", []))
        ]

        # Construir flags y determinar riesgo
        flags = []
        if installed_via_intune:
            flags.append(
                "instalado_via_intune: sin consentimiento explícito del trabajador"
            )
        if sessions:
            flags.append(f"{len(sessions)} sesion(es) documentada(s)")
        if unusual_sessions:
            flags.append(
                f"{len(unusual_sessions)} sesion(es) en horario inusual "
                f"(antes de las {WORK_HOURS_START}h, "
                f"después de las {WORK_HOURS_END}h, o fin de semana)"
            )

        risk = tool_cfg["risk_level"]

        # Descripción
        description_parts = [
            f"Herramienta de acceso remoto '{tool_name}' detectada mediante "
            f"{', '.join(detected_by)}."
        ]
        if installed_via_intune:
            description_parts.append(
                "Instalada a través de Microsoft Intune (gestión corporativa) "
                "sin información previa documentada al trabajador."
            )
        if sessions:
            description_parts.append(
                f"Se han documentado {len(sessions)} sesión(es) mediante "
                "metadatos de filesystem (sin descifrar contenido de logs)."
            )
        if unusual_sessions:
            description_parts.append(
                f"Atención: {len(unusual_sessions)} sesión(es) tuvieron lugar "
                "en horario inusual."
            )

        # Issues legales
        legal_issues = []
        if installed_via_intune:
            legal_issues.append(
                "Instalación via MDM/Intune sin información previa — "
                "RGPD art. 13, LOPDGDD art. 87, ET art. 20 bis, "
                "Barbulescu II (TEDH 2017)"
            )
        if sessions:
            legal_issues.append(
                "Cada sesión de acceso remoto es un tratamiento de datos "
                "personales que requiere base legal explícita — RGPD art. 6"
            )
        if unusual_sessions:
            legal_issues.append(
                "Acceso remoto fuera de horario laboral requiere "
                "justificación específica y proporcionalidad — "
                "LOPDGDD art. 87, art. 88 (desconexión digital)"
            )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="remote_access_tool_detected",
            title=(
                f"Herramienta de acceso remoto: {tool_name}"
                + (f" — {len(sessions)} sesión(es)" if sessions else "")
                + (" — horario inusual" if unusual_sessions else "")
                + (" — instalada via Intune" if installed_via_intune else "")
            ),
            description=" ".join(description_parts),
            risk_level=risk,
            technical_risk=(
                f"{tool_cfg['capability']} "
                f"Detectada mediante: {', '.join(detected_by)}."
            ),
            legal_risk=(
                "; ".join(legal_issues)
                if legal_issues
                else "Verificar base legal y política de uso comunicada al trabajador."
            ),
            what_it_is=(
                f"'{tool_name}' es una herramienta de soporte y acceso remoto "
                "que permite a un técnico tomar control del equipo. "
                "Su presencia en el equipo no implica uso indebido, pero "
                "requiere transparencia y base legal documentada."
            ),
            what_it_is_not=(
                "No es prueba por sí sola de vigilancia ilegal. "
                "Puede ser herramienta de soporte IT legítima. "
                "La irregularidad está en la ausencia de información previa "
                "al trabajador, no en la herramienta en sí."
            ),
            raw_data={
                "tool": tool_name,
                "detection_method": detected_by,
                "installed_paths": fs_paths,
                "installed_via_intune": installed_via_intune,
                "intune_log": intune_info,
                "session_count": len(sessions),
                "unusual_session_count": len(unusual_sessions),
                "sessions": sessions,
                "flags": flags,
                "capability": tool_cfg["capability"],
            },
        ))

    def _audit_rdp(self):
        """Audita la configuración de RDP nativo de Windows."""
        from core.audit_engine import AuditFinding

        # Verificar si RDP está habilitado
        try:
            k = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                0, winreg.KEY_READ
            )
            val, _ = winreg.QueryValueEx(k, "fDenyTSConnections")
            winreg.CloseKey(k)
            rdp_enabled = (str(val) == "0")
        except Exception:
            rdp_enabled = False

        if not rdp_enabled:
            return

        print("[RemoteAccess] RDP nativo habilitado — auditando cuentas con acceso")
        self.detected_tools.append("Windows RDP")

        # Cuentas en el grupo RDP
        rdp_accounts = []
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-LocalGroupMember -Group 'Usuarios de escritorio remoto' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object Name, ObjectClass | ConvertTo-Json -Depth 2"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                rdp_accounts = [
                    str(a.get("Name", "")).strip()
                    for a in (data or [])
                    if a.get("Name")
                ]
        except Exception:
            pass

        # Detectar cuentas admin con RDP (mayor riesgo)
        admin_with_rdp = [
            a for a in rdp_accounts
            if any(k in a.lower() for k in ["admin", "it", "emeal", "local"])
        ]

        risk = "orange"
        if admin_with_rdp:
            risk = "red"

        flags = []
        if rdp_accounts:
            flags.append(f"{len(rdp_accounts)} cuenta(s) con acceso RDP habilitado")
        if admin_with_rdp:
            flags.append(
                f"Cuentas con nombre admin/IT con acceso RDP: "
                f"{', '.join(admin_with_rdp)}"
            )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="rdp_native_enabled",
            title=(
                f"RDP nativo habilitado — "
                f"{len(rdp_accounts)} cuenta(s) con acceso"
                + (" — cuentas admin detectadas" if admin_with_rdp else "")
            ),
            description=(
                f"El Escritorio Remoto de Windows (RDP) está habilitado "
                f"en este equipo. {len(rdp_accounts)} cuenta(s) tienen "
                f"acceso RDP configurado."
                + (f" Se han detectado {len(admin_with_rdp)} cuenta(s) "
                   f"con nombre sugestivo de administrador: "
                   f"{', '.join(admin_with_rdp)}."
                   if admin_with_rdp else "")
            ),
            risk_level=risk,
            technical_risk=(
                "RDP habilitado con cuentas de administrador permite "
                "control total del equipo de forma remota. "
                "Las cuentas listadas pueden conectarse sin intervención "
                "del usuario actual del equipo."
            ),
            legal_risk=(
                "El acceso RDP por parte de personal IT a un equipo "
                "asignado a un trabajador debe estar documentado, "
                "justificado y comunicado previamente — "
                "LOPDGDD art. 87, ET art. 20 bis."
            ),
            what_it_is=(
                "RDP (Remote Desktop Protocol) es el protocolo nativo "
                "de Windows para acceso remoto al escritorio. "
                "Estar habilitado no implica uso activo, pero "
                "sí capacidad de acceso."
            ),
            what_it_is_not=(
                "No implica que alguien esté conectándose en este momento. "
                "RDP puede estar habilitado por política corporativa estándar."
            ),
            raw_data={
                "rdp_enabled": True,
                "rdp_accounts": rdp_accounts,
                "admin_accounts_with_rdp": admin_with_rdp,
                "flags": flags,
            },
        ))