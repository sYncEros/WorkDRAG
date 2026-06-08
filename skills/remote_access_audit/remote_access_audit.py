"""
WorkDRAG — Skill: Remote Access Audit
======================================
Detecta herramientas de acceso remoto instaladas en el equipo,
documenta sesiones con metadatos forenses y evalúa riesgo legal.

Operación: solo lectura, sin elevación de privilegios.
Fuentes: registro, filesystem, Intune logs, event viewer accesible.
"""

import os
import re
import json
import hashlib
import subprocess
import winreg
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Constantes ──────────────────────────────────────────────────────────────

SKILL_ID = "remote_access_audit"
SKILL_VERSION = "1.0.0"

# Herramientas conocidas: nombre → metadatos de detección
KNOWN_TOOLS = {
    "LogMeIn Rescue": {
        "registry_keys": [
            r"SOFTWARE\LogMeIn Rescue",
            r"SOFTWARE\WOW6432Node\LogMeIn Rescue",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LogMeIn Rescue",
        ],
        "programdata_paths": [
            r"C:\ProgramData\LogMeIn Rescue Calling Card",
        ],
        "program_files_paths": [
            r"C:\Program Files (x86)\LogMeIn Rescue Calling Card",
            r"C:\Program Files\LogMeIn Rescue Calling Card",
        ],
        "process_names": ["LMIRescue.exe", "lmir.exe", "LMIGuardian.exe"],
        "intune_log_pattern": "LogMeIn Rescue",
        "risk_level": "red",
        "capability": "Control total de escritorio, transferencia de archivos, "
                      "ejecución de comandos de forma remota.",
    },
    "TeamViewer": {
        "registry_keys": [
            r"SOFTWARE\TeamViewer",
            r"SOFTWARE\WOW6432Node\TeamViewer",
        ],
        "programdata_paths": [
            r"C:\ProgramData\TeamViewer",
        ],
        "program_files_paths": [
            r"C:\Program Files\TeamViewer",
            r"C:\Program Files (x86)\TeamViewer",
        ],
        "process_names": ["TeamViewer.exe", "TeamViewer_Service.exe"],
        "intune_log_pattern": "TeamViewer",
        "risk_level": "red",
        "capability": "Acceso remoto completo, transferencia de archivos, "
                      "grabación de sesiones opcional.",
    },
    "AnyDesk": {
        "registry_keys": [
            r"SOFTWARE\AnyDesk",
            r"SOFTWARE\WOW6432Node\AnyDesk",
        ],
        "programdata_paths": [
            r"C:\ProgramData\AnyDesk",
        ],
        "program_files_paths": [
            r"C:\Program Files\AnyDesk",
            r"C:\Program Files (x86)\AnyDesk",
        ],
        "process_names": ["AnyDesk.exe"],
        "intune_log_pattern": "AnyDesk",
        "risk_level": "red",
        "capability": "Acceso remoto completo, sin instalación obligatoria, "
                      "puede operar en modo desatendido.",
    },
    "Zoho Assist": {
        "registry_keys": [
            r"SOFTWARE\Zoho Corp\Zoho Assist",
            r"SOFTWARE\WOW6432Node\Zoho Corp",
        ],
        "programdata_paths": [
            r"C:\ProgramData\Zoho\ZohoAssist",
        ],
        "program_files_paths": [
            r"C:\Program Files\Zoho\ZohoAssist",
            r"C:\Program Files (x86)\Zoho\ZohoAssist",
        ],
        "process_names": ["ZohoAssist.exe", "zaService.exe"],
        "intune_log_pattern": "Zoho Assist",
        "risk_level": "red",
        "capability": "Soporte remoto, acceso desatendido, "
                      "grabación de sesiones.",
    },
    "Splashtop": {
        "registry_keys": [
            r"SOFTWARE\Splashtop Inc",
            r"SOFTWARE\WOW6432Node\Splashtop Inc",
        ],
        "programdata_paths": [
            r"C:\ProgramData\Splashtop",
        ],
        "program_files_paths": [
            r"C:\Program Files\Splashtop",
            r"C:\Program Files (x86)\Splashtop",
        ],
        "process_names": ["SRService.exe", "SplashtopStreamer.exe"],
        "intune_log_pattern": "Splashtop",
        "risk_level": "red",
        "capability": "Acceso remoto completo, modo desatendido, "
                      "grabación de pantalla.",
    },
    "Windows Remote Desktop (RDP)": {
        "registry_keys": [],
        "programdata_paths": [],
        "program_files_paths": [],
        "process_names": ["TermService"],
        "intune_log_pattern": None,
        "risk_level": "orange",
        "capability": "Sesión de escritorio remoto estándar de Windows. "
                      "Riesgo depende de las cuentas con acceso.",
    },
}

# Horas consideradas inusuales (antes de 7:00 y después de 22:00)
UNUSUAL_HOUR_START = 7
UNUSUAL_HOUR_END = 22

INTUNE_LOG_DIR = Path(
    r"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
)


# ── Utilidades ───────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _file_hash(path: Path) -> Optional[str]:
    """SHA-256 de un archivo. Devuelve None si no es accesible."""
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
        return True   # Existe pero protegida — también es señal
    except Exception:
        return False


def _reg_value(hive, subkey: str, value: str) -> Optional[str]:
    try:
        k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(k, value)
        winreg.CloseKey(k)
        return str(val)
    except Exception:
        return None


def _ps(cmd: str, timeout: int = 15) -> str:
    """Ejecuta PowerShell y devuelve stdout. Silencia errores."""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _is_unusual_time(dt: datetime) -> bool:
    """True si la hora es antes de UNUSUAL_HOUR_START o después de UNUSUAL_HOUR_END,
    o si es fin de semana."""
    if dt.weekday() >= 5:   # sábado=5, domingo=6
        return True
    if dt.hour < UNUSUAL_HOUR_START or dt.hour >= UNUSUAL_HOUR_END:
        return True
    return False


# ── Módulos de detección ─────────────────────────────────────────────────────

def _detect_via_registry(tool_name: str, tool_cfg: dict) -> bool:
    for subkey in tool_cfg["registry_keys"]:
        if _reg_key_exists(winreg.HKEY_LOCAL_MACHINE, subkey):
            return True
        if _reg_key_exists(winreg.HKEY_CURRENT_USER, subkey):
            return True
    return False


def _detect_via_filesystem(tool_cfg: dict) -> tuple[bool, list[str]]:
    found_paths = []
    for p in tool_cfg["programdata_paths"] + tool_cfg["program_files_paths"]:
        if Path(p).exists():
            found_paths.append(p)
    return bool(found_paths), found_paths


def _detect_via_intune_logs(tool_cfg: dict) -> Optional[dict]:
    """Busca el log de instalación de Intune para esta herramienta."""
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
                    "log_mtime": datetime.fromtimestamp(
                        log_file.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                    "sha256": _file_hash(log_file),
                    "installed_via_intune": True,
                }
        except Exception:
            continue
    return None


def _detect_rdp_enabled() -> bool:
    val = _reg_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections"
    )
    return val == "0"


# ── Lectura de sesiones ──────────────────────────────────────────────────────

def _parse_logmein_sessions(base_path: Path) -> list[dict]:
    """
    Extrae metadatos de sesiones de LogMeIn Rescue desde las carpetas
    LMIR*.tmp. No intenta descifrar el contenido de los logs.
    """
    sessions = []
    if not base_path.exists():
        return sessions

    for folder in sorted(base_path.iterdir()):
        if not folder.is_dir() or not folder.name.startswith("LMIR"):
            continue

        session = {
            "folder": folder.name,
            "created": datetime.fromtimestamp(
                folder.stat().st_ctime, tz=timezone.utc
            ).isoformat(),
            "modified": datetime.fromtimestamp(
                folder.stat().st_mtime, tz=timezone.utc
            ).isoformat(),
            "files": [],
            "flags": [],
        }

        for f in folder.iterdir():
            if f.is_file():
                session["files"].append({
                    "name": f.name,
                    "size_bytes": f.stat().st_size,
                    "created": datetime.fromtimestamp(
                        f.stat().st_ctime, tz=timezone.utc
                    ).isoformat(),
                    "modified": datetime.fromtimestamp(
                        f.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                    "sha256": _file_hash(f),
                })

        # Calcular duración aproximada por diferencia de mtime entre archivos
        mtimes = [
            f["modified"] for f in session["files"]
            if f["modified"]
        ]
        if len(mtimes) >= 2:
            t0 = datetime.fromisoformat(min(mtimes))
            t1 = datetime.fromisoformat(max(mtimes))
            duration_s = int((t1 - t0).total_seconds())
            session["duration_seconds"] = duration_s
        else:
            session["duration_seconds"] = None

        # Flags de horario inusual
        created_dt = datetime.fromisoformat(session["created"])
        if _is_unusual_time(created_dt):
            weekday_name = [
                "lunes", "martes", "miércoles", "jueves",
                "viernes", "sábado", "domingo"
            ][created_dt.weekday()]
            session["flags"].append(
                f"sesion_horario_inusual: {weekday_name} "
                f"{created_dt.strftime('%H:%M')} UTC"
            )

        # Flag si tiene chatlog (indica sesión interactiva con técnico)
        if any(f["name"] == "chatlog.dat" for f in session["files"]):
            session["flags"].append("chatlog_presente")

        # Flag si tiene params.txt (indica sesión con parámetros configurados)
        if any(f["name"] == "params.txt" for f in session["files"]):
            session["flags"].append("params_configurados")

        sessions.append(session)

    return sessions


def _get_generic_sessions(tool_name: str, tool_cfg: dict) -> list[dict]:
    """Para herramientas distintas de LogMeIn, busca logs en sus rutas."""
    sessions = []
    for base in tool_cfg["programdata_paths"] + tool_cfg["program_files_paths"]:
        p = Path(base)
        if not p.exists():
            continue
        # Buscar archivos de log con timestamps recientes
        for log_file in p.rglob("*.log"):
            try:
                stat = log_file.stat()
                mtime = datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                )
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
                        f"{mtime.strftime('%A %H:%M')} UTC"
                    )
                sessions.append(entry)
            except Exception:
                continue
    return sessions


# ── Evaluación de riesgo legal ───────────────────────────────────────────────

def _legal_assessment(tool_name: str, installed_via_intune: bool,
                      session_count: int, unusual_sessions: int) -> dict:
    issues = []

    if installed_via_intune:
        issues.append({
            "issue": "Instalación via MDM/Intune sin información previa documentada",
            "legal_ref": "RGPD art. 13, LOPDGDD art. 87, ET art. 20 bis",
            "risk": "high",
            "detail": "La instalación de herramientas de acceso remoto mediante "
                      "gestión corporativa sin notificación previa al trabajador "
                      "puede vulnerar el derecho a la intimidad digital.",
        })

    if session_count > 0:
        issues.append({
            "issue": f"{session_count} sesiones de acceso remoto documentadas",
            "legal_ref": "RGPD art. 5.1.a (transparencia), LOPDGDD art. 87",
            "risk": "high",
            "detail": "Cada sesión de acceso remoto constituye un tratamiento de "
                      "datos personales que requiere base legal explícita y, "
                      "según doctrina Barbulescu II (TEDH 2017), información "
                      "previa adecuada al trabajador.",
        })

    if unusual_sessions > 0:
        issues.append({
            "issue": f"{unusual_sessions} sesiones en horario inusual "
                     "(madrugada o fin de semana)",
            "legal_ref": "LOPDGDD art. 87, ET art. 20 bis",
            "risk": "high",
            "detail": "El acceso remoto fuera del horario laboral habitual "
                      "requiere justificación específica y proporcionalidad.",
        })

    overall_risk = "red" if issues else "green"
    return {
        "overall_risk": overall_risk,
        "issues": issues,
        "dpo_requests": [
            "Identidad del técnico en cada sesión documentada",
            "Finalidad y base legal de cada acceso remoto (RGPD art. 6)",
            "Política de acceso remoto corporativa y si fue comunicada al trabajador",
            "Confirmación de si las sesiones fueron grabadas y retención de datos",
        ] if issues else [],
    }


# ── Función principal ─────────────────────────────────────────────────────────

def run_audit() -> dict:
    """
    Ejecuta la auditoría completa de herramientas de acceso remoto.
    Devuelve un diccionario con todos los hallazgos.
    """
    result = {
        "skill_id": SKILL_ID,
        "skill_version": SKILL_VERSION,
        "timestamp": _now_iso(),
        "hostname": os.environ.get("COMPUTERNAME", "unknown"),
        "findings": [],
        "summary": {
            "tools_detected": 0,
            "total_sessions": 0,
            "unusual_sessions": 0,
            "installed_via_intune": False,
            "max_risk": "green",
        },
    }

    # ── RDP: caso especial ───────────────────────────────────────────────────
    if _detect_rdp_enabled():
        rdp_cfg = KNOWN_TOOLS["Windows Remote Desktop (RDP)"]

        # Contar cuentas locales con acceso RDP
        rdp_accounts_raw = _ps(
            "Get-LocalGroupMember -Group 'Usuarios de escritorio remoto' "
            "| Select-Object -ExpandProperty Name"
        )
        rdp_accounts = [
            a.strip() for a in rdp_accounts_raw.splitlines() if a.strip()
        ]

        finding = {
            "tool": "Windows Remote Desktop (RDP)",
            "detected": True,
            "detection_method": ["registry"],
            "risk_level": rdp_cfg["risk_level"],
            "capability": rdp_cfg["capability"],
            "rdp_accounts": rdp_accounts,
            "flags": [],
            "legal": _legal_assessment(
                "Windows Remote Desktop (RDP)",
                installed_via_intune=False,
                session_count=0,
                unusual_sessions=0,
            ),
        }

        if len(rdp_accounts) > 0:
            finding["flags"].append(
                f"{len(rdp_accounts)} cuenta(s) con acceso RDP habilitado"
            )

        result["findings"].append(finding)
        result["summary"]["tools_detected"] += 1

    # ── Resto de herramientas ────────────────────────────────────────────────
    for tool_name, tool_cfg in KNOWN_TOOLS.items():
        if tool_name == "Windows Remote Desktop (RDP)":
            continue

        detected_by = []

        # Registro
        if _detect_via_registry(tool_name, tool_cfg):
            detected_by.append("registry")

        # Filesystem
        fs_detected, fs_paths = _detect_via_filesystem(tool_cfg)
        if fs_detected:
            detected_by.append("filesystem")

        if not detected_by:
            continue   # No detectada, no incluir en el informe

        # Intune
        intune_info = _detect_via_intune_logs(tool_cfg)
        installed_via_intune = intune_info is not None

        # Sesiones
        sessions = []
        unusual_count = 0

        if tool_name == "LogMeIn Rescue":
            for base in tool_cfg["programdata_paths"]:
                sessions.extend(_parse_logmein_sessions(Path(base)))
        else:
            sessions = _get_generic_sessions(tool_name, tool_cfg)

        for s in sessions:
            if s.get("flags") and any(
                "inusual" in f for f in s["flags"]
            ):
                unusual_count += 1

        finding = {
            "tool": tool_name,
            "detected": True,
            "detection_method": detected_by,
            "installed_paths": fs_paths,
            "risk_level": tool_cfg["risk_level"],
            "capability": tool_cfg["capability"],
            "installed_via_intune": installed_via_intune,
            "intune_log": intune_info,
            "sessions": sessions,
            "session_count": len(sessions),
            "unusual_sessions": unusual_count,
            "flags": [],
            "legal": _legal_assessment(
                tool_name,
                installed_via_intune=installed_via_intune,
                session_count=len(sessions),
                unusual_sessions=unusual_count,
            ),
        }

        # Flags de resumen
        if installed_via_intune:
            finding["flags"].append(
                "instalado_via_intune: sin consentimiento explícito del trabajador"
            )
        if len(sessions) > 0:
            finding["flags"].append(
                f"{len(sessions)} sesion(es) documentada(s)"
            )
        if unusual_count > 0:
            finding["flags"].append(
                f"{unusual_count} sesion(es) en horario inusual"
            )

        result["findings"].append(finding)
        result["summary"]["tools_detected"] += 1
        result["summary"]["total_sessions"] += len(sessions)
        result["summary"]["unusual_sessions"] += unusual_count
        if installed_via_intune:
            result["summary"]["installed_via_intune"] = True

    # ── Riesgo global ────────────────────────────────────────────────────────
    risk_order = {"green": 0, "yellow": 1, "orange": 2, "red": 3}
    max_risk = "green"
    for f in result["findings"]:
        r = f.get("risk_level", "green")
        if risk_order.get(r, 0) > risk_order.get(max_risk, 0):
            max_risk = r
    result["summary"]["max_risk"] = max_risk

    return result


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    output = run_audit()

    # Imprimir resumen legible
    s = output["summary"]
    print(f"\n{'='*60}")
    print(f"  WorkDRAG — Remote Access Audit v{SKILL_VERSION}")
    print(f"  {output['timestamp']}")
    print(f"{'='*60}")
    print(f"  Herramientas detectadas : {s['tools_detected']}")
    print(f"  Sesiones documentadas   : {s['total_sessions']}")
    print(f"  Sesiones horario inusual: {s['unusual_sessions']}")
    print(f"  Instalado via Intune    : {s['installed_via_intune']}")
    print(f"  Riesgo máximo           : {s['max_risk'].upper()}")
    print(f"{'='*60}\n")

    for finding in output["findings"]:
        print(f"  [{finding['risk_level'].upper()}] {finding['tool']}")
        print(f"    Detección : {', '.join(finding['detection_method'])}")
        if finding.get("session_count"):
            print(f"    Sesiones  : {finding['session_count']}")
        for flag in finding.get("flags", []):
            print(f"    ⚑ {flag}")
        for issue in finding.get("legal", {}).get("issues", []):
            print(f"    ⚖ {issue['issue']}")
        print()

    # Exportar JSON
    out_path = Path("remote_access_audit_result.json")
    out_path.write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"  Resultado guardado en: {out_path.resolve()}")
    print(f"  SHA-256: {_file_hash(out_path)}\n")

    sys.exit(0 if s["max_risk"] == "green" else 1)