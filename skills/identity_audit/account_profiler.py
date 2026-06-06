# skills/identity_audit/account_profiler.py
"""
Account Profiler — módulo de Identity Audit
Perfila cada cuenta detectada: qué es, qué hace,
cuándo fue creada, qué procesos tiene, qué grupos,
y por qué es sospechosa.
"""

import subprocess
import json
import psutil
import time
from datetime import datetime


# Cuentas de sistema conocidas — no perfilar
SYSTEM_ACCOUNTS = {
    "system", "local service", "network service",
    "defaultaccount", "wdagutilityaccount",
    "nt authority\\system", "nt authority\\localservice",
    "nt authority\\networkservice", "guest",
}

# Grupos de alto riesgo
HIGH_RISK_GROUPS = {
    "administrators", "administradores",
    "domain admins", "administradores del dominio",
    "remote desktop users", "usuarios de escritorio remoto",
    "remote management users",
    "schema admins", "enterprise admins",
}

# Procesos conocidos asociados a vigilancia
SURVEILLANCE_PROCESS_MAP = {
    "csfalconservice":   "CrowdStrike Falcon EDR",
    "mssense":           "Microsoft Defender for Endpoint",
    "sentinelagent":     "SentinelOne EDR",
    "taniumclient":      "Tanium Agent",
    "activtrak":         "ActivTrak (monitorización productividad)",
    "teramind":          "Teramind (monitorización productividad)",
    "onedrive":          "Microsoft OneDrive (sync nube)",
    "filecoauth":        "OneDrive File Co-Auth",
    "diagtrack":         "Windows Telemetry (DiagTrack)",
    "rdpclip":           "RDP Clipboard (sesión remota activa)",
    "teamviewer":        "TeamViewer (acceso remoto)",
    "anydesk":           "AnyDesk (acceso remoto)",
}

# Razones de sospecha
def _assess_suspicion(account: dict) -> list:
    flags = []
    name = account.get("name", "").lower()
    groups = [g.lower() for g in account.get("groups", [])]

    if account.get("password_never_expires") and account.get("enabled"):
        flags.append("⚠️ Contraseña permanente — no expira nunca")

    if account.get("enabled") and not account.get("last_logon"):
        flags.append("⚠️ Habilitada pero nunca usada — posible backdoor")

    if any(g in HIGH_RISK_GROUPS for g in groups):
        risky = [g for g in groups if g in HIGH_RISK_GROUPS]
        flags.append(f"⚠️ En grupos de alto privilegio: {', '.join(risky)}")

    suspicious_names = [
        "admin", "support", "helpdesk", "remote",
        "backup", "monitor", "agent", "service",
        "svc", "scan", "audit", "test", "temp"
    ]
    matched = [s for s in suspicious_names if s in name]
    if matched:
        flags.append(
            f"⚠️ Nombre sugiere función especial: {', '.join(matched)}"
        )

    if account.get("source") == "Local" and account.get("enabled"):
        flags.append("ℹ️ Cuenta local habilitada — no es cuenta de dominio")

    return flags


class AccountProfiler:
    MAX_PROFILED_ACCOUNTS = 8
    MAX_PROFILING_SECONDS = 75.0

    def __init__(self):
        self.process_by_user = self._map_processes_to_users()

    def _map_processes_to_users(self) -> dict:
        """Mapea procesos activos a usuarios."""
        by_user = {}
        for proc in psutil.process_iter(
            ["pid", "name", "username", "cpu_percent", "memory_info"]
        ):
            try:
                user = proc.info.get("username", "") or "SYSTEM"
                user = user.split("\\")[-1].lower()
                if user not in by_user:
                    by_user[user] = []
                by_user[user].append({
                    "pid":  proc.info["pid"],
                    "name": proc.info["name"],
                    "known": SURVEILLANCE_PROCESS_MAP.get(
                        proc.info["name"].lower().replace(".exe", "")
                    )
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return by_user

    def profile_all_accounts(self) -> list:
        """Perfila todas las cuentas locales del sistema."""
        accounts = self._get_accounts()
        profiles = []
        started_at = time.monotonic()
        profiled = 0

        for acc in accounts:
            if profiled >= self.MAX_PROFILED_ACCOUNTS:
                break
            if (time.monotonic() - started_at) > self.MAX_PROFILING_SECONDS:
                break

            name = acc.get("Name", "")
            if name.lower() in SYSTEM_ACCOUNTS:
                continue

            profile = self._profile_account(name, acc)
            profiles.append(profile)
            profiled += 1

        return profiles

    def _get_accounts(self) -> list:
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-LocalUser | Select-Object Name, Enabled, "
                 "LastLogon, PasswordLastSet, PasswordNeverExpires, "
                 "Description, SID | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                return [data] if isinstance(data, dict) else data
        except Exception:
            pass
        return []

    def _profile_account(self, name: str, raw: dict) -> dict:
        """Construye el perfil completo de una cuenta."""
        groups    = self._get_account_groups(name)
        sessions  = self._get_account_sessions(name)
        services  = self._get_account_services(name)
        procs     = self.process_by_user.get(name.lower(), [])
        events    = self._get_account_events(name)

        account = {
            "name":                 name,
            "enabled":              raw.get("Enabled", False),
            "description":          raw.get("Description", ""),
            "last_logon":           str(raw.get("LastLogon", "") or "Nunca"),
            "password_last_set":    str(raw.get("PasswordLastSet", "") or ""),
            "password_never_expires": raw.get("PasswordNeverExpires", False),
            "sid":                  str(raw.get("SID", {}).get("Value", "")),
            "groups":               groups,
            "active_sessions":      sessions,
            "running_services":     services,
            "running_processes":    procs[:10],
            "recent_events":        events,
            "source":               "Local",
        }

        account["suspicion_flags"] = _assess_suspicion(account)
        account["risk_level"] = self._compute_risk(account)
        account["summary"]    = self._build_summary(account)

        return account

    def _get_account_groups(self, name: str) -> list:
        groups = []
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-LocalUser -Name '{name}' | "
                 f"Get-LocalGroup -ErrorAction SilentlyContinue).Name"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                groups = [
                    l.strip() for l in result.stdout.strip().split("\n")
                    if l.strip()
                ]
        except Exception:
            pass

        # Alternativa: buscar en qué grupos está el usuario
        if not groups:
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-LocalGroup | ForEach-Object { "
                     "$g = $_; "
                     "try { $members = Get-LocalGroupMember $g "
                     "-ErrorAction SilentlyContinue; "
                     f"if ($members.Name -like '*{name}*') "
                     "{ $g.Name } } catch {} }"],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    groups = [
                        l.strip()
                        for l in result.stdout.strip().split("\n")
                        if l.strip()
                    ]
            except Exception:
                pass

        return groups

    def _get_account_sessions(self, name: str) -> list:
        sessions = []
        try:
            result = subprocess.run(
                ["query", "user"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n")[1:]:
                    if name.lower() in line.lower():
                        sessions.append(line.strip())
        except Exception:
            pass
        return sessions

    def _get_account_services(self, name: str) -> list:
        services = []
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-WmiObject Win32_Service | "
                 f"Where-Object {{ $_.StartName -like '*{name}*' }} | "
                 f"Select-Object Name, DisplayName, State, StartName | "
                 f"ConvertTo-Json"],
                capture_output=True, text=True, timeout=8
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                services = [
                    {
                        "name":    s.get("Name"),
                        "display": s.get("DisplayName"),
                        "state":   s.get("State"),
                    }
                    for s in (data or [])
                ]
        except Exception:
            pass
        return services

    def _get_account_events(self, name: str) -> list:
        events = []
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-WinEvent -FilterHashtable "
                 f"@{{LogName='Security'; Id=4624; "
                 f"StartTime=(Get-Date).AddDays(-7)}} "
                 f"-MaxEvents 30 -ErrorAction SilentlyContinue | "
                 f"Where-Object {{ $_.Message -like '*{name}*' }} | "
                 f"Select-Object TimeCreated, Id, Message | "
                 f"Select-Object -First 5 | ConvertTo-Json -Depth 1"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                events = [
                    {
                        "time": str(e.get("TimeCreated", "")),
                        "id":   e.get("Id"),
                        "type": "logon"
                    }
                    for e in (data or [])
                ]
        except Exception:
            pass
        return events

    def _compute_risk(self, account: dict) -> str:
        flags = account.get("suspicion_flags", [])
        groups = [g.lower() for g in account.get("groups", [])]

        if not account.get("enabled"):
            return "green"
        if any(g in {"administrators", "administradores",
                     "domain admins"} for g in groups):
            return "orange" if not flags else "red"
        if len(flags) >= 2:
            return "orange"
        if flags:
            return "yellow"
        return "green"

    def _build_summary(self, account: dict) -> str:
        parts = []
        name = account["name"]

        if not account["enabled"]:
            return f"{name} — cuenta deshabilitada, sin riesgo activo"

        last = account["last_logon"]
        if "Nunca" in last:
            parts.append("nunca ha iniciado sesión")
        else:
            parts.append(f"último acceso: {last[:10]}")

        groups = account.get("groups", [])
        if groups:
            parts.append(f"grupos: {', '.join(groups[:3])}")

        services = account.get("running_services", [])
        if services:
            svc_names = [s["display"] or s["name"] for s in services[:2]]
            parts.append(f"ejecuta servicios: {', '.join(svc_names)}")

        procs = account.get("running_processes", [])
        known_procs = [
            p["known"] for p in procs if p.get("known")
        ]
        if known_procs:
            parts.append(
                f"procesos relevantes: {', '.join(known_procs[:2])}"
            )

        flags = account.get("suspicion_flags", [])
        if flags:
            parts.append(f"{len(flags)} alertas de seguridad")

        return f"{name} — {' | '.join(parts)}"