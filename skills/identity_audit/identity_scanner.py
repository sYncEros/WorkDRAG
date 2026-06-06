# skills/identity_audit/identity_scanner.py
"""
Skill 11 — Identity & Access Audit
Detecta cuentas locales, grupos de administradores,
sesiones activas, tokens de acceso y privilegios
que pueden afectar a los derechos del trabajador.
"""

import winreg
import subprocess
import json
import psutil
from datetime import datetime
from pathlib import Path
from core.capability_intel import (
    get_sources,
    gpresult_summary,
    fltmc_summary,
    confidence_from_evidence,
)


# Cuentas y grupos de alto privilegio a vigilar
HIGH_PRIVILEGE_GROUPS = [
    "Administrators", "Administradores",
    "Domain Admins", "Administradores del dominio",
    "Enterprise Admins", "Administradores de empresa",
    "Schema Admins", "Administradores de esquema",
    "Remote Desktop Users", "Usuarios de escritorio remoto",
    "Remote Management Users",
]

# Procesos que pueden indicar sesión remota activa
REMOTE_SESSION_INDICATORS = [
    "rdpclip",        # RDP activo
    "tstheme",        # Terminal Services
    "dwm",            # Desktop Window Manager (puede ser remoto)
    "winvnc",         # VNC
    "tvnserver",      # TightVNC
    "vncserver",      # VNC genérico
    "screenshare",    # Compartición de pantalla
]

# Tokens y credenciales almacenadas sospechosas
CREDENTIAL_STORE_PATHS = [
    Path.home() / "AppData/Roaming/Microsoft/Credentials",
    Path.home() / "AppData/Local/Microsoft/Credentials",
    Path("C:/Windows/System32/config/systemprofile/AppData/Local"
         "/Microsoft/Credentials"),
    Path("C:/Windows/System32/config/systemprofile/AppData/Roaming"
            "/Microsoft/Credentials"),
    Path.home() / "AppData/Roaming/Microsoft/Protect",
    Path.home() / "AppData/Local/Microsoft/Protect",
    Path("C:/Windows/System32/config/systemprofile/AppData/Local"
         "/Microsoft/Protect"),
    Path("C:/Windows/System32/config/systemprofile/AppData/Roaming"
         "/Microsoft/Protect"),
    
]


class IdentityAudit:
    SKILL_NAME = "identity_audit"

    def __init__(self, engine):
        self.engine = engine
        self.running_procs = self._get_processes()

    def run(self):
        print("[Identity] Iniciando auditoría de identidad y acceso...")
        self._check_local_accounts()
        self._check_admin_group()
        self._check_active_sessions()
        self._check_remote_sessions()
        self._check_stored_credentials()
        self._check_service_accounts()
        self._check_logon_rights()
        self._check_privileged_processes()
        self._profile_accounts()

    def _get_processes(self) -> set:
        procs = set()
        for p in psutil.process_iter(["name"]):
            try:
                procs.add(p.info["name"].lower().replace(".exe", ""))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs

    # ── Cuentas locales ────────────────────────────────────────────

    def _check_local_accounts(self):
        from core.audit_engine import AuditFinding

        accounts = []
        suspicious = []

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-LocalUser | Select-Object Name, Enabled, "
                 "LastLogon, PasswordLastSet, "
                 "UserMayChangePassword, PasswordNeverExpires | "
                 "ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                accounts = data

                for acc in accounts:
                    flags = []
                    name = acc.get("Name", "").lower()

                    # Cuenta habilitada con contraseña que no expira
                    if (acc.get("Enabled") and
                            acc.get("PasswordNeverExpires")):
                        flags.append("password_never_expires")

                    # Cuenta nunca usada pero habilitada
                    if acc.get("Enabled") and not acc.get("LastLogon"):
                        flags.append("enabled_never_used")

                    # Cuentas con nombres sospechosos
                    suspicious_names = [
                        "admin", "administrator", "service",
                        "support", "helpdesk", "remote",
                        "backup", "monitor", "agent"
                    ]
                    if any(s in name for s in suspicious_names):
                        flags.append("suspicious_name")

                    if flags:
                        suspicious.append({
                            "name": acc.get("Name"),
                            "enabled": acc.get("Enabled"),
                            "last_logon": str(acc.get("LastLogon", "")),
                            "flags": flags
                        })

        except Exception as e:
            print(f"[Identity] Error leyendo cuentas: {e}")

        if accounts:
            risk = "orange" if suspicious else "yellow"
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="identity_local_accounts",
                title=f"Cuentas locales detectadas "
                      f"({len(accounts)} total, "
                      f"{len(suspicious)} sospechosas)",
                description=(
                    f"El sistema tiene {len(accounts)} cuentas locales. "
                    f"{len(suspicious)} tienen características "
                    f"que merecen revisión."
                ),
                risk_level=risk,
                technical_risk=(
                    "Cuentas locales con contraseña que no expira o "
                    "nunca usadas pueden ser puertas traseras para "
                    "acceso remoto no autorizado al equipo."
                ),
                legal_risk=(
                    "Cuentas de servicio o soporte no documentadas "
                    "pueden permitir acceso al equipo del trabajador "
                    "sin su conocimiento. "
                    "Bajo LOPDGDD art. 87 el trabajador tiene derecho "
                    "a saber quién puede acceder a su dispositivo."
                ),
                what_it_is=(
                    "Cuentas de usuario locales creadas en el equipo, "
                    "distintas de las cuentas de dominio corporativo."
                ),
                what_it_is_not=(
                    "Las cuentas de sistema (DefaultAccount, "
                    "WDAGUtilityAccount) son normales en Windows. "
                    "El riesgo está en cuentas habilitadas "
                    "no documentadas."
                ),
                raw_data={
                    "total_accounts": len(accounts),
                    "suspicious": suspicious,
                    "all_accounts": [
                        {"name": a.get("Name"),
                         "enabled": a.get("Enabled")}
                        for a in accounts
                    ]
                }
            ))

    # ── Grupo de administradores ───────────────────────────────────

    def _check_admin_group(self):
        from core.audit_engine import AuditFinding

        admin_members = []

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-LocalGroupMember -Group 'Administrators' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object Name, ObjectClass, PrincipalSource | "
                 "ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                admin_members = data or []
        except Exception as e:
            print(f"[Identity] Error leyendo admins: {e}")

        # También intenta con nombre en español
        if not admin_members:
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-LocalGroupMember -Group 'Administradores' "
                     "-ErrorAction SilentlyContinue | "
                     "Select-Object Name, ObjectClass, "
                     "PrincipalSource | ConvertTo-Json"],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    data = json.loads(result.stdout)
                    if isinstance(data, dict):
                        data = [data]
                    admin_members = data or []
            except Exception:
                pass

        if admin_members:
            # Cuentas no-usuario (grupos, servicios) en administradores
            non_user_admins = [
                m for m in admin_members
                if m.get("ObjectClass") != "User"
            ]
            risk = "orange" if len(admin_members) > 3 else "yellow"

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="identity_admin_group",
                title=f"Grupo Administradores: "
                      f"{len(admin_members)} miembros",
                description=(
                    f"El grupo de administradores locales tiene "
                    f"{len(admin_members)} miembros. "
                    + (f"{len(non_user_admins)} son grupos o servicios, "
                       f"no usuarios individuales."
                       if non_user_admins else "")
                ),
                risk_level=risk,
                technical_risk=(
                    "Los administradores locales tienen acceso "
                    "completo al equipo: pueden leer cualquier archivo, "
                    "instalar software, acceder a credenciales "
                    "y monitorizar toda la actividad."
                ),
                legal_risk=(
                    "El trabajador tiene derecho a saber qué cuentas "
                    "tienen acceso administrativo a su equipo. "
                    "Un número elevado de administradores aumenta "
                    "el riesgo de acceso no autorizado. "
                    "LOPDGDD art. 87 y RGPD art. 32."
                ),
                what_it_is=(
                    "Lista de cuentas con privilegios de administrador "
                    "local en el equipo del trabajador."
                ),
                what_it_is_not=(
                    "Tener administradores corporativos en el equipo "
                    "es normal en entornos gestionados. "
                    "El problema es la falta de transparencia "
                    "sobre quién tiene acceso y con qué finalidad."
                ),
                raw_data={
                    "admin_members": [
                        {"name": m.get("Name"),
                         "type": m.get("ObjectClass"),
                         "source": m.get("PrincipalSource")}
                        for m in admin_members
                    ],
                    "non_user_admins": non_user_admins
                }
            ))
            print(
                f"[Identity] Administradores locales: "
                f"{len(admin_members)}"
            )

    # ── Sesiones activas ───────────────────────────────────────────

    def _check_active_sessions(self):
        from core.audit_engine import AuditFinding

        sessions = []

        try:
            result = subprocess.run(
                ["query", "session"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        sessions.append({
                            "raw": line.strip(),
                            "active": "Activ" in line or "Active" in line
                        })
        except Exception:
            pass

        # Sesiones múltiples pueden indicar acceso remoto simultáneo
        active_sessions = [s for s in sessions if s["active"]]

        if len(active_sessions) > 1:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="identity_multiple_sessions",
                title=f"Múltiples sesiones activas simultáneas "
                      f"({len(active_sessions)})",
                description=(
                    f"Hay {len(active_sessions)} sesiones activas "
                    f"simultáneas en el equipo. "
                    "Puede indicar acceso remoto concurrente."
                ),
                risk_level="orange",
                technical_risk=(
                    "Múltiples sesiones simultáneas pueden indicar "
                    "que alguien está accediendo remotamente al equipo "
                    "mientras el trabajador lo usa, "
                    "pudiendo ver su actividad en tiempo real."
                ),
                legal_risk=(
                    "El acceso remoto simultáneo sin conocimiento "
                    "del trabajador puede vulnerar LOPDGDD art. 87 "
                    "y constituir vigilancia encubierta."
                ),
                what_it_is=(
                    "Sesiones de usuario activas en el sistema, "
                    "incluyendo sesiones locales y remotas."
                ),
                what_it_is_not=(
                    "Una segunda sesión puede ser una sesión de "
                    "servicio de sistema, no necesariamente "
                    "un acceso remoto humano."
                ),
                raw_data={"sessions": sessions}
            ))

    # ── Sesiones remotas ───────────────────────────────────────────

    def _check_remote_sessions(self):
        from core.audit_engine import AuditFinding

        remote_indicators = []

        # Procesos de sesión remota activos
        for proc in REMOTE_SESSION_INDICATORS:
            if proc in self.running_procs:
                remote_indicators.append(proc)

        # Verifica si RDP está habilitado
        rdp_enabled = False
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                0, winreg.KEY_READ
            )
            val, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            rdp_enabled = (val == 0)
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        # Verifica conexiones RDP activas
        rdp_connections = []
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetTCPConnection -LocalPort 3389 "
                 "-State Established "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object LocalAddress, RemoteAddress, "
                 "State | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                rdp_connections = data or []
        except Exception:
            pass

        if rdp_enabled or remote_indicators or rdp_connections:
            risk = "red" if rdp_connections else "orange"
            sources = get_sources(
                "event_and_logging_capabilities",
                "worker_rights_and_surveillance_context",
            )
            triangulation = {
                "gpresult": gpresult_summary(),
                "fltmc_filters": fltmc_summary(),
            }
            direct_count = len(remote_indicators) + len(rdp_connections) + (1 if rdp_enabled else 0)
            confidence = confidence_from_evidence(
                sources,
                triangulation,
                direct_indicators_count=direct_count,
            )
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="identity_remote_access",
                title="Acceso remoto habilitado"
                      + (" — conexión RDP ACTIVA"
                         if rdp_connections else ""),
                description=(
                    ("RDP está habilitado en este equipo. "
                     if rdp_enabled else "")
                    + (f"Procesos de acceso remoto activos: "
                       f"{', '.join(remote_indicators)}. "
                       if remote_indicators else "")
                    + (f"Conexiones RDP establecidas: "
                       f"{len(rdp_connections)}."
                       if rdp_connections else "")
                ),
                risk_level=risk,
                technical_risk=(
                    "Con RDP habilitado, cualquier administrador "
                    "puede conectarse remotamente al escritorio "
                    "del trabajador y ver o controlar todo. "
                    "Una conexión RDP activa significa que alguien "
                    "puede estar viendo el escritorio ahora mismo."
                ),
                legal_risk=(
                    "El acceso remoto al escritorio sin notificación "
                    "al trabajador puede constituir vigilancia "
                    "encubierta bajo LOPDGDD art. 87. "
                    "Una conexión RDP activa no consentida podría "
                    "vulnerar adicionalmente el art. 197 del "
                    "Código Penal."
                ),
                what_it_is=(
                    "Protocolo de escritorio remoto que permite "
                    "a terceros ver y controlar el equipo "
                    "a través de la red."
                ),
                what_it_is_not=(
                    "RDP habilitado es normal en entornos corporativos "
                    "para soporte técnico. El problema es el acceso "
                    "sin notificación ni consentimiento del trabajador."
                ),
                raw_data={
                    "rdp_enabled": rdp_enabled,
                    "remote_processes": remote_indicators,
                    "active_rdp_connections": rdp_connections,
                    "independent_sources": sources,
                    "triangulation": triangulation,
                    "confidence": confidence,
                }
            ))
            print(
                f"[Identity] RDP: {'habilitado' if rdp_enabled else 'deshabilitado'}"
                + (f" | Conexiones activas: {len(rdp_connections)}"
                   if rdp_connections else "")
            )

    # ── Credenciales almacenadas ───────────────────────────────────

    def _check_stored_credentials(self):
        from core.audit_engine import AuditFinding

        stored_creds = []

        try:
            result = subprocess.run(
                ["cmdkey", "/list"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                current = {}
                for line in lines:
                    line = line.strip()
                    if line.startswith("Destino:") or \
                       line.startswith("Target:"):
                        if current:
                            stored_creds.append(current)
                        current = {"target": line.split(":", 1)[-1].strip()}
                    elif line.startswith("Tipo:") or \
                         line.startswith("Type:"):
                        current["type"] = line.split(":", 1)[-1].strip()
                    elif line.startswith("Usuario:") or \
                         line.startswith("User:"):
                        current["user"] = line.split(":", 1)[-1].strip()
                if current and "target" in current:
                    stored_creds.append(current)
        except Exception as e:
            print(f"[Identity] Error leyendo credenciales: {e}")

        # Filtra entradas vacías
        stored_creds = [c for c in stored_creds if c.get("target")]

        if stored_creds:
            # Credenciales corporativas de alto riesgo
            corporate_creds = [
                c for c in stored_creds
                if any(kw in c.get("target", "").lower()
                       for kw in ["domain", "windows", "rdp",
                                  "termsrv", "mstsc"])
            ]

            risk = "orange" if corporate_creds else "yellow"

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="identity_stored_credentials",
                title=f"Credenciales almacenadas en Windows "
                      f"Credential Manager ({len(stored_creds)})",
                description=(
                    f"Windows tiene {len(stored_creds)} credenciales "
                    f"almacenadas. "
                    + (f"{len(corporate_creds)} son credenciales "
                       f"corporativas de acceso remoto."
                       if corporate_creds else "")
                ),
                risk_level=risk,
                technical_risk=(
                    "Las credenciales almacenadas en Windows "
                    "Credential Manager están cifradas con la clave "
                    "del perfil de usuario. "
                    "Un proceso con privilegios de administrador "
                    "puede extraerlas usando herramientas estándar."
                ),
                legal_risk=(
                    "Las credenciales almacenadas pueden incluir "
                    "contraseñas de sistemas personales del trabajador. "
                    "Su acceso no autorizado vulnera LOPDGDD "
                    "y puede constituir delito bajo CP art. 197."
                ),
                what_it_is=(
                    "Almacén seguro de Windows donde se guardan "
                    "credenciales para acceso automático a recursos "
                    "de red, RDP y otros servicios."
                ),
                what_it_is_not=(
                    "No es un keylogger. Son credenciales que el "
                    "usuario guardó voluntariamente para no "
                    "introducirlas cada vez."
                ),
                raw_data={
                    "stored_credentials": [
                        {"target": c.get("target"),
                         "type": c.get("type"),
                         "user": c.get("user")}
                        for c in stored_creds
                    ],
                    "corporate_credentials_count": len(corporate_creds)
                }
            ))

    # ── Cuentas de servicio ────────────────────────────────────────

    def _check_service_accounts(self):
        from core.audit_engine import AuditFinding

        service_accounts = []

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services",
                0, winreg.KEY_READ
            )
            idx = 0
            while True:
                try:
                    svc_name = winreg.EnumKey(key, idx)
                    try:
                        svc_key = winreg.OpenKey(
                            key, svc_name, 0, winreg.KEY_READ
                        )
                        try:
                            account, _ = winreg.QueryValueEx(
                                svc_key, "ObjectName"
                            )
                            account_str = str(account).lower()
                            # Servicios que no usan cuentas del sistema
                            if account_str not in [
                                "localsystem", "localservice",
                                "networkservice",
                                "nt authority\\localsystem",
                                "nt authority\\localservice",
                                "nt authority\\networkservice",
                                "nt authority\\system",
                                ""
                            ]:
                                try:
                                    display, _ = winreg.QueryValueEx(
                                        svc_key, "DisplayName"
                                    )
                                except (FileNotFoundError, OSError):
                                    display = svc_name
                                service_accounts.append({
                                    "service": svc_name,
                                    "display": str(display),
                                    "account": str(account)
                                })
                        except (FileNotFoundError, OSError):
                            pass
                        winreg.CloseKey(svc_key)
                    except (FileNotFoundError,
                            PermissionError, OSError):
                        pass
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception as e:
            print(f"[Identity] Error leyendo cuentas de servicio: {e}")

        if service_accounts:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="identity_service_accounts",
                title=f"Servicios con cuentas de usuario específicas "
                      f"({len(service_accounts)})",
                description=(
                    f"{len(service_accounts)} servicios de Windows "
                    f"se ejecutan bajo cuentas de usuario específicas, "
                    f"no cuentas de sistema estándar."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Servicios que corren bajo cuentas de usuario "
                    "específicas tienen acceso a los recursos de esa "
                    "cuenta: archivos, red, credenciales. "
                    "Si la cuenta tiene privilegios elevados, "
                    "el servicio también."
                ),
                legal_risk=(
                    "Servicios de monitorización que corren bajo "
                    "cuentas de dominio pueden acceder a recursos "
                    "corporativos con privilegios del usuario. "
                    "Relevante para determinar el alcance real "
                    "de la vigilancia."
                ),
                what_it_is=(
                    "Servicios de Windows que utilizan cuentas de "
                    "usuario con credenciales específicas en lugar "
                    "de las cuentas de sistema estándar."
                ),
                what_it_is_not=(
                    "Es una práctica común en entornos corporativos "
                    "para servicios que necesitan acceso a recursos "
                    "de red. No implica actividad maliciosa."
                ),
                raw_data={
                    "service_accounts": service_accounts[:20]
                }
            ))

    # ── Derechos de inicio de sesión ───────────────────────────────

    def _check_logon_rights(self):
        from core.audit_engine import AuditFinding

        logon_rights = {}

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "secedit /export /cfg $env:TEMP\\secpol.cfg "
                 "/quiet; "
                 "if (Test-Path $env:TEMP\\secpol.cfg) { "
                 "Get-Content $env:TEMP\\secpol.cfg | "
                 "Where-Object { $_ -match 'SeRemote|SeBatch"
                 "|SeInteractive|SeNetwork' }; "
                 "Remove-Item $env:TEMP\\secpol.cfg -Force }"],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    if "=" in line:
                        key, val = line.split("=", 1)
                        logon_rights[key.strip()] = val.strip()
        except Exception:
            pass

        if logon_rights:
            # SeRemoteInteractiveLogonRight es especialmente relevante
            remote_logon = logon_rights.get(
                "SeRemoteInteractiveLogonRight", ""
            )

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="identity_logon_rights",
                title="Derechos de inicio de sesión configurados",
                description=(
                    "Política de seguridad que define qué cuentas "
                    "pueden iniciar sesión local o remotamente."
                ),
                risk_level="yellow",
                technical_risk=(
                    "SeRemoteInteractiveLogonRight define quién puede "
                    "conectarse por RDP. Si incluye grupos amplios "
                    "(Domain Users), muchos usuarios pueden acceder "
                    "remotamente al equipo del trabajador."
                ),
                legal_risk=(
                    "Un gran número de cuentas con derecho de acceso "
                    "remoto aumenta el riesgo de vigilancia no "
                    "autorizada. El trabajador debería conocer "
                    "qué cuentas pueden acceder a su equipo."
                ),
                what_it_is=(
                    "Política de seguridad local que determina "
                    "qué usuarios o grupos pueden iniciar sesión "
                    "en el equipo de forma local o remota."
                ),
                what_it_is_not=(
                    "No implica que alguien esté accediendo. "
                    "Define quién tiene el derecho técnico "
                    "de hacerlo si lo intenta."
                ),
                raw_data={"logon_rights": logon_rights}
            ))

    # ── Procesos con privilegios elevados ──────────────────────────

    def _check_privileged_processes(self):
        from core.audit_engine import AuditFinding

        elevated_procs = []

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Process | Where-Object { "
                 "try { $_.MainWindowTitle -ne $null } "
                 "catch { $false } } | "
                 "ForEach-Object { "
                 "try { "
                 "$token = [System.Diagnostics.Process]"
                 "::GetCurrentProcess(); "
                 "$elevated = ([Security.Principal.WindowsPrincipal]"
                 "[Security.Principal.WindowsIdentity]::GetCurrent())"
                 ".IsInRole([Security.Principal.WindowsBuiltInRole]"
                 "::Administrator); "
                 "if ($elevated) { $_.Name } "
                 "} catch {} } | "
                 "Select-Object -Unique | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                data = result.stdout.strip()
                if data.startswith("["):
                    elevated_procs = json.loads(data)
                elif data.startswith('"'):
                    elevated_procs = [json.loads(data)]
        except Exception:
            pass

        # Procesos de monitorización conocidos que típicamente corren elevados
        monitoring_elevated = []
        elevated_monitoring_names = [
            "csfalconservice", "sentinelagent", "mssense",
            "taniumclient", "carbonblack", "cylancesvc",
            "cylancememdef"
        ]
        for name in elevated_monitoring_names:
            if name in self.running_procs:
                monitoring_elevated.append(name)

        if monitoring_elevated:
            sources = get_sources(
                "endpoint_monitoring_capabilities",
                "worker_rights_and_surveillance_context",
            )
            triangulation = {
                "gpresult": gpresult_summary(),
                "fltmc_filters": fltmc_summary(),
            }
            confidence = confidence_from_evidence(
                sources,
                triangulation,
                direct_indicators_count=len(monitoring_elevated),
            )
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="identity_privileged_monitoring",
                title=f"Procesos de monitorización con privilegios "
                      f"de sistema ({len(monitoring_elevated)})",
                description=(
                    "Agentes de seguridad/monitorización ejecutándose "
                    "con privilegios de SISTEMA, el nivel más alto "
                    "de acceso en Windows."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Los procesos de SISTEMA tienen acceso sin "
                    "restricciones a todos los archivos, memoria, "
                    "red y configuración del equipo. "
                    "Es el contexto de mayor privilegio posible."
                ),
                legal_risk=(
                    "Agentes corporativos con privilegios de SISTEMA "
                    "tienen capacidad técnica para acceder a cualquier "
                    "dato del trabajador. "
                    "Su alcance real depende de su configuración, "
                    "no de sus privilegios técnicos."
                ),
                what_it_is=(
                    "Servicios de seguridad que operan con la cuenta "
                    "SYSTEM de Windows, necesaria para proteger "
                    "el sistema a nivel de kernel."
                ),
                what_it_is_not=(
                    "Es normal que los agentes EDR/AV corran como "
                    "SYSTEM. Es un requisito técnico para su función "
                    "de seguridad, no indica uso indebido."
                ),
                raw_data={
                    "monitoring_as_system": monitoring_elevated,
                    "independent_sources": sources,
                    "triangulation": triangulation,
                    "confidence": confidence,
                }
            ))
    


    # ── Perfilado de cuentas ───────────────────────────────────────
    def _profile_accounts(self):
        from core.audit_engine import AuditFinding
        from skills.identity_audit.account_profiler import AccountProfiler

        print("[Identity] Perfilando cuentas...")
        profiler = AccountProfiler()
        profiles = profiler.profile_all_accounts()

        suspicious = [p for p in profiles if p["suspicion_flags"]]
        high_risk  = [p for p in profiles if p["risk_level"] in
                      ["orange", "red"]]

        if not suspicious:
            print("[Identity] Sin cuentas sospechosas detectadas")
            print("[Identity] Completado")  # ← aquí si no hay sospechosas
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="identity_account_profiles",
            title=f"Perfiles de cuentas — "
                  f"{len(suspicious)} con alertas "
                  f"({len(high_risk)} alto riesgo)",
            description=(
                f"Análisis detallado de {len(profiles)} cuentas. "
                f"{len(suspicious)} tienen características que "
                f"requieren revisión."
            ),
            risk_level="orange" if high_risk else "yellow",
            technical_risk=(
                "Cuentas con privilegios elevados, contraseña "
                "permanente o nunca usadas pueden ser vectores "
                "de acceso no autorizado al equipo."
            ),
            legal_risk=(
                "El trabajador tiene derecho a conocer qué cuentas "
                "tienen acceso a su dispositivo y con qué finalidad. "
                "LOPDGDD art. 87 y RGPD art. 32."
            ),
            what_it_is=(
                "Análisis de cada cuenta de usuario del sistema: "
                "qué es, qué hace, cuándo fue usada por última vez "
                "y por qué puede ser relevante."
            ),
            what_it_is_not=(
                "No todas las cuentas con alertas son maliciosas. "
                "Muchas son cuentas de servicio legítimas. "
                "El perfil ayuda a identificar cuáles merecen "
                "justificación documentada."
            ),
            raw_data={
                "total_profiled":   len(profiles),
                "suspicious_count": len(suspicious),
                "high_risk_count":  len(high_risk),
                "profiles": [
                    {
                        "name":     p["name"],
                        "enabled":  p["enabled"],
                        "risk":     p["risk_level"],
                        "summary":  p["summary"],
                        "flags":    p["suspicion_flags"],
                        "groups":   p["groups"],
                        "services": [
                            s["display"] for s in p["running_services"]
                        ],
                        "last_logon": p["last_logon"],
                        "recent_events_count": len(p["recent_events"]),
                    }
                    for p in profiles
                ]
            }
        ))

        for profile in high_risk:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="identity_suspicious_account",
                title=f"Cuenta: {profile['name']} — "
                      f"{len(profile['suspicion_flags'])} alertas",
                description=profile["summary"],
                risk_level=profile["risk_level"],
                technical_risk="\n".join(profile["suspicion_flags"]),
                legal_risk=(
                    "Esta cuenta puede tener acceso al equipo del "
                    "trabajador. Su presencia sin documentación "
                    "puede vulnerar LOPDGDD art. 87."
                ),
                what_it_is=(
                    f"Cuenta '{profile['name']}' detectada con: "
                    f"grupos={profile['groups']}, "
                    f"servicios={len(profile['running_services'])}, "
                    f"último acceso={profile['last_logon']}."
                ),
                what_it_is_not=(
                    "Puede ser una cuenta de servicio corporativo "
                    "legítima. La alerta indica que merece "
                    "justificación documentada por parte del empleador."
                ),
                raw_data=profile
            ))
            print(
                f"[Identity] ⚠️  {profile['name']} — "
                f"riesgo: {profile['risk_level'].upper()} | "
                f"{profile['summary']}"
            )

        print(
            f"[Identity] Perfiles completados — "
            f"{len(suspicious)} cuentas con alertas"
        )
        
        print("[Identity] Completado")
