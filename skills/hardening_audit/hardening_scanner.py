# skills/hardening_audit/hardening_scanner.py
"""
Skill 10 — Windows Hardening Audit
Detecta configuraciones de seguridad que deberían estar activas
y no lo están — enfoque en derechos del trabajador:
qué protecciones se han desactivado o no se han aplicado.
"""

import winreg
import subprocess
import json
from pathlib import Path


# Configuraciones esperadas en un equipo corporativo bien configurado
# Cada check tiene: descripción, por qué importa al trabajador,
# cómo detectarlo y qué significa su ausencia.

HARDENING_CHECKS = [
    {
        "id": "bitlocker",
        "title": "BitLocker — Cifrado de disco",
        "category": "hardening_encryption",
        "importance": "critical",
        "worker_impact": (
            "Sin cifrado, si el equipo se pierde o es robado, "
            "cualquier persona puede acceder a todos tus datos "
            "sin contraseña. Incluye documentos, correos y credenciales."
        ),
        "absence_means": (
            "Los datos del disco son accesibles sin autenticación "
            "si se extrae el disco o se arranca desde medio externo."
        ),
    },
    {
        "id": "secure_boot",
        "title": "Secure Boot — Arranque seguro",
        "category": "hardening_boot",
        "importance": "high",
        "worker_impact": (
            "Sin Secure Boot, software malicioso puede instalarse "
            "antes de que Windows arranque, invisible para el antivirus."
        ),
        "absence_means": (
            "El sistema puede ser comprometido a nivel de firmware "
            "sin que ninguna herramienta de seguridad lo detecte."
        ),
    },
    {
        "id": "uac",
        "title": "UAC — Control de cuentas de usuario",
        "category": "hardening_privileges",
        "importance": "high",
        "worker_impact": (
            "UAC desactivado permite que cualquier programa se instale "
            "o modifique el sistema sin pedir confirmación. "
            "Facilita la instalación silenciosa de software de vigilancia."
        ),
        "absence_means": (
            "Software puede instalarse con privilegios de administrador "
            "sin que el usuario lo sepa ni lo autorice."
        ),
    },
    {
        "id": "firewall",
        "title": "Windows Firewall — Cortafuegos",
        "category": "hardening_network",
        "importance": "high",
        "worker_impact": (
            "Sin firewall activo, conexiones entrantes no autorizadas "
            "pueden acceder al equipo desde la red corporativa."
        ),
        "absence_means": (
            "El equipo está expuesto a conexiones entrantes "
            "desde la red local sin filtrado."
        ),
    },
    {
        "id": "windows_update",
        "title": "Windows Update — Actualizaciones automáticas",
        "category": "hardening_updates",
        "importance": "high",
        "worker_impact": (
            "Sin actualizaciones automáticas el sistema tiene "
            "vulnerabilidades conocidas que pueden ser explotadas "
            "para instalar software no autorizado."
        ),
        "absence_means": (
            "Vulnerabilidades de seguridad conocidas sin parchear "
            "pueden ser explotadas por software malicioso."
        ),
    },
    {
        "id": "defender_realtime",
        "title": "Windows Defender — Protección en tiempo real",
        "category": "hardening_antimalware",
        "importance": "high",
        "worker_impact": (
            "Sin protección en tiempo real, software malicioso "
            "puede ejecutarse sin ser detectado, incluyendo "
            "keyloggers o software de vigilancia no autorizado."
        ),
        "absence_means": (
            "Malware puede ejecutarse libremente sin detección "
            "hasta el próximo análisis manual."
        ),
    },
    {
        "id": "smb_v1",
        "title": "SMBv1 — Protocolo de red obsoleto y vulnerable",
        "category": "hardening_protocols",
        "importance": "medium",
        "worker_impact": (
            "SMBv1 tiene vulnerabilidades críticas (EternalBlue/WannaCry). "
            "Su presencia indica falta de hardening básico del sistema."
        ),
        "absence_means": (
            "El sistema es vulnerable a ataques de red conocidos "
            "desde 2017 que no requieren interacción del usuario."
        ),
    },
    {
        "id": "powershell_logging",
        "title": "PowerShell Script Block Logging",
        "category": "hardening_logging",
        "importance": "medium",
        "worker_impact": (
            "Sin logging de PowerShell, comandos ejecutados en segundo "
            "plano no quedan registrados. Esto puede ocultar "
            "actividad de scripts de monitorización."
        ),
        "absence_means": (
            "Scripts PowerShell ejecutados por agentes corporativos "
            "no dejan rastro auditable por el trabajador."
        ),
    },
    {
        "id": "lsass_protection",
        "title": "LSASS Protection — Protección de credenciales",
        "category": "hardening_credentials",
        "importance": "high",
        "worker_impact": (
            "Sin protección de LSASS, herramientas como Mimikatz "
            "pueden extraer contraseñas en texto claro de la memoria. "
            "Afecta a las credenciales del trabajador."
        ),
        "absence_means": (
            "Las credenciales del trabajador pueden ser extraídas "
            "de la memoria del sistema por procesos con privilegios."
        ),
    },
    {
        "id": "rdp_encryption",
        "title": "RDP — Nivel de cifrado del escritorio remoto",
        "category": "hardening_remote",
        "importance": "medium",
        "worker_impact": (
            "RDP sin cifrado adecuado permite interceptar sesiones "
            "de escritorio remoto. Si IT accede remotamente, "
            "la sesión puede ser observada o grabada."
        ),
        "absence_means": (
            "Las sesiones de escritorio remoto pueden ser "
            "interceptadas en la red sin cifrado suficiente."
        ),
    },
    {
        "id": "audit_policy",
        "title": "Política de auditoría — Registro de eventos",
        "category": "hardening_logging",
        "importance": "medium",
        "worker_impact": (
            "Sin política de auditoría activa, accesos a archivos "
            "y cambios de configuración no quedan registrados. "
            "El trabajador no puede demostrar qué ocurrió "
            "si hay una disputa."
        ),
        "absence_means": (
            "No hay registro forense de accesos a archivos, "
            "cambios de configuración ni actividad administrativa."
        ),
    },
    {
        "id": "controlled_folder_access",
        "title": "Acceso controlado a carpetas (Ransomware Protection)",
        "category": "hardening_antimalware",
        "importance": "medium",
        "worker_impact": (
            "Sin protección contra ransomware, software malicioso "
            "puede cifrar o eliminar todos los documentos del trabajador."
        ),
        "absence_means": (
            "Los documentos del trabajador no tienen protección "
            "adicional contra modificación no autorizada por software."
        ),
    },
    {
        "id": "credential_guard",
        "title": "Windows Credential Guard",
        "category": "hardening_credentials",
        "importance": "medium",
        "worker_impact": (
            "Credential Guard aísla las credenciales en un entorno "
            "virtualizado. Sin él, credenciales corporativas y "
            "personales son más vulnerables a extracción."
        ),
        "absence_means": (
            "Las credenciales almacenadas tienen menor protección "
            "frente a ataques de extracción de memoria."
        ),
    },
    {
        "id": "exploit_protection",
        "title": "Windows Exploit Protection (DEP/ASLR)",
        "category": "hardening_memory",
        "importance": "medium",
        "worker_impact": (
            "Sin protección de memoria, exploits en aplicaciones "
            "pueden ejecutar código malicioso con mayor facilidad."
        ),
        "absence_means": (
            "Aplicaciones vulnerables son más fácilmente explotables "
            "para ejecutar código no autorizado."
        ),
    },
]


class HardeningAudit:
    SKILL_NAME = "hardening_audit"

    def __init__(self, engine):
        self.engine = engine
        self.results = {}

    def run(self):
        print("[Hardening] Iniciando auditoría de configuración de seguridad...")
        self._check_bitlocker()
        self._check_secure_boot()
        self._check_uac()
        self._check_firewall()
        self._check_windows_update()
        self._check_defender_realtime()
        self._check_smb_v1()
        self._check_powershell_logging()
        self._check_lsass_protection()
        self._check_rdp_encryption()
        self._check_audit_policy()
        self._check_controlled_folder_access()
        self._check_credential_guard()
        self._check_exploit_protection()
        self._generate_hardening_summary()

    # ── BitLocker ──────────────────────────────────────────────────

    def _check_bitlocker(self):
        enabled = False
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-BitLockerVolume -MountPoint C: "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object ProtectionStatus | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                enabled = data.get("ProtectionStatus") == 1
        except Exception:
            pass
        self.results["bitlocker"] = enabled

    # ── Secure Boot ────────────────────────────────────────────────

    def _check_secure_boot(self):
        enabled = False
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Confirm-SecureBootUEFI -ErrorAction SilentlyContinue"],
                capture_output=True, text=True, timeout=10
            )
            enabled = result.stdout.strip().lower() == "true"
        except Exception:
            pass
        self.results["secure_boot"] = enabled

    # ── UAC ────────────────────────────────────────────────────────

    def _check_uac(self):
        enabled = False
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                0, winreg.KEY_READ
            )
            val, _ = winreg.QueryValueEx(key, "EnableLUA")
            winreg.CloseKey(key)
            enabled = (val == 1)
        except (FileNotFoundError, PermissionError, OSError):
            pass
        self.results["uac"] = enabled

    # ── Firewall ───────────────────────────────────────────────────

    def _check_firewall(self):
        enabled = False
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetFirewallProfile | "
                 "Select-Object Name, Enabled | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                profiles = json.loads(result.stdout)
                if isinstance(profiles, dict):
                    profiles = [profiles]
                enabled = all(p.get("Enabled") for p in profiles)
        except Exception:
            pass
        self.results["firewall"] = enabled

    # ── Windows Update ─────────────────────────────────────────────

    def _check_windows_update(self):
        enabled = True
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
                0, winreg.KEY_READ
            )
            try:
                val, _ = winreg.QueryValueEx(key, "NoAutoUpdate")
                if val == 1:
                    enabled = False
            except (FileNotFoundError, OSError):
                pass
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass
        self.results["windows_update"] = enabled

    # ── Defender Real-time ─────────────────────────────────────────

    def _check_defender_realtime(self):
        enabled = False
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-MpPreference).DisableRealtimeMonitoring"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.strip().lower()
            enabled = output == "false"
        except Exception:
            pass
        self.results["defender_realtime"] = enabled

    # ── SMBv1 ──────────────────────────────────────────────────────

    def _check_smb_v1(self):
        smb1_disabled = True
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-SmbServerConfiguration).EnableSMB1Protocol"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.strip().lower()
            smb1_disabled = (output == "false")
        except Exception:
            pass
        self.results["smb_v1"] = smb1_disabled

    # ── PowerShell Logging ─────────────────────────────────────────

    def _check_powershell_logging(self):
        enabled = False
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell"
                r"\ScriptBlockLogging",
                0, winreg.KEY_READ
            )
            val, _ = winreg.QueryValueEx(key, "EnableScriptBlockLogging")
            winreg.CloseKey(key)
            enabled = (val == 1)
        except (FileNotFoundError, PermissionError, OSError):
            pass
        self.results["powershell_logging"] = enabled

    # ── LSASS Protection ───────────────────────────────────────────

    def _check_lsass_protection(self):
        enabled = False
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Lsa",
                0, winreg.KEY_READ
            )
            try:
                val, _ = winreg.QueryValueEx(key, "RunAsPPL")
                enabled = (val >= 1)
            except (FileNotFoundError, OSError):
                pass
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass
        self.results["lsass_protection"] = enabled

    # ── RDP Encryption ─────────────────────────────────────────────

    def _check_rdp_encryption(self):
        secure = False
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server"
                r"\WinStations\RDP-Tcp",
                0, winreg.KEY_READ
            )
            try:
                val, _ = winreg.QueryValueEx(key, "MinEncryptionLevel")
                secure = (val >= 3)
            except (FileNotFoundError, OSError):
                secure = True
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            secure = True
        self.results["rdp_encryption"] = secure

    # ── Audit Policy ───────────────────────────────────────────────

    def _check_audit_policy(self):
        enabled = False
        try:
            result = subprocess.run(
                ["auditpol", "/get", "/category:*"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                enabled = (
                    "success" in output or
                    "failure" in output or
                    "correcto" in output or
                    "error" in output
                )
        except Exception:
            pass
        self.results["audit_policy"] = enabled

    # ── Controlled Folder Access ───────────────────────────────────

    def _check_controlled_folder_access(self):
        enabled = False
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-MpPreference).EnableControlledFolderAccess"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.strip()
            enabled = output in ["1", "2", "Enabled", "AuditMode"]
        except Exception:
            pass
        self.results["controlled_folder_access"] = enabled

    # ── Credential Guard ───────────────────────────────────────────

    def _check_credential_guard(self):
        enabled = False
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                0, winreg.KEY_READ
            )
            try:
                val, _ = winreg.QueryValueEx(
                    key, "EnableVirtualizationBasedSecurity"
                )
                enabled = (val == 1)
            except (FileNotFoundError, OSError):
                pass
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass
        self.results["credential_guard"] = enabled

    # ── Exploit Protection ─────────────────────────────────────────

    def _check_exploit_protection(self):
        enabled = False
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ProcessMitigation -System | "
                 "Select-Object DEP, ASLR | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                dep  = data.get("DEP",  {})
                aslr = data.get("ASLR", {})
                enabled = bool(dep or aslr)
        except Exception:
            pass
        self.results["exploit_protection"] = enabled

    # ── Resumen de hardening ───────────────────────────────────────

    def _generate_hardening_summary(self):
        from core.audit_engine import AuditFinding

        check_map = {c["id"]: c for c in HARDENING_CHECKS}

        missing   = []
        present   = []

        for check_id, is_ok in self.results.items():
            check = check_map.get(check_id)
            if not check:
                continue
            if is_ok:
                present.append(check)
            else:
                missing.append(check)

        # Agrupa ausencias por importancia
        critical_missing = [
            c for c in missing if c["importance"] == "critical"
        ]
        high_missing = [
            c for c in missing if c["importance"] == "high"
        ]
        medium_missing = [
            c for c in missing if c["importance"] == "medium"
        ]

        if not missing:
            print("[Hardening] Sistema bien configurado — sin ausencias críticas")
            return

        # Riesgo según ausencias
        if critical_missing:
            risk = "red"
        elif len(high_missing) >= 3:
            risk = "red"
        elif high_missing:
            risk = "orange"
        else:
            risk = "yellow"

        # Hallazgo global de hardening
        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="hardening_missing",
            title=f"Configuraciones de seguridad ausentes "
                  f"({len(missing)} de {len(HARDENING_CHECKS)})",
            description=(
                f"Se han detectado {len(missing)} configuraciones de "
                f"seguridad no activas: "
                f"{len(critical_missing)} críticas, "
                f"{len(high_missing)} altas, "
                f"{len(medium_missing)} medias."
            ),
            risk_level=risk,
            technical_risk=(
                "Las configuraciones de seguridad ausentes reducen "
                "la protección del sistema y pueden facilitar "
                "la instalación o ejecución de software no autorizado, "
                "incluyendo herramientas de vigilancia."
            ),
            legal_risk=(
                "El empleador tiene obligación de garantizar la "
                "seguridad de los equipos corporativos bajo RGPD art. 32. "
                "La ausencia de medidas técnicas básicas puede "
                "constituir incumplimiento de esta obligación."
            ),
            what_it_is=(
                "Configuraciones de seguridad de Windows que deberían "
                "estar activas en un equipo corporativo gestionado "
                "pero no lo están."
            ),
            what_it_is_not=(
                "No implica que el equipo esté comprometido. "
                "Indica que las protecciones estándar no se han aplicado, "
                "lo que aumenta la superficie de riesgo."
            ),
            raw_data={
                "missing": [c["id"] for c in missing],
                "present": [c["id"] for c in present],
                "critical_missing": [
                    {"id": c["id"], "title": c["title"],
                     "worker_impact": c["worker_impact"]}
                    for c in critical_missing
                ],
                "high_missing": [
                    {"id": c["id"], "title": c["title"],
                     "worker_impact": c["worker_impact"]}
                    for c in high_missing
                ],
                "medium_missing": [
                    {"id": c["id"], "title": c["title"],
                     "worker_impact": c["worker_impact"]}
                    for c in medium_missing
                ],
            }
        ))

        # Hallazgos individuales para los críticos y altos
        for check in critical_missing + high_missing:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category=check["category"],
                title=f"AUSENTE: {check['title']}",
                description=(
                    f"Esta protección de seguridad no está activa. "
                    f"Importancia: {check['importance'].upper()}."
                ),
                risk_level=(
                    "red" if check["importance"] == "critical"
                    else "orange"
                ),
                technical_risk=check["absence_means"],
                legal_risk=(
                    "El empleador tiene obligación bajo RGPD art. 32 "
                    "de implementar medidas técnicas apropiadas. "
                    "La ausencia de esta medida puede ser relevante "
                    "en caso de incidente de seguridad."
                ),
                what_it_is=check["title"],
                what_it_is_not=(
                    "No implica que haya ocurrido un incidente. "
                    "Es una protección que debería estar activa "
                    "y no lo está."
                ),
                raw_data={
                    "check_id": check["id"],
                    "importance": check["importance"],
                    "worker_impact": check["worker_impact"],
                    "absence_means": check["absence_means"],
                }
            ))

        print(
            f"[Hardening] Ausentes: {len(missing)} "
            f"({len(critical_missing)} críticos, "
            f"{len(high_missing)} altos, "
            f"{len(medium_missing)} medios)"
        )