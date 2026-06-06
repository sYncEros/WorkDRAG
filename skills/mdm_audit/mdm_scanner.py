# skills/mdm_audit/mdm_scanner.py
"""
Skill 1 — Auditoría MDM y Control Corporativo
Detecta nivel de gestión corporativa (Intune, Azure AD, inscripción MDM)
"""

import winreg
import subprocess
import json
from pathlib import Path


class MDMAudit:
    SKILL_NAME = "mdm_audit"

    MDM_REGISTRY_PATHS = [
        r"SOFTWARE\Microsoft\Enrollments",
        r"SOFTWARE\Microsoft\MDM",
        r"SOFTWARE\Microsoft\Provisioning\OMADM\Accounts",
        r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM",
    ]

    INTUNE_PATHS = [
        r"SOFTWARE\Microsoft\IntuneManagementExtension",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate",
    ]

    def __init__(self, engine):
        self.engine = engine
        self.results = {}

    def run(self):
        print("[MDM] Iniciando auditoría de gestión corporativa...")
        self.results["mdm_enrolled"] = self._check_mdm_enrollment()
        self.results["managed_by"] = self._check_managed_by()
        self.results["intune_present"] = self._check_intune()
        self.results["applocker_active"] = self._check_applocker()
        self.results["unenrollment_blocked"] = self._check_unenrollment_policy()
        self.results["corporate_certificates"] = self._check_corp_certificates()
        self.results["azure_ad_joined"] = self._check_azure_ad()

        self._evaluate_and_report()
        self._check_usb_restriction_policies()
        self._check_software_installation_policies()
        self._check_dlp_device_policies()

    # ── Detección MDM ──────────────────────────────────────────────

    def _check_mdm_enrollment(self) -> bool:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Enrollments",
                0, winreg.KEY_READ
            )
            # Si existe la clave y tiene subclaves, hay enrollment
            idx = 0
            subkeys = []
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, idx))
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
            return len(subkeys) > 0
        except (FileNotFoundError, PermissionError, OSError):
            return False
        except Exception as e:
            print(f"[MDM] Error leyendo enrollment: {e}")
            return False

    def _check_managed_by(self) -> str:
        """Intenta obtener el nombre de la organización gestora."""
        paths_values = [
            (r"SOFTWARE\Microsoft\Enrollments", None),  # iterar subclaves
            (r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
             r"\FirewallPolicy\MDM", "TenantId"),
        ]
        # Buscar en subclaves de Enrollments el UPN o el nombre
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Enrollments",
                0, winreg.KEY_READ
            )
            idx = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, idx)
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        val, _ = winreg.QueryValueEx(subkey, "UPN")
                        if val:
                            return val.split("@")[-1]  # dominio del UPN
                    except (FileNotFoundError, PermissionError, OSError):
                        pass
                    try:
                        val, _ = winreg.QueryValueEx(subkey, "ProviderID")
                        if val:
                            return val
                    except (FileNotFoundError, PermissionError, OSError):
                        pass
                    winreg.CloseKey(subkey)
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass
        return "unknown"

    def _check_intune(self) -> bool:
        try:
            winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\IntuneManagementExtension",
                0, winreg.KEY_READ
            )
            return True
        except (FileNotFoundError, PermissionError, OSError):
            return False

    def _check_applocker(self) -> bool:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\SrpV2",
                0, winreg.KEY_READ
            )
            winreg.CloseKey(key)
            return True
        except (FileNotFoundError, PermissionError, OSError):
            return False

    def _check_unenrollment_policy(self) -> bool:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM",
                0, winreg.KEY_READ
            )
            val, _ = winreg.QueryValueEx(key, "AllowManualMDMUnenrollment")
            winreg.CloseKey(key)
            return val == 0
        except (FileNotFoundError, PermissionError, OSError):
            return False

    def _check_corp_certificates(self) -> list:
        """Lista certificados raíz corporativos (no de Microsoft/estándar)."""
        standard_issuers = {
            "microsoft", "digicert", "comodo", "sectigo",
            "globalsign", "entrust", "usertrust", "verisign",
            "amazon", "google", "baltimore", "starfield"
        }
        corp_certs = []
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ChildItem Cert:\\LocalMachine\\Root | "
                 "Select-Object Subject, Issuer, Thumbprint | "
                 "ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                certs = json.loads(result.stdout)
                if isinstance(certs, dict):
                    certs = [certs]
                for cert in certs:
                    subject = cert.get("Subject", "").lower()
                    if not any(s in subject for s in standard_issuers):
                        corp_certs.append({
                            "subject": cert.get("Subject", ""),
                            "thumbprint": cert.get("Thumbprint", "")
                        })
        except Exception as e:
            print(f"[MDM] Error leyendo certificados: {e}")
        return corp_certs

    def _check_azure_ad(self) -> dict:
        """Comprueba si el equipo está unido a Azure AD."""
        try:
            result = subprocess.run(
                ["dsregcmd", "/status"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            return {
                "azure_ad_joined": "AzureAdJoined : YES" in output,
                "domain_joined": "DomainJoined : YES" in output,
                "workplace_joined": "WorkplaceJoined : YES" in output,
            }
        except Exception:
            return {"azure_ad_joined": False, "domain_joined": False}

    # ── Evaluación y reporte ───────────────────────────────────────

    def _evaluate_and_report(self):
        from core.audit_engine import AuditFinding

        flags = []
        risk = "green"

        if self.results["mdm_enrolled"]:
            flags.append("mdm_enrolled")
            risk = "yellow"

        if self.results["intune_present"]:
            flags.append("intune_management_extension_present")

        if self.results["unenrollment_blocked"]:
            flags.append("manual_unenrollment_disabled")
            risk = "yellow"

        if self.results["applocker_active"]:
            flags.append("applocker_policy_active")

        corp_certs = self.results["corporate_certificates"]
        if corp_certs:
            flags.append(f"corporate_root_certificates_present ({len(corp_certs)})")
            if risk == "green":
                risk = "yellow"

        azure = self.results.get("azure_ad_joined", {})
        if isinstance(azure, dict) and azure.get("azure_ad_joined"):
            flags.append("azure_ad_joined")

        managed_by = self.results["managed_by"]

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="Corporate Control",
            title="MDM / Gestión corporativa del dispositivo",
            description=(
                f"El dispositivo {'está' if self.results['mdm_enrolled'] else 'no está'} "
                f"gestionado mediante MDM. "
                f"Organización detectada: {managed_by}. "
                f"Flags: {', '.join(flags) if flags else 'ninguno'}."
            ),
            risk_level=risk,
            technical_risk=(
                "MDM permite a la organización instalar software, aplicar políticas, "
                "borrar el dispositivo remotamente y restringir aplicaciones."
            ),
            legal_risk=(
                "La gestión MDM en dispositivos corporativos es generalmente legítima "
                "bajo el ET y LOPDGDD si está informada al trabajador."
            ),
            what_it_is=(
                "MDM (Mobile Device Management) es software que permite a las empresas "
                "gestionar dispositivos corporativos: aplicar políticas de seguridad, "
                "instalar apps, configurar VPN y, en caso extremo, borrar el dispositivo."
            ),
            what_it_is_not=(
                "MDM por sí solo no implica monitorización de actividad, "
                "lectura de mensajes personales ni vigilancia en tiempo real. "
                "Gestiona el dispositivo, no espía al usuario."
            ),
            raw_data={**self.results, "flags": flags}
        ))

        print(f"[MDM] Completado — Riesgo: {risk.upper()} | Flags: {flags}")

    # ── Políticas de restricción de USB via MDM/GPO ────────────────

    def _check_usb_restriction_policies(self):
        from core.audit_engine import AuditFinding

        usb_restrictions = []

        # Políticas MDM de almacenamiento extraíble
        mdm_usb_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
             "RemovableStorage GPO"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\PolicyManager\current\device\Storage",
             "MDM Storage Policy"),
        ]

        for hive, path, label in mdm_usb_keys:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        usb_restrictions.append({
                            "source": label,
                            "policy": name,
                            "value": str(value),
                        })
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        # Comprobar estado del servicio USBSTOR
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\USBSTOR",
                0, winreg.KEY_READ
            )
            try:
                start_val, _ = winreg.QueryValueEx(key, "Start")
                usb_restrictions.append({
                    "source": "USBSTOR service",
                    "policy": "Start",
                    "value": str(start_val),
                    "interpretation": {
                        "1": "Boot (activo)",
                        "2": "Automático (activo)",
                        "3": "Manual (disponible bajo demanda)",
                        "4": "Deshabilitado (USB bloqueado)",
                    }.get(str(start_val), "Desconocido"),
                })
            except (FileNotFoundError, PermissionError, OSError):
                pass
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        if not usb_restrictions:
            return

        blocking = [r for r in usb_restrictions
                    if r.get("value") in ("4", "1") or
                    r.get("policy", "").startswith("Deny_")]
        risk = "orange" if blocking else "yellow"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="mdm_usb_restrictions",
            title=f"Políticas MDM/GPO de restricción USB "
                  f"({len(usb_restrictions)} reglas, "
                  f"{len(blocking)} bloqueos activos)",
            description=(
                "Se han detectado políticas corporativas que controlan el "
                "uso de almacenamiento USB, aplicadas via MDM o GPO."
            ),
            risk_level=risk,
            technical_risk=(
                "Las políticas de USB pueden bloquear dispositivos, registrar "
                "intentos de conexión o aplicarse de forma silenciosa. "
                "Si registran intentos, la empresa puede saber cuándo y qué "
                "dispositivos intentó conectar el trabajador."
            ),
            legal_risk=(
                "Las restricciones de USB son medidas DLP legítimas. "
                "Si los intentos se registran y analizan, requieren "
                "información previa bajo LOPDGDD art. 87."
            ),
            what_it_is=(
                "Políticas del sistema operativo o MDM que controlan el "
                "acceso a dispositivos de almacenamiento USB extraíble."
            ),
            what_it_is_not=(
                "No toda restricción USB es ilegítima. Es una medida de "
                "seguridad corporativa estándar."
            ),
            raw_data={
                "restrictions": usb_restrictions,
                "blocking_policies": blocking
            }
        ))

    # ── Políticas de bloqueo de instalación de software ───────────

    def _check_software_installation_policies(self):
        from core.audit_engine import AuditFinding

        install_policies = []

        install_policy_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Windows\Installer",
             "Windows Installer Policy"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
             "Explorer Policies"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Windows\System",
             "System Policies"),
        ]

        for hive, path, label in install_policy_keys:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        install_policies.append({
                            "source": label,
                            "policy": name,
                            "value": str(value),
                        })
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        # Buscar políticas específicas de bloqueo
        blocking_keywords = [
            "DisableMSI", "NoControlPanel", "NoAddRemovePrograms",
            "DisableUserInstall", "NoRun", "DisableCMD",
        ]
        blocking = [p for p in install_policies
                    if any(k.lower() in p["policy"].lower()
                           for k in blocking_keywords)
                    and p["value"] in ("1", "2")]

        if not install_policies:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="mdm_software_install_policy",
            title=f"Políticas de control de instalación de software "
                  f"({len(install_policies)} reglas)",
            description=(
                "Se han detectado políticas corporativas que controlan la "
                "instalación de software en el equipo."
            ),
            risk_level="yellow",
            technical_risk=(
                "Estas políticas pueden bloquear la instalación de software "
                "no autorizado, deshabilitar el Panel de Control o "
                "restringir el acceso a herramientas del sistema."
            ),
            legal_risk=(
                "Las restricciones de instalación son una medida de seguridad "
                "corporativa estándar. No afectan directamente a los derechos "
                "del trabajador salvo que impidan el uso de herramientas laborales."
            ),
            what_it_is=(
                "Políticas de administración de Windows que determinan qué "
                "software puede instalarse y quién puede hacerlo."
            ),
            what_it_is_not=(
                "No es vigilancia del trabajador. Es control de la integridad "
                "del dispositivo corporativo."
            ),
            raw_data={
                "policies": install_policies,
                "blocking_policies": blocking
            }
        ))

    # ── Políticas DLP de dispositivos via MDM ──────────────────────

    def _check_dlp_device_policies(self):
        from core.audit_engine import AuditFinding

        dlp_policies = []

        dlp_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\PolicyManager\current\device\DeviceGuard",
             "DeviceGuard MDM"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
             "DataCollection Policy"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
             "InkWorkspace Policy"),
        ]

        for hive, path, label in dlp_keys:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        dlp_policies.append({
                            "source": label,
                            "policy": name,
                            "value": str(value),
                        })
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        # Comprobar Azure Information Protection / Microsoft Purview
        aip_indicators = []
        aip_paths = [
            r"SOFTWARE\Microsoft\MSIP",
            r"SOFTWARE\Microsoft\Azure Information Protection",
            r"SOFTWARE\Policies\Microsoft\Azure Information Protection",
        ]
        for path in aip_paths:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ
                )
                aip_indicators.append({"path": path, "present": True})
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        if not dlp_policies and not aip_indicators:
            return

        risk = "orange" if aip_indicators else "yellow"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="mdm_dlp_device_policy",
            title=f"Políticas DLP de dispositivo via MDM "
                  f"({len(dlp_policies)} reglas"
                  f"{', AIP/Purview activo' if aip_indicators else ''})",
            description=(
                "Se han detectado políticas de prevención de pérdida de datos "
                "aplicadas via MDM al dispositivo, incluyendo posiblemente "
                "Azure Information Protection / Microsoft Purview."
            ),
            risk_level=risk,
            technical_risk=(
                "Azure Information Protection (AIP) / Microsoft Purview "
                "puede clasificar y cifrar documentos automáticamente, "
                "registrar accesos y bloquear la transferencia de archivos "
                "etiquetados como confidenciales."
            ),
            legal_risk=(
                "El DLP de dispositivo que clasifica y controla documentos "
                "puede afectar archivos personales si están en el equipo corporativo. "
                "Requiere información previa bajo LOPDGDD art. 87."
            ),
            what_it_is=(
                "Herramientas de clasificación y protección de información "
                "corporativa que controlan cómo se usan y comparten los documentos."
            ),
            what_it_is_not=(
                "No es vigilancia del trabajador. Es protección de la información "
                "de la empresa frente a fuga de datos."
            ),
            raw_data={
                "dlp_policies": dlp_policies,
                "aip_indicators": aip_indicators
            }
        ))