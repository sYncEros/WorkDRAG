# skills/cloud_sync_audit/cloud_sync_scanner.py
"""
Skill 8 — Cloud Sync Monitor
Detecta sincronización de datos en segundo plano:
OneDrive, SharePoint, Google Drive, Dropbox, Box,
y otros servicios que sacan datos del equipo silenciosamente.
"""

import winreg
import subprocess
import json
import psutil
from pathlib import Path


# Servicios de sincronización conocidos
SYNC_SERVICES = {
    "onedrive": {
        "name": "Microsoft OneDrive",
        "processes": ["onedrive", "filecoauth", "filesynchelper"],
        "registry": r"SOFTWARE\Microsoft\OneDrive",
        "risk": "orange",
        "data_type": "Archivos del perfil de usuario, documentos, escritorio",
        "destination": "Microsoft Azure (EEUU/UE según configuración)",
    },
    "sharepoint": {
        "name": "SharePoint / OneDrive Empresarial",
        "processes": ["groove", "msoidsvc", "spopluginwkr"],
        "registry": r"SOFTWARE\Microsoft\Office\16.0\Common\Internet",
        "risk": "orange",
        "data_type": "Documentos corporativos, librerías de SharePoint",
        "destination": "Microsoft 365 (tenant corporativo)",
    },
    "googledrive": {
        "name": "Google Drive",
        "processes": ["googledrivefs", "googledrivesyncd", "googledrive"],
        "registry": r"SOFTWARE\Google\DriveFS",
        "risk": "orange",
        "data_type": "Archivos sincronizados con Google Drive",
        "destination": "Google Cloud (EEUU)",
    },
    "dropbox": {
        "name": "Dropbox",
        "processes": ["dropbox"],
        "registry": r"SOFTWARE\Dropbox",
        "risk": "orange",
        "data_type": "Carpeta Dropbox y subcarpetas",
        "destination": "Amazon AWS (EEUU/UE)",
    },
    "box": {
        "name": "Box",
        "processes": ["box", "boxsync", "boxtools"],
        "registry": r"SOFTWARE\Box",
        "risk": "orange",
        "data_type": "Archivos sincronizados con Box",
        "destination": "Box Cloud (EEUU)",
    },
    "icloud": {
        "name": "iCloud Drive",
        "processes": ["icloudservices", "iclouddrive", "applefileserver"],
        "registry": r"SOFTWARE\Apple Inc.\iCloud",
        "risk": "orange",
        "data_type": "Documentos, fotos, datos de apps Apple",
        "destination": "Apple Cloud (EEUU/China)",
    },
    "mega": {
        "name": "MEGA",
        "processes": ["megasync"],
        "registry": r"SOFTWARE\Mega Limited",
        "risk": "yellow",
        "data_type": "Carpeta MEGA sincronizada",
        "destination": "MEGA NZ (Nueva Zelanda/UE)",
    },
}

# Carpetas de alto riesgo que no deberían sincronizarse
HIGH_RISK_SYNC_FOLDERS = [
    "Desktop", "Escritorio",
    "Documents", "Documentos",
    "Downloads", "Descargas",
    "Pictures", "Imágenes",
    "AppData",
]


class CloudSyncAudit:
    SKILL_NAME = "cloud_sync_audit"

    def __init__(self, engine):
        self.engine = engine
        self.running_procs = self._get_processes()

    def run(self):
        print("[CloudSync] Iniciando auditoría de sincronización en nube...")
        self._scan_sync_services()
        self._check_onedrive_detail()
        self._check_known_good_folders_syncing()
        self._check_backup_agents()
        self._check_corporate_sync_policy()

    def _get_processes(self) -> set:
        procs = set()
        for p in psutil.process_iter(["name"]):
            try:
                procs.add(p.info["name"].lower().replace(".exe", ""))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs

    # ── Escaneo de servicios de sync ───────────────────────────────

    def _scan_sync_services(self):
        from core.audit_engine import AuditFinding

        for svc_id, svc in SYNC_SERVICES.items():
            detected = self._detect_sync_service(svc)
            if not detected:
                continue

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="cloud_sync_service",
                title=f"{svc['name']} activo — sincronización en segundo plano",
                description=(
                    f"{svc['name']} está activo y sincronizando archivos "
                    f"hacia {svc['destination']}."
                ),
                risk_level=svc["risk"],
                technical_risk=(
                    f"Datos sincronizados: {svc['data_type']}. "
                    f"Destino: {svc['destination']}. "
                    "La sincronización ocurre automáticamente en segundo "
                    "plano sin intervención del usuario."
                ),
                legal_risk=(
                    "La sincronización automática puede constituir "
                    "transferencia internacional de datos personales "
                    "bajo RGPD cap. V. "
                    "En equipos corporativos el empleador debe tener "
                    "DPA con el proveedor de nube y base legal adecuada."
                ),
                what_it_is=(
                    f"{svc['name']} sincroniza automáticamente archivos "
                    "locales hacia servidores en la nube, "
                    "manteniéndolos accesibles desde cualquier dispositivo."
                ),
                what_it_is_not=(
                    "La sincronización en nube no implica acceso no "
                    "autorizado por terceros. El riesgo es la transferencia "
                    "de datos sin control explícito y la accesibilidad "
                    "desde otros dispositivos."
                ),
                raw_data={
                    "service": svc["name"],
                    "detection": detected,
                    "destination": svc["destination"]
                }
            ))
            print(f"[CloudSync] Detectado: {svc['name']}")

    def _detect_sync_service(self, svc: dict) -> dict:
        found = {}

        # Procesos activos
        active_procs = [
            p for p in svc.get("processes", [])
            if p in self.running_procs
        ]
        if active_procs:
            found["processes"] = active_procs

        # Registro
        if svc.get("registry"):
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    svc["registry"], 0, winreg.KEY_READ
                )
                winreg.CloseKey(key)
                found["registry"] = True
            except (FileNotFoundError, PermissionError, OSError):
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        svc["registry"], 0, winreg.KEY_READ
                    )
                    winreg.CloseKey(key)
                    found["registry"] = True
                except (FileNotFoundError, PermissionError, OSError):
                    pass

        return found if found else {}

    # ── OneDrive detalle ───────────────────────────────────────────

    def _check_onedrive_detail(self):
        from core.audit_engine import AuditFinding

        onedrive_info = {}

        # Carpeta local de OneDrive
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\OneDrive",
                0, winreg.KEY_READ
            )
            for field in ["UserFolder", "UserEmail",
                          "UserName", "LastSignInTime"]:
                try:
                    val, _ = winreg.QueryValueEx(key, field)
                    onedrive_info[field] = str(val)
                except (FileNotFoundError, OSError):
                    pass
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        if not onedrive_info:
            return

        # Analiza qué carpetas se están sincronizando
        user_folder = onedrive_info.get("UserFolder", "")
        synced_folders = []
        high_risk_folders = []

        if user_folder and Path(user_folder).exists():
            try:
                for item in Path(user_folder).iterdir():
                    if item.is_dir():
                        synced_folders.append(item.name)
                        if item.name in HIGH_RISK_SYNC_FOLDERS:
                            high_risk_folders.append(item.name)
            except PermissionError:
                pass

        # Known Folder Move — carpetas del sistema sincronizadas
        kfm_folders = self._check_known_folder_move()

        risk = "red" if kfm_folders or high_risk_folders else "orange"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="cloud_sync_onedrive_detail",
            title=f"OneDrive: detalle de sincronización"
                  + (f" — KFM activo ({len(kfm_folders)} carpetas sistema)"
                     if kfm_folders else ""),
            description=(
                f"OneDrive está sincronizando desde: "
                f"{user_folder or 'ruta no detectada'}. "
                + (f"Known Folder Move activo: {', '.join(kfm_folders)}. "
                   if kfm_folders else "")
                + (f"Carpetas de sistema sincronizadas: "
                   f"{', '.join(high_risk_folders)}."
                   if high_risk_folders else "")
            ),
            risk_level=risk,
            technical_risk=(
                "Known Folder Move (KFM) redirige automáticamente "
                "Escritorio, Documentos y Imágenes a OneDrive. "
                "Todo archivo guardado en estas carpetas se sincroniza "
                "inmediatamente a la nube sin acción del usuario."
            ),
            legal_risk=(
                "KFM activo significa que cualquier documento que el "
                "trabajador guarda en Escritorio o Documentos "
                "va automáticamente a Microsoft 365. "
                "Esto incluye documentos de trabajo, personales, "
                "y potencialmente confidenciales. "
                "Requiere información previa bajo LOPDGDD art. 87."
            ),
            what_it_is=(
                "Known Folder Move es una configuración de OneDrive que "
                "redirige las carpetas principales del sistema "
                "(Escritorio, Documentos, Imágenes) a OneDrive, "
                "sincronizándolas automáticamente."
            ),
            what_it_is_not=(
                "No es una extracción maliciosa de datos. "
                "Es una función de Microsoft para backup automático. "
                "El problema es la falta de transparencia "
                "y el impacto en la privacidad del trabajador."
            ),
            raw_data={
                "onedrive_info": onedrive_info,
                "synced_folders": synced_folders[:20],
                "high_risk_folders": high_risk_folders,
                "known_folder_move": kfm_folders,
            }
        ))

    def _check_known_folder_move(self) -> list:
        """Detecta si KFM está redirigiendo carpetas del sistema a OneDrive."""
        kfm_folders = []
        kfm_keys = [
            r"SOFTWARE\Microsoft\OneDrive\Accounts\Business1",
            r"SOFTWARE\Microsoft\OneDrive\Accounts\Personal",
        ]
        kfm_values = {
            "KFMSilentOptIn":        "KFM silencioso activado",
            "KFMSilentOptInFolders": "Carpetas en KFM silencioso",
        }

        for reg_path in kfm_keys:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    reg_path, 0, winreg.KEY_READ
                )
                for val_name in kfm_values:
                    try:
                        val, _ = winreg.QueryValueEx(key, val_name)
                        if val:
                            kfm_folders.append(f"{val_name}={val}")
                    except (FileNotFoundError, OSError):
                        pass
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        # También verifica via política GPO
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\OneDrive",
                0, winreg.KEY_READ
            )
            for val_name in ["KFMSilentOptIn", "KFMBlockOptOut"]:
                try:
                    val, _ = winreg.QueryValueEx(key, val_name)
                    if val:
                        kfm_folders.append(f"GPO:{val_name}={val}")
                except (FileNotFoundError, OSError):
                    pass
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        return kfm_folders

    # ── Carpetas del sistema sincronizando ─────────────────────────

    def _check_known_good_folders_syncing(self):
        from core.audit_engine import AuditFinding

        # Verifica si las carpetas shell apuntan a OneDrive
        shell_folders = {}
        redirected = []

        shell_paths = {
            "Desktop":   r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                         r"\Explorer\User Shell Folders",
            "Personal":  r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                         r"\Explorer\User Shell Folders",
        }

        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                r"\Explorer\User Shell Folders",
                0, winreg.KEY_READ
            )
            idx = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, idx)
                    val_str = str(val).lower()
                    if "onedrive" in val_str or "sharepoint" in val_str:
                        redirected.append({
                            "folder": name,
                            "target": str(val)
                        })
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        if redirected:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="cloud_sync_folder_redirect",
                title=f"Carpetas del sistema redirigidas a nube "
                      f"({len(redirected)} carpetas)",
                description=(
                    "Carpetas principales de Windows (Escritorio, "
                    "Documentos, etc.) están redirigidas hacia "
                    "OneDrive o SharePoint."
                ),
                risk_level="red",
                technical_risk=(
                    "Cada archivo que el trabajador guarda en estas "
                    "carpetas se sincroniza automáticamente a la nube "
                    "sin ninguna acción adicional. "
                    "Incluye: documentos de trabajo, archivos personales, "
                    "screenshots, descargas guardadas en escritorio."
                ),
                legal_risk=(
                    "La redirección automática de carpetas del sistema "
                    "implica que el empleador (a través de Microsoft 365) "
                    "tiene acceso inmediato a cualquier archivo guardado. "
                    "Esto puede incluir notas personales, documentos "
                    "sindicales o comunicaciones privadas. "
                    "LOPDGDD art. 87 y ET art. 20bis requieren "
                    "información previa y proporcionalidad."
                ),
                what_it_is=(
                    "Redirección de carpetas de Windows hacia OneDrive/"
                    "SharePoint, convirtiendo el almacenamiento local "
                    "en almacenamiento corporativo en la nube."
                ),
                what_it_is_not=(
                    "Es una práctica común en entornos corporativos "
                    "para backup y acceso multi-dispositivo. "
                    "No implica lectura activa de contenidos, "
                    "pero sí acceso técnico posible."
                ),
                raw_data={"redirected_folders": redirected}
            ))

    # ── Agentes de backup ──────────────────────────────────────────

    def _check_backup_agents(self):
        from core.audit_engine import AuditFinding

        backup_agents = {
            "veeam":        "Veeam Backup Agent",
            "carbonite":    "Carbonite Backup",
            "backblaze":    "Backblaze B2",
            "acronis":      "Acronis Cyber Backup",
            "commvault":    "CommVault",
            "veritas":      "Veritas Backup Exec",
            "cohesity":     "Cohesity DataProtect",
            "rubrik":       "Rubrik Cloud Data Management",
            "druva":        "Druva inSync",
            "crashplan":    "CrashPlan",
        }

        found_agents = {
            name: desc for name, desc in backup_agents.items()
            if name in self.running_procs
        }

        # Druva inSync es especialmente relevante — monitoriza endpoints
        if "druva" in found_agents:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="cloud_sync_backup_drp",
                title="Druva inSync detectado — backup y monitorización de endpoint",
                description=(
                    "Druva inSync está activo. Este producto combina "
                    "backup en nube con capacidades de monitorización "
                    "de endpoint y compliance."
                ),
                risk_level="orange",
                technical_risk=(
                    "Druva inSync puede: hacer backup completo del dispositivo, "
                    "aplicar políticas de retención de datos, "
                    "monitorizar actividad de archivos, "
                    "y en versiones enterprise: borrado remoto "
                    "y reporting de actividad del usuario."
                ),
                legal_risk=(
                    "Las capacidades de reporting de actividad de Druva "
                    "van más allá del backup y pueden constituir "
                    "monitorización encubierta si no se informa al trabajador."
                ),
                what_it_is=(
                    "Plataforma de protección de datos de endpoint "
                    "que combina backup, archivo y compliance."
                ),
                what_it_is_not=(
                    "No es específicamente software espía. "
                    "Es una herramienta de backup corporativo "
                    "con funciones de compliance adicionales."
                ),
                raw_data={"agent": "druva", "description": found_agents["druva"]}
            ))

        if found_agents and "druva" not in found_agents:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="cloud_sync_backup_agent",
                title=f"Agentes de backup activos ({len(found_agents)})",
                description=(
                    "Se han detectado agentes de backup corporativo "
                    "que copian datos del equipo a sistemas externos."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Los agentes de backup tienen acceso completo "
                    "al sistema de archivos para realizar copias. "
                    "Algunos incluyen capacidades de reporting de actividad."
                ),
                legal_risk=(
                    "El backup corporativo es generalmente legítimo "
                    "pero requiere información previa sobre qué datos "
                    "se copian, dónde se almacenan y quién tiene acceso."
                ),
                what_it_is=(
                    "Software que realiza copias automáticas del equipo "
                    "hacia almacenamiento corporativo o en la nube."
                ),
                what_it_is_not=(
                    "El backup no implica lectura activa de contenidos. "
                    "Es protección de datos, no vigilancia."
                ),
                raw_data={"agents": found_agents}
            ))

    # ── Política corporativa de sync ───────────────────────────────

    def _check_corporate_sync_policy(self):
        from core.audit_engine import AuditFinding

        policy_findings = {}

        # Política de OneDrive empresarial
        onedrive_policies = {
            r"SOFTWARE\Policies\Microsoft\OneDrive": [
                ("DisablePersonalSync",     "Sync personal desactivado"),
                ("KFMSilentOptIn",          "KFM silencioso forzado por GPO"),
                ("KFMBlockOptOut",          "Bloqueo de desactivación KFM"),
                ("AllowTenantList",         "Tenants permitidos"),
                ("BlockExternalSync",       "Bloqueo sync externo"),
                ("EnableADAL",              "Autenticación moderna"),
            ]
        }

        for reg_path, values in onedrive_policies.items():
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    reg_path, 0, winreg.KEY_READ
                )
                for val_name, description in values:
                    try:
                        val, _ = winreg.QueryValueEx(key, val_name)
                        policy_findings[description] = val
                    except (FileNotFoundError, OSError):
                        pass
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        # KFM forzado por política es especialmente relevante
        kfm_forced = (
            "KFM silencioso forzado por GPO" in policy_findings or
            "Bloqueo de desactivación KFM" in policy_findings
        )

        if policy_findings:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="cloud_sync_policy",
                title="Políticas corporativas de OneDrive activas"
                      + (" — KFM forzado por GPO" if kfm_forced else ""),
                description=(
                    "Se han detectado políticas GPO que configuran "
                    "el comportamiento de OneDrive en este equipo."
                ),
                risk_level="orange" if kfm_forced else "yellow",
                technical_risk=(
                    "Las políticas GPO de OneDrive pueden forzar la "
                    "sincronización de carpetas del sistema sin que el "
                    "usuario pueda desactivarla. "
                    "'KFMBlockOptOut' impide que el trabajador desactive "
                    "la sincronización de Escritorio y Documentos."
                ),
                legal_risk=(
                    "Forzar KFM mediante GPO sin información previa "
                    "al trabajador puede vulnerar LOPDGDD art. 87. "
                    "El trabajador no puede controlar qué datos "
                    "se sincronizan a la nube corporativa."
                ),
                what_it_is=(
                    "Configuración GPO que controla cómo OneDrive "
                    "se comporta en los equipos de la organización."
                ),
                what_it_is_not=(
                    "Las políticas GPO de OneDrive son gestión IT "
                    "corporativa legítima. El problema es la "
                    "transparencia hacia el trabajador."
                ),
                raw_data={
                    "policies": policy_findings,
                    "kfm_forced": kfm_forced
                }
            ))

        print("[CloudSync] Completado")