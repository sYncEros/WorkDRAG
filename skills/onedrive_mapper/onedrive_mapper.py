# skills/onedrive_mapper/onedrive_mapper.py
"""
Skill — OneDrive Mapper
Documenta carpetas del sistema redirigidas a OneDrive/SharePoint (KFM),
calcula volumen de datos en nube corporativa, detecta archivos personales
y crea carpetas locales seguras fuera del alcance corporativo.
"""

import os
import json
import winreg
import subprocess
from pathlib import Path
from datetime import datetime


# ── Configuración ──────────────────────────────────────────────────────────────

# Carpeta local segura fuera de OneDrive
SAFE_LOCAL_ROOT = Path(os.environ.get("USERPROFILE", "")) / "TrabajoLocal"

SAFE_FOLDERS = [
    "Documentos_Personales",
    "Notas_Privadas",
    "Evidencias",
    "Comunicaciones_Sindicales",
]

# Claves KFM en registro
KFM_REGISTRY_KEYS = {
    "Desktop":   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    "Documents": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    "Pictures":  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
}

SHELL_FOLDER_NAMES = {
    "Desktop":        "{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}",
    "Personal":       "{F42EE2D3-909F-4907-8871-4C22FC0BF756}",
    "My Pictures":    "{0DDD015D-B06C-45D5-8C4C-F59713854639}",
    "My Music":       "{A0C69A99-21C8-4671-8703-7934162FCF1D}",
    "My Video":       "{35286A68-3C57-41A1-BBB1-0EAE73D76C95}",
}

# Extensiones de archivos personales típicos
PERSONAL_FILE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".rar", ".7z", ".txt", ".md",
}

# Palabras clave que sugieren contenido personal
PERSONAL_KEYWORDS = [
    "personal", "privado", "private", "nómina", "nomina",
    "contrato", "médico", "medico", "familia", "vacaciones",
    "sindicato", "denuncia", "abogado", "seguridad social",
]


class OneDriveMapper:
    SKILL_NAME = "onedrive_mapper"

    def __init__(self, engine):
        self.engine = engine
        self.redirected_folders = []
        self.onedrive_path      = None
        self.kfm_policies       = []
        self.personal_files     = []
        self.volume_bytes       = 0

    def run(self):
        print("[OneDrive] Iniciando mapeo de carpetas redirigidas...")
        self._detect_onedrive_path()
        self._detect_redirected_folders()
        self._detect_kfm_policies()
        self._scan_personal_files()
        self._create_safe_folders()
        self._report()

    # ── Detección de OneDrive ──────────────────────────────────────────────────

    def _detect_onedrive_path(self):
        """Detecta la ruta local de OneDrive corporativo."""
        candidates = [
            os.environ.get("OneDriveCommercial", ""),
            os.environ.get("OneDrive", ""),
        ]
        for c in candidates:
            if c and Path(c).exists():
                self.onedrive_path = Path(c)
                print(f"[OneDrive] Ruta OneDrive: {self.onedrive_path}")
                return

        # Buscar en registro
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\OneDrive\Accounts\Business1"
            )
            path, _ = winreg.QueryValueEx(key, "UserFolder")
            if path and Path(path).exists():
                self.onedrive_path = Path(path)
                print(f"[OneDrive] Ruta OneDrive (registro): {self.onedrive_path}")
        except OSError:
            pass

    def _detect_redirected_folders(self):
        """Detecta carpetas del sistema redirigidas a OneDrive via Shell Folders."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            )
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    value_expanded = os.path.expandvars(str(value))

                    is_onedrive = (
                        "onedrive" in value_expanded.lower() or
                        "sharepoint" in value_expanded.lower()
                    )

                    if is_onedrive:
                        folder_path = Path(value_expanded)
                        size_bytes  = self._get_folder_size(folder_path)
                        self.volume_bytes += size_bytes
                        self.redirected_folders.append({
                            "shell_name":  name,
                            "path":        value_expanded,
                            "exists":      folder_path.exists(),
                            "size_bytes":  size_bytes,
                            "size_human":  self._human_size(size_bytes),
                            "in_onedrive": is_onedrive,
                        })
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except OSError:
            pass

        if self.redirected_folders:
            print(
                f"[OneDrive] Carpetas redirigidas: {len(self.redirected_folders)} "
                f"— {self._human_size(self.volume_bytes)} en nube"
            )

    def _detect_kfm_policies(self):
        """Detecta políticas GPO de KFM que impiden desactivar sincronización."""
        kfm_policy_values = {
            "KFMSilentOptIn":          "Redirección silenciosa activada",
            "KFMBlockOptOut":          "Trabajador NO puede desactivar sincronización",
            "KFMBlockOptIn":           "Trabajador NO puede activar sincronización",
            "KFMSilentOptInWithNotification": "Redirección con notificación",
        }
        policy_keys = [
            r"SOFTWARE\Policies\Microsoft\OneDrive",
            r"SOFTWARE\Microsoft\OneDrive\Policies",
        ]
        for key_path in policy_keys:
            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    key = winreg.OpenKey(hive, key_path)
                    for policy_name, description in kfm_policy_values.items():
                        try:
                            value, _ = winreg.QueryValueEx(key, policy_name)
                            self.kfm_policies.append({
                                "policy":      policy_name,
                                "value":       value,
                                "description": description,
                                "source":      "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                            })
                        except OSError:
                            pass
                    winreg.CloseKey(key)
                except OSError:
                    pass

        if self.kfm_policies:
            block = [p for p in self.kfm_policies if "BlockOptOut" in p["policy"]]
            print(
                f"[OneDrive] Políticas KFM: {len(self.kfm_policies)} "
                + ("— BLOQUEO de desactivación activo" if block else "")
            )

    def _scan_personal_files(self):
        """Detecta posibles archivos personales en carpetas redirigidas a OneDrive."""
        if not self.redirected_folders:
            return

        for folder in self.redirected_folders:
            folder_path = Path(folder["path"])
            if not folder_path.exists():
                continue
            try:
                for f in folder_path.rglob("*"):
                    if not f.is_file():
                        continue
                    name_lower = f.name.lower()
                    # Detectar por extensión + keyword en nombre
                    has_personal_ext = f.suffix.lower() in PERSONAL_FILE_EXTENSIONS
                    has_personal_kw  = any(
                        kw in name_lower for kw in PERSONAL_KEYWORDS
                    )
                    if has_personal_ext and has_personal_kw:
                        self.personal_files.append({
                            "path":     str(f),
                            "name":     f.name,
                            "size":     self._human_size(f.stat().st_size),
                            "modified": datetime.fromtimestamp(
                                f.stat().st_mtime
                            ).strftime("%Y-%m-%d"),
                        })
                    if len(self.personal_files) >= 20:  # límite para no saturar
                        break
            except PermissionError:
                pass

        if self.personal_files:
            print(
                f"[OneDrive] Posibles archivos personales en nube: "
                f"{len(self.personal_files)}"
            )

    # ── Creación de carpetas seguras ───────────────────────────────────────────

    def _create_safe_folders(self):
        """Crea estructura de carpetas locales fuera de OneDrive."""
        try:
            SAFE_LOCAL_ROOT.mkdir(exist_ok=True)
            created = []
            for folder_name in SAFE_FOLDERS:
                folder = SAFE_LOCAL_ROOT / folder_name
                folder.mkdir(exist_ok=True)
                created.append(str(folder))

            # Crea README explicativo
            readme = SAFE_LOCAL_ROOT / "LEEME.txt"
            if not readme.exists():
                readme.write_text(
                    "CARPETA LOCAL SEGURA — fuera de OneDrive corporativo\n"
                    "=====================================================\n\n"
                    "Esta carpeta NO está sincronizada con OneDrive ni con\n"
                    "ningún servicio de nube corporativa.\n\n"
                    "Usa estas subcarpetas para:\n"
                    "- Documentos_Personales: archivos personales\n"
                    "- Notas_Privadas: notas que no deben salir del equipo\n"
                    "- Evidencias: capturas y documentación forense\n"
                    "- Comunicaciones_Sindicales: contacto con representantes\n\n"
                    f"Creada por WorkDRAG el {datetime.now().strftime('%Y-%m-%d')}\n",
                    encoding="utf-8"
                )
            print(f"[OneDrive] Carpetas seguras creadas en: {SAFE_LOCAL_ROOT}")
        except Exception as e:
            print(f"[OneDrive] Error creando carpetas seguras: {e}")

    # ── Utilidades ─────────────────────────────────────────────────────────────

    def _get_folder_size(self, path: Path) -> int:
        """Calcula el tamaño de una carpeta en bytes (muestra, no exhaustivo)."""
        total = 0
        try:
            for f in path.rglob("*"):
                if f.is_file():
                    try:
                        total += f.stat().st_size
                    except OSError:
                        pass
                if total > 10 * 1024 * 1024 * 1024:  # cap 10GB
                    break
        except (PermissionError, OSError):
            pass
        return total

    def _human_size(self, size_bytes: int) -> str:
        """Convierte bytes a formato legible."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

    # ── Reporte ────────────────────────────────────────────────────────────────

    def _report(self):
        from core.audit_engine import AuditFinding

        # ── Hallazgo 1: Carpetas redirigidas a nube ────────────────────────────
        if self.redirected_folders:
            block_policy = any(
                "BlockOptOut" in p["policy"] for p in self.kfm_policies
            )
            risk = "red" if block_policy else "orange"

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="onedrive_folder_map",
                title=(
                    f"{len(self.redirected_folders)} carpetas del sistema "
                    f"sincronizadas a nube corporativa "
                    f"({self._human_size(self.volume_bytes)})"
                    + (" — desactivación BLOQUEADA por GPO" if block_policy else "")
                ),
                description=(
                    f"Las siguientes carpetas del sistema están redirigidas "
                    f"a OneDrive/SharePoint corporativo: "
                    + ", ".join(
                        f["shell_name"] for f in self.redirected_folders
                    ) + f". Volumen total en nube: {self._human_size(self.volume_bytes)}."
                ),
                risk_level=risk,
                technical_risk=(
                    "Todo archivo guardado en estas carpetas es inmediatamente "
                    "accesible por el empleador a través de la consola de M365. "
                    + ("El trabajador no puede desactivar la sincronización "
                       "porque KFMBlockOptOut está activo por GPO."
                       if block_policy else
                       "El trabajador podría desactivar la sincronización manualmente.")
                ),
                legal_risk=(
                    "La redirección forzada de carpetas a nube corporativa sin "
                    "información previa al trabajador vulnera LOPDGDD art. 87 y "
                    "ET art. 20bis. El empleador tiene acceso técnico completo "
                    "a todos los archivos guardados en estas carpetas."
                ),
                what_it_is=(
                    "Known Folder Move (KFM) es una función de OneDrive que "
                    "redirige las carpetas principales de Windows a la nube "
                    "corporativa automáticamente."
                ),
                what_it_is_not=(
                    "No implica que el empleador esté leyendo activamente los archivos, "
                    "pero sí que tiene capacidad técnica de hacerlo en cualquier momento."
                ),
                raw_data={
                    "redirected_folders": self.redirected_folders,
                    "kfm_policies":       self.kfm_policies,
                    "total_volume":       self._human_size(self.volume_bytes),
                    "block_opt_out":      block_policy,
                    "onedrive_path":      str(self.onedrive_path or "No detectado"),
                    "safe_local_path":    str(SAFE_LOCAL_ROOT),
                }
            ))

        # ── Hallazgo 2: Políticas KFM de bloqueo ──────────────────────────────
        block_policies = [
            p for p in self.kfm_policies
            if "BlockOptOut" in p["policy"] or "SilentOptIn" in p["policy"]
        ]
        if block_policies:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="onedrive_kfm_block",
                title=(
                    f"GPO impide al trabajador desactivar sincronización OneDrive "
                    f"({len(block_policies)} políticas)"
                ),
                description=(
                    "Políticas activas: " +
                    ", ".join(
                        f"{p['policy']} = {p['value']}"
                        for p in block_policies
                    )
                ),
                risk_level="red",
                technical_risk=(
                    "KFMBlockOptOut activo significa que el trabajador no puede "
                    "desactivar la sincronización de sus carpetas principales "
                    "con la nube corporativa desde la configuración de OneDrive."
                ),
                legal_risk=(
                    "Impedir al trabajador controlar qué datos van a la nube "
                    "corporativa puede vulnerar el principio de control del "
                    "interesado bajo RGPD art. 5 y LOPDGDD art. 87."
                ),
                what_it_is=(
                    "Política GPO corporativa que bloquea la opción de desactivar "
                    "la sincronización de carpetas con OneDrive."
                ),
                what_it_is_not=(
                    "No es un malware ni un acceso no autorizado. "
                    "Es una política corporativa estándar, pero que el trabajador "
                    "tiene derecho a conocer y cuestionar."
                ),
                raw_data={"block_policies": block_policies}
            ))

        # ── Hallazgo 3: Archivos personales detectados en nube ─────────────────
        if self.personal_files:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="onedrive_personal_exposure",
                title=(
                    f"Posibles archivos personales en nube corporativa: "
                    f"{len(self.personal_files)} detectados"
                ),
                description=(
                    "Se han detectado archivos con nombres que sugieren contenido "
                    "personal (nóminas, contratos, documentos médicos) en carpetas "
                    "sincronizadas con OneDrive corporativo."
                ),
                risk_level="orange",
                technical_risk=(
                    "Estos archivos son técnicamente accesibles por el administrador "
                    "de M365 de la empresa a través de la consola de SharePoint."
                ),
                legal_risk=(
                    "El acceso del empleador a documentos personales del trabajador "
                    "almacenados sin su conocimiento en la nube corporativa puede "
                    "vulnerar LOPDGDD art. 87 y RGPD art. 5."
                ),
                what_it_is=(
                    "Archivos guardados en carpetas redirigidas que por su nombre "
                    "sugieren contenido personal, no laboral."
                ),
                what_it_is_not=(
                    "La herramienta solo analiza nombres de archivo, no su contenido. "
                    "Puede haber falsos positivos."
                ),
                raw_data={
                    "personal_files": self.personal_files,
                    "safe_path":      str(SAFE_LOCAL_ROOT),
                }
            ))

        # ── Hallazgo 4: Carpetas seguras creadas ───────────────────────────────
        if SAFE_LOCAL_ROOT.exists():
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="onedrive_safe_folders",
                title=f"Carpetas locales seguras creadas en {SAFE_LOCAL_ROOT}",
                description=(
                    "Se han creado carpetas locales fuera del alcance de OneDrive "
                    "corporativo para uso personal del trabajador."
                ),
                risk_level="green",
                technical_risk="Sin riesgo — carpetas locales no sincronizadas.",
                legal_risk=(
                    "El trabajador tiene derecho a mantener documentos personales "
                    "fuera del alcance del empleador."
                ),
                what_it_is=(
                    f"Carpetas creadas en {SAFE_LOCAL_ROOT} fuera de OneDrive: "
                    + ", ".join(SAFE_FOLDERS)
                ),
                what_it_is_not=(
                    "No garantiza privacidad absoluta — un admin con acceso RDP "
                    "podría acceder igualmente a estas carpetas."
                ),
                raw_data={
                    "safe_root":    str(SAFE_LOCAL_ROOT),
                    "safe_folders": SAFE_FOLDERS,
                }
            ))

        print(
            f"[OneDrive] Completado — "
            f"{len(self.redirected_folders)} carpetas redirigidas, "
            f"{len(self.kfm_policies)} políticas KFM, "
            f"{len(self.personal_files)} archivos personales detectados, "
            f"carpetas seguras: {SAFE_LOCAL_ROOT.exists()}"
        )