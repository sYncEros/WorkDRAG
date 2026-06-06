# skills/git_identity_audit/git_identity_scanner.py
"""
Skill — Auditoría de identidad Git impuesta
Detecta configuraciones de autor Git que no corresponden al usuario real
del dispositivo: nombres/emails corporativos heredados, identidades de
terceros presentes en el .gitconfig global, ausencia de useConfigOnly, etc.

Contexto legal: un commit firmado con la identidad de otra persona puede
tener implicaciones en la autoría intelectual del trabajo y en la trazabilidad
de acciones sobre repositorios corporativos o personales.
"""

import subprocess
import os
import re
from pathlib import Path


# ── Constantes ────────────────────────────────────────────────────────────────

GITCONFIG_PATH = Path.home() / ".gitconfig"
SSH_CONFIG_PATH = Path.home() / ".ssh" / "config"
SSH_DIR = Path.home() / ".ssh"


# ── Clase principal ───────────────────────────────────────────────────────────

class GitIdentityAudit:
    SKILL_NAME = "git_identity_audit"

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[GitIdentity] Iniciando auditoría de identidad Git...")
        self._check_global_identity()
        self._check_use_config_only()
        self._check_gitconfig_metadata()
        self._check_ssh_config()
        self._check_local_repo_identity()

    # ── Comprobaciones ─────────────────────────────────────────────────────────

    def _check_global_identity(self):
        """Detecta si hay una identidad global fijada en .gitconfig."""
        name = self._git_config_global("user.name")
        email = self._git_config_global("user.email")

        if not name and not email:
            # Sin identidad global: correcto si useConfigOnly = true
            return

        # Heurística: el nombre de usuario del sistema (login) vs. el nombre Git
        system_user = os.environ.get("USERNAME", "").lower()
        git_name_lower = (name or "").lower()

        # Si el email es corporativo pero el dominio no coincide con nada del
        # username de Windows, podría ser una identidad "prestada"
        email_domain = ""
        if email and "@" in email:
            email_domain = email.split("@")[-1].lower()

        suspicious = False
        reason_parts = []

        if name and system_user and system_user not in git_name_lower:
            # El nombre Git no contiene el login de Windows como subcadena
            suspicious = True
            reason_parts.append(
                f"El nombre Git '{name}' no coincide con el usuario de Windows '{system_user}'"
            )

        if suspicious:
            self.engine.add_finding(
                self._make_finding(
                    skill=self.SKILL_NAME,
                    category="imposed_identity",
                    title="Identidad Git global que no corresponde al usuario del dispositivo",
                    description=(
                        f"user.name='{name}', user.email='{email}'. "
                        + " | ".join(reason_parts)
                        + ". Esta identidad se usa para firmar cualquier commit "
                        "realizado desde esta máquina, incluyendo proyectos personales."
                    ),
                    risk_level="orange",
                    technical_risk=(
                        "Todos los commits del usuario quedan firmados con la identidad "
                        "de un tercero. Si el repositorio se sube a un remoto, la autoría "
                        "aparece asociada a esa persona, no al autor real."
                    ),
                    legal_risk=(
                        "Puede generar confusión sobre la autoría intelectual del código "
                        "(art. 97 TRLPI). En contextos laborales, atribuir trabajo propio "
                        "a otra persona —o viceversa— puede tener consecuencias en "
                        "la acreditación de méritos o en responsabilidades derivadas de "
                        "commits concretos."
                    ),
                    what_it_is=(
                        "Una configuración Git global (user.name / user.email) que define "
                        "la firma de autoría usada en cada commit."
                    ),
                    what_it_is_not=(
                        "No es un mecanismo de acceso remoto por sí solo. No permite "
                        "que la persona nombrada lea ni escriba en el repositorio. "
                        "No es equivalente a una credencial de autenticación."
                    ),
                    raw_data={
                        "user.name": name,
                        "user.email": email,
                        "system_username": system_user,
                        "gitconfig_path": str(GITCONFIG_PATH),
                    },
                )
            )
        else:
            # Identidad presente pero aparentemente coherente: hallazgo informativo
            self.engine.add_finding(
                self._make_finding(
                    skill=self.SKILL_NAME,
                    category="global_identity_present",
                    title="Identidad Git global configurada",
                    description=(
                        f"user.name='{name}', user.email='{email}'. "
                        "La identidad parece coherente con el usuario del sistema."
                    ),
                    risk_level="green",
                    technical_risk="Sin riesgo técnico identificado.",
                    legal_risk="Sin riesgo legal identificado.",
                    what_it_is="Identidad Git global que firmará commits realizados desde esta máquina.",
                    what_it_is_not="No es una credencial de acceso remoto.",
                    raw_data={
                        "user.name": name,
                        "user.email": email,
                        "system_username": system_user,
                    },
                )
            )

    def _check_use_config_only(self):
        """Comprueba si useConfigOnly está activado (previene firmas automáticas)."""
        value = self._git_config_global("user.useConfigOnly")
        if value != "true":
            self.engine.add_finding(
                self._make_finding(
                    skill=self.SKILL_NAME,
                    category="missing_use_config_only",
                    title="user.useConfigOnly no está activado",
                    description=(
                        "Git puede inferir automáticamente una identidad de autor "
                        "a partir del nombre de host o variables de entorno si no "
                        "se fuerza el uso exclusivo de la configuración explícita. "
                        f"Valor actual: '{value or '(no configurado)'}'."
                    ),
                    risk_level="yellow",
                    technical_risk=(
                        "Sin useConfigOnly=true, Git puede generar commits con una "
                        "identidad inventada o heredada de configuraciones corporativas "
                        "sin que el usuario sea consciente."
                    ),
                    legal_risk=(
                        "Riesgo menor pero real: commits con autoría no controlada "
                        "dificultan la trazabilidad y pueden complicar reclamaciones "
                        "de autoría intelectual."
                    ),
                    what_it_is=(
                        "Parámetro Git que obliga a usar solo la identidad explícita "
                        "configurada en lugar de inferirla del entorno."
                    ),
                    what_it_is_not="No es una credencial de acceso ni un control de seguridad de red.",
                    raw_data={"user.useConfigOnly": value},
                )
            )

    def _check_gitconfig_metadata(self):
        """Revisa los metadatos del .gitconfig global para detectar modificaciones recientes."""
        if not GITCONFIG_PATH.exists():
            return

        stat = GITCONFIG_PATH.stat()
        import datetime
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
        ctime = datetime.datetime.fromtimestamp(stat.st_ctime)
        now = datetime.datetime.now()
        days_since_change = (now - mtime).days

        raw = {
            "path": str(GITCONFIG_PATH),
            "size_bytes": stat.st_size,
            "created": ctime.isoformat(),
            "last_modified": mtime.isoformat(),
            "days_since_last_change": days_since_change,
        }

        if days_since_change < 7:
            self.engine.add_finding(
                self._make_finding(
                    skill=self.SKILL_NAME,
                    category="gitconfig_recently_modified",
                    title=".gitconfig global modificado hace menos de 7 días",
                    description=(
                        f"Última modificación: {mtime.strftime('%d/%m/%Y %H:%M:%S')} "
                        f"({days_since_change} días). Puede indicar un cambio reciente "
                        "de identidad o una reconfiguración automatizada."
                    ),
                    risk_level="yellow",
                    technical_risk="Cambio reciente de configuración Git global.",
                    legal_risk=(
                        "Si el cambio fue realizado por un proceso automatizado o por "
                        "herramientas corporativas, el usuario puede haber perdido el "
                        "control sobre su identidad de firma."
                    ),
                    what_it_is="Metadato de sistema de ficheros del archivo .gitconfig.",
                    what_it_is_not="No es evidencia definitiva de intrusión; puede ser un cambio legítimo del propio usuario.",
                    raw_data=raw,
                )
            )

    def _check_ssh_config(self):
        """Detecta entradas en ~/.ssh/config y si las claves referenciadas existen."""
        if not SSH_CONFIG_PATH.exists():
            return

        content = SSH_CONFIG_PATH.read_text(encoding="utf-8", errors="replace")
        hosts = re.findall(r'Host\s+(\S+)', content, re.IGNORECASE)
        identity_files = re.findall(r'IdentityFile\s+(\S+)', content, re.IGNORECASE)

        missing_keys = []
        present_keys = []
        for idf in identity_files:
            p = Path(idf.replace("~", str(Path.home())))
            if p.exists():
                present_keys.append(str(p))
            else:
                missing_keys.append(str(p))

        if hosts or identity_files:
            risk = "yellow" if present_keys else "green"
            self.engine.add_finding(
                self._make_finding(
                    skill=self.SKILL_NAME,
                    category="ssh_config_present",
                    title="Configuración SSH personalizada detectada",
                    description=(
                        f"Hosts definidos: {hosts}. "
                        f"Claves presentes: {present_keys}. "
                        f"Claves referenciadas pero ausentes: {missing_keys}."
                    ),
                    risk_level=risk,
                    technical_risk=(
                        "Las claves SSH presentes permiten autenticación remota sin "
                        "contraseña a los hosts definidos. Si alguna entrada fue "
                        "añadida por un proceso ajeno al usuario, podría facilitar "
                        "acceso no autorizado a servidores."
                    ),
                    legal_risk=(
                        "Si la clave SSH es corporativa y da acceso a servidores de "
                        "la empresa desde un dispositivo personal o no gestionado, "
                        "puede incumplir las políticas de seguridad del empleador "
                        "y generar responsabilidades."
                    ),
                    what_it_is=(
                        "Archivo de configuración SSH que define alias de host, "
                        "usuarios y claves privadas para conexiones remotas."
                    ),
                    what_it_is_not="No es por sí solo evidencia de acceso no autorizado.",
                    raw_data={
                        "ssh_config_path": str(SSH_CONFIG_PATH),
                        "hosts": hosts,
                        "identity_files_present": present_keys,
                        "identity_files_missing": missing_keys,
                    },
                )
            )

    def _check_local_repo_identity(self):
        """Comprueba si el repo actual tiene una identidad local sobreescrita."""
        local_name = self._git_config_local("user.name")
        local_email = self._git_config_local("user.email")

        if local_name or local_email:
            self.engine.add_finding(
                self._make_finding(
                    skill=self.SKILL_NAME,
                    category="local_repo_identity",
                    title="Identidad Git local definida en el repositorio actual",
                    description=(
                        f"user.name='{local_name}', user.email='{local_email}'. "
                        "Esta identidad tiene prioridad sobre la global para commits "
                        "en este repositorio concreto."
                    ),
                    risk_level="yellow",
                    technical_risk=(
                        "Una identidad local puede enmascarar o diferir de la identidad "
                        "real del usuario. Si fue puesta por una herramienta corporativa, "
                        "el control de autoría pasa a terceros."
                    ),
                    legal_risk=(
                        "La autoría de commits en este repositorio quedará asociada a "
                        "esta identidad local, independientemente de quién realice "
                        "los commits físicamente."
                    ),
                    what_it_is="Identidad Git definida a nivel de repositorio local (.git/config).",
                    what_it_is_not="No es una credencial de red.",
                    raw_data={
                        "local_user.name": local_name,
                        "local_user.email": local_email,
                    },
                )
            )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _git_config_global(self, key: str) -> str:
        try:
            result = subprocess.run(
                ["git", "config", "--global", "--get", key],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            return ""

    def _git_config_local(self, key: str) -> str:
        try:
            result = subprocess.run(
                ["git", "config", "--local", "--get", key],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            return ""

    def _make_finding(self, **kwargs):
        from core.audit_engine import AuditFinding
        return AuditFinding(**kwargs)
