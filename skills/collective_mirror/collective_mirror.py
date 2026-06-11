# skills/collective_mirror/collective_mirror.py
"""
Skill — Espejo Colectivo (Collective Mirror)

Genera un "perfil anónimo" del entorno laboral que puede ser
compartido sin revelar identidad.

Funciona en modo LOCAL: no envía datos a ningún servidor.
El trabajador decide qué compartir y cómo.

Principio: transformar casos individuales en patrón colectivo.
"Es mucho más difícil despachar un patrón que un caso aislado."

Uso:
    mirror = CollectiveMirror()
    profile = mirror.generate_mirror(findings)
    mirror.export_profile(profile, "mi_perfil_anonimo.json")
"""

import json
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Estructura del Perfil Anónimo ─────────────────────────────────────────────

@dataclass
class MirrorProfile:
    """Perfil anónimo de un entorno laboral."""
    version: str = "1.0"
    generated: str = ""
    
    # Capacidades detectadas (booleano — sin detalles)
    has_rdp: bool = False
    has_dlp: bool = False
    has_ssl_inspection: bool = False
    has_kfm_forced: bool = False
    has_edr: bool = False
    has_copilot: bool = False
    has_recall: bool = False
    has_remote_tools: bool = False
    
    # Métricas agregadas (sin datos identificativos)
    total_findings: int = 0
    red_findings: int = 0
    orange_findings: int = 0
    yellow_findings: int = 0
    green_findings: int = 0
    
    hardening_gaps: int = 0
    accounts_with_remote_access: int = 0
    monitoring_tools_count: int = 0
    credentials_exposed: int = 0
    
    # Sector (opcional, para agregación por industria)
    sector: str = "no_especificado"
    country: str = "ES"
    company_size: str = "no_especificado"  # pyme, mediana, grande, multinacional
    
    # Integridad
    integrity_hash: str = ""

    def __post_init__(self):
        if not self.generated:
            self.generated = datetime.now().isoformat()


# ── Motor Principal ───────────────────────────────────────────────────────────

class CollectiveMirror:
    """
    Genera perfiles anónimos para compartir con sindicato o investigadores.
    
    Garantías:
    - NO incluye nombres, IPs, rutas, cuentas ni datos identificativos.
    - Solo incluye presencia/ausencia de capacidades (booleano).
    - Solo incluye conteos agregados (números).
    - El hash de integridad permite verificar que no se ha manipulado.
    - El trabajador revisa el perfil ANTES de compartirlo.
    """

    def generate_mirror(self, findings: list, 
                        sector: str = "no_especificado",
                        company_size: str = "no_especificado") -> MirrorProfile:
        """
        Genera perfil anónimo a partir de hallazgos de auditoría.
        
        Args:
            findings: Lista de AuditFinding (objetos o dicts).
            sector: Sector de la empresa (tecnología, banca, salud, etc.)
            company_size: Tamaño (pyme, mediana, grande, multinacional)
        
        Returns:
            MirrorProfile con datos anonimizados.
        """
        profile = MirrorProfile(
            sector=sector,
            company_size=company_size,
        )
        
        # Detectar capacidades (solo booleano)
        categories = set(self._get_category(f) for f in findings)
        
        profile.has_rdp = "identity_remote_access" in categories
        profile.has_dlp = "exfiltration_dlp_monitoring" in categories
        profile.has_ssl_inspection = "ssl_inspection" in categories
        profile.has_kfm_forced = "cloud_sync_folder_redirect" in categories
        profile.has_edr = "edr_xdr" in categories
        profile.has_copilot = "ai_copilot" in categories
        profile.has_recall = "ai_windows_recall" in categories
        profile.has_remote_tools = any(
            "remote" in self._get_category(f) for f in findings
        )
        
        # Métricas agregadas
        profile.total_findings = len(findings)
        profile.red_findings = sum(1 for f in findings if self._get_risk(f) == "red")
        profile.orange_findings = sum(1 for f in findings if self._get_risk(f) == "orange")
        profile.yellow_findings = sum(1 for f in findings if self._get_risk(f) == "yellow")
        profile.green_findings = sum(1 for f in findings if self._get_risk(f) == "green")
        
        profile.hardening_gaps = sum(
            1 for f in findings if "hardening" in self._get_category(f)
        )
        profile.accounts_with_remote_access = self._count_remote_accounts(findings)
        profile.monitoring_tools_count = self._count_monitoring_tools(findings)
        profile.credentials_exposed = self._count_credentials(findings)
        
        # Calcular hash de integridad
        profile_data = asdict(profile)
        profile_data.pop("integrity_hash", None)
        profile.integrity_hash = hashlib.sha256(
            json.dumps(profile_data, sort_keys=True).encode()
        ).hexdigest()
        
        return profile

    def export_profile(self, profile: MirrorProfile, 
                       output_path: Optional[str] = None) -> Path:
        """
        Exporta el perfil anónimo a un archivo JSON.
        
        Args:
            profile: MirrorProfile generado.
            output_path: Ruta de salida. Si None, usa exports/mirror_profile.json.
        
        Returns:
            Path del archivo generado.
        """
        if output_path is None:
            output_path = Path("exports") / "mirror_profile.json"
        else:
            output_path = Path(output_path)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = asdict(profile)
        data["_metadata"] = {
            "tool": "WorkDRAG — Collective Mirror v1.0",
            "purpose": (
                "Perfil anónimo de entorno laboral para agregación colectiva. "
                "No contiene datos identificativos del trabajador ni la empresa."
            ),
            "usage_rights": (
                "Este perfil puede ser compartido libremente con: "
                "sindicatos, comités de empresa, investigadores, AEPD. "
                "El trabajador ha revisado y aprobado su contenido."
            ),
            "verification": (
                "Para verificar integridad: recalcular SHA-256 del contenido "
                "excluyendo el campo 'integrity_hash' y '_metadata'."
            ),
        }
        
        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        
        return output_path

    def compare_profiles(self, profiles: list) -> dict:
        """
        Compara múltiples perfiles anónimos para detectar patrones colectivos.
        
        Args:
            profiles: Lista de MirrorProfile o dicts.
        
        Returns:
            Dict con estadísticas agregadas del colectivo.
        """
        n = len(profiles)
        if n == 0:
            return {"error": "No hay perfiles para comparar."}
        
        # Calcular porcentajes
        stats = {
            "total_profiles": n,
            "capabilities": {
                "rdp_enabled": self._percentage(profiles, "has_rdp"),
                "dlp_active": self._percentage(profiles, "has_dlp"),
                "ssl_inspection": self._percentage(profiles, "has_ssl_inspection"),
                "kfm_forced": self._percentage(profiles, "has_kfm_forced"),
                "edr_deployed": self._percentage(profiles, "has_edr"),
                "copilot_active": self._percentage(profiles, "has_copilot"),
                "recall_enabled": self._percentage(profiles, "has_recall"),
            },
            "risk_average": {
                "avg_red_findings": sum(
                    self._get_field_int(p, "red_findings") for p in profiles
                ) / n,
                "avg_total_findings": sum(
                    self._get_field_int(p, "total_findings") for p in profiles
                ) / n,
                "avg_hardening_gaps": sum(
                    self._get_field_int(p, "hardening_gaps") for p in profiles
                ) / n,
            },
            "narrative": self._generate_collective_narrative(profiles, n),
        }
        
        return stats

    # ── Generación de Narrativa Colectiva ─────────────────────────────────────

    def _generate_collective_narrative(self, profiles: list, n: int) -> str:
        """Genera una narrativa legible de los patrones colectivos."""
        rdp_pct = self._percentage(profiles, "has_rdp")
        dlp_pct = self._percentage(profiles, "has_dlp")
        ssl_pct = self._percentage(profiles, "has_ssl_inspection")
        kfm_pct = self._percentage(profiles, "has_kfm_forced")
        
        lines = []
        lines.append(f"Análisis de {n} entornos laborales:")
        lines.append("")
        
        if rdp_pct > 50:
            lines.append(
                f"• {rdp_pct}% tiene acceso remoto habilitado. "
                "Esto sugiere una política generalizada, no un caso aislado."
            )
        if ssl_pct > 50:
            lines.append(
                f"• {ssl_pct}% tiene inspección de tráfico HTTPS. "
                "El alcance de esta medida debería estar documentado en la DPIA."
            )
        if kfm_pct > 50:
            lines.append(
                f"• {kfm_pct}% tiene carpetas personales sincronizadas forzosamente. "
                "Esto afecta a datos personales de forma masiva."
            )
        if dlp_pct > 50:
            lines.append(
                f"• {dlp_pct}% tiene DLP activo inspeccionando contenido. "
                "La proporcionalidad de esta medida es cuestionable si no hay DPIA."
            )
        
        lines.append("")
        lines.append(
            "Estos datos colectivos pueden presentarse ante el comité de empresa, "
            "la AEPD o la ITSS como evidencia de patrón organizativo."
        )
        
        return "\n".join(lines)

    # ── Utilidades ────────────────────────────────────────────────────────────

    @staticmethod
    def _get_category(finding) -> str:
        if isinstance(finding, dict):
            return finding.get("category", "")
        return getattr(finding, "category", "")

    @staticmethod
    def _get_risk(finding) -> str:
        if isinstance(finding, dict):
            return finding.get("risk_level", "green")
        return getattr(finding, "risk_level", "green")

    def _count_remote_accounts(self, findings: list) -> int:
        """Cuenta cuentas con acceso remoto (sin revelar nombres)."""
        for f in findings:
            if self._get_category(f) == "identity_remote_access":
                raw = self._get_raw_data(f)
                if isinstance(raw, dict):
                    accounts = raw.get("accounts", [])
                    if isinstance(accounts, list):
                        return len(accounts)
        return 0

    def _count_monitoring_tools(self, findings: list) -> int:
        """Cuenta herramientas de monitorización detectadas."""
        monitoring_categories = {
            "edr_xdr", "ssl_inspection", "exfiltration_dlp_monitoring",
            "behavior_logging_capabilities", "activity_resources",
        }
        return sum(
            1 for f in findings 
            if self._get_category(f) in monitoring_categories
        )

    def _count_credentials(self, findings: list) -> int:
        """Cuenta credenciales expuestas (solo número)."""
        for f in findings:
            if self._get_category(f) == "identity_stored_credentials":
                raw = self._get_raw_data(f)
                if isinstance(raw, dict):
                    return raw.get("count", 0)
        return 0

    @staticmethod
    def _get_raw_data(finding) -> dict:
        if isinstance(finding, dict):
            return finding.get("raw_data", {})
        return getattr(finding, "raw_data", {})

    @staticmethod
    def _percentage(profiles: list, field: str) -> float:
        """Calcula porcentaje de perfiles con un campo True."""
        n = len(profiles)
        if n == 0:
            return 0.0
        count = sum(
            1 for p in profiles
            if (p.get(field, False) if isinstance(p, dict) else getattr(p, field, False))
        )
        return round((count / n) * 100, 1)

    @staticmethod
    def _get_field_int(profile, field: str) -> int:
        if isinstance(profile, dict):
            return profile.get(field, 0)
        return getattr(profile, field, 0)


# ── Interfaz CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  Espejo Colectivo — Generador de Perfil Anónimo")
    print("  " + "─" * 50)
    print("  Este módulo genera un perfil anónimo de tu entorno")
    print("  que puedes compartir sin revelar tu identidad.")
    print("\n  Uso: importar desde main.py o ejecutar con datos de auditoría.")
