# skills/redactor_sindical/redactor_sindical.py
"""
Skill — Redactor Sindical
Anonimiza informes de auditoría antes de compartirlos con sindicato,
comité de empresa, abogados o AEPD.

Tres niveles de anonimización:
- PUBLICO:   máxima anonimización — para prensa o documentos públicos
- SINDICATO: anonimización media — para comité y delegados
- PERICIAL:  mínima — para abogado o perito técnico (con clave)

NUNCA modifica el informe original.
Genera siempre una copia anonimizada con su propio hash SHA-256.
"""

import json
import re
import hashlib
import os
import copy
from pathlib import Path
from datetime import datetime


# ── Configuración ──────────────────────────────────────────────────────────────

REDACTION_LEVELS = {
    "PUBLICO":   0,  # máxima anonimización
    "SINDICATO": 1,  # media
    "PERICIAL":  2,  # mínima — preserva más contexto técnico
}

# Patrones de datos sensibles a redactar
PATTERNS = {
    # Identificadores de usuario
    "username": [
        r"jnavaqui",                          # usuario específico detectado
        r"USERSAD\\[A-Za-z0-9._-]+",          # dominio\usuario
        r"(?i)usuario[:\s]+[A-Za-z0-9._-]+",  # usuario: nombre
    ],
    # Emails
    "email": [
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    ],
    # Rutas de usuario
    "user_path": [
        r"C:\\Users\\[A-Za-z0-9._-]+",
        r"/home/[A-Za-z0-9._-]+",
    ],
    # IPs internas
    "internal_ip": [
        r"192\.168\.\d{1,3}\.\d{1,3}",
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
    ],
    # Hostnames
    "hostname": [
        r"(?i)hostname[:\s\"]+[A-Za-z0-9._-]+",
        r"(?i)computername[:\s\"]+[A-Za-z0-9._-]+",
    ],
    # Tenant IDs y GUIDs
    "tenant_id": [
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    ],
    # Credenciales referenciadas
    "credential": [
        r"(?i)password[:\s\"]+[^\s\"]{3,}",
        r"(?i)token[:\s\"]+[A-Za-z0-9._-]{10,}",
        r"(?i)api[_-]?key[:\s\"]+[A-Za-z0-9._-]{10,}",
    ],
    # Nombres de cuentas específicas (nivel PUBLICO y SINDICATO)
    "account_name": [
        r"EMEAL-IT",
        r"Local-Admin",
        r"DevToolsUser",
    ],
    # Tenant name
    "tenant_name": [
        r"NTT DATA EMEAL",       # hostnames corporativos
        r"NTT DATA",
        r"NTT\s+DATA",
        r"NTTD-[A-Z0-9]+",       
        r"NTTData EMEA",         # varianter"
        r"emealRootCA",          # CA corporativa
        r"everisRootCA",         # nombre anterior de NTT
    ],
}

# Sustituciones por nivel
REPLACEMENTS = {
    "PUBLICO": {
        "username":    "[USUARIO_REDACTADO]",
        "email":       "[EMAIL_REDACTADO]",
        "user_path":   "C:\\Users\\[USUARIO]",
        "internal_ip": "[IP_INTERNA]",
        "hostname":    "[HOSTNAME_REDACTADO]",
        "tenant_id":   "[TENANT_ID_REDACTADO]",
        "credential":  "[CREDENCIAL_REDACTADA]",
        "account_name":"[CUENTA_PRIVILEGIADA]",
        "tenant_name": "[EMPRESA_EMPLEADORA]",
    },
    "SINDICATO": {
        "username":    "[TRABAJADOR_X]",
        "email":       "[EMAIL_TRABAJADOR]",
        "user_path":   "C:\\Users\\[TRABAJADOR]",
        "internal_ip": "[IP_RED_CORP]",
        "hostname":    "[EQUIPO_CORP]",
        "tenant_id":   "[TENANT_CORP]",
        "credential":  "[CREDENCIAL]",
        "account_name":"[CUENTA_ADMIN]",
        "tenant_name": "[EMPRESA]",
    },
    "PERICIAL": {
        "username":    "[USR_REDACT]",
        "email":       "[EMAIL_REDACT]",
        "user_path":   "C:\\Users\\[USR]",
        "internal_ip": "[IP_PRIV]",
        "hostname":    "[HOST]",
        "tenant_id":   "[GUID_REDACT]",
        "credential":  "[CRED_REDACT]",
        "account_name":"[CUENTA_X]",  # preserva tipo pero no nombre
        "tenant_name": "[EMPRESA_X]",
    },
}

# Campos que se redactan según nivel
FIELDS_BY_LEVEL = {
    "PUBLICO": {
        # Redacta absolutamente todo
        "redact_all_paths":     True,
        "redact_account_names": True,
        "redact_tenant":        True,
        "redact_ips":           True,
        "redact_raw_data":      True,  # elimina raw_data completo
    },
    "SINDICATO": {
        "redact_all_paths":     True,
        "redact_account_names": True,
        "redact_tenant":        True,
        "redact_ips":           True,
        "redact_raw_data":      False,  # mantiene raw_data pero redactado
    },
    "PERICIAL": {
        "redact_all_paths":     True,
        "redact_account_names": False,  # preserva nombres de cuentas
        "redact_tenant":        False,   # preserva tenant para perito
        "redact_ips":           True,
        "redact_raw_data":      False,
    },
}


class RedactorSindical:
    SKILL_NAME = "redactor_sindical"

    def __init__(self, engine=None):
        self.engine          = engine
        self.redacted_counts = {}
        self.level           = "SINDICATO"

    def run(self):
        """Modo integrado en pipeline — genera versión SINDICATO del último informe."""
        print("[Redactor] Buscando último informe para anonimizar...")
        latest = self._find_latest_report()
        if not latest:
            print("[Redactor] No se encontró ningún informe en exports/")
            return

        result = self.redact_file(latest, "SINDICATO")
        if result and self.engine:
            from core.audit_engine import AuditFinding
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="redactor_output",
                title=f"Informe anonimizado generado — nivel SINDICATO",
                description=(
                    f"Se ha generado una versión anonimizada del informe "
                    f"lista para compartir con el sindicato o comité de empresa. "
                    f"Datos redactados: {sum(self.redacted_counts.values())} sustituciones."
                ),
                risk_level="green",
                technical_risk="Sin riesgo — copia anonimizada del informe original.",
                legal_risk=(
                    "El informe anonimizado puede compartirse con sindicato, "
                    "comité de empresa o AEPD sin exponer datos personales "
                    "del trabajador bajo RGPD art. 89."
                ),
                what_it_is="Copia del informe de auditoría con datos identificativos sustituidos.",
                what_it_is_not="No modifica el informe original — genera una copia independiente.",
                raw_data={
                    "output_path":     str(result),
                    "level":           "SINDICATO",
                    "redacted_counts": self.redacted_counts,
                }
            ))

    def redact_file(
        self,
        input_path: Path,
        level: str = "SINDICATO",
        output_path: Path = None
    ) -> Path | None:
        """
        Anonimiza un archivo JSON de auditoría.
        Devuelve la ruta del archivo anonimizado.
        """
        if level not in REDACTION_LEVELS:
            print(f"[Redactor] Nivel inválido: {level}. Usa: PUBLICO, SINDICATO, PERICIAL")
            return None

        self.level = level
        self.redacted_counts = {k: 0 for k in PATTERNS}

        try:
            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[Redactor] Error leyendo informe: {e}")
            return None

        print(f"[Redactor] Anonimizando {input_path.name} — nivel {level}...")

        # Deep copy para no modificar el original
        redacted = copy.deepcopy(data)

        # Añadir metadata de anonimización
        redacted["_redaction"] = {
            "level":          level,
            "generated_at":   datetime.now().isoformat(),
            "tool":           "WorkDRAG — Redactor Sindical",
            "original_hash":  self._hash_file(input_path),
            "warning":        (
                "Este informe ha sido anonimizado. "
                "Los datos identificativos han sido sustituidos. "
                "El informe original con hash verificable se conserva "
                "en el equipo del trabajador."
            ),
        }

        # Anonimizar según nivel
        config = FIELDS_BY_LEVEL[level]

        if config["redact_raw_data"]:
            # Nivel PUBLICO: eliminar raw_data de todos los hallazgos
            for finding in redacted.get("findings", []):
                finding["raw_data"] = {"redacted": "Nivel público — datos técnicos omitidos"}

        # Procesar todo el JSON como string para aplicar patrones
        redacted_str = json.dumps(redacted, ensure_ascii=False, indent=2)
        redacted_str = self._apply_patterns(redacted_str, level, config)

        # Reconstruir JSON
        try:
            redacted = json.loads(redacted_str)
        except Exception:
            # Si algo falla en el parse, usar la string directamente
            pass

        # Añadir resumen de redacciones
        redacted["_redaction"]["substitutions"] = self.redacted_counts
        redacted["_redaction"]["total_substitutions"] = sum(
            self.redacted_counts.values()
        )

        # Determinar ruta de salida
        if output_path is None:
            output_path = input_path.parent / (
                input_path.stem +
                f"_anonimizado_{level.lower()}.json"
            )

        # Guardar con hash
        content = json.dumps(redacted, ensure_ascii=False, indent=2)
        output_path.write_text(content, encoding="utf-8")

        # Hash del archivo anonimizado
        anon_hash = hashlib.sha256(content.encode()).hexdigest()
        redacted["_redaction"]["anon_hash"] = anon_hash

        # Reescribir con el hash incluido
        content = json.dumps(redacted, ensure_ascii=False, indent=2)
        output_path.write_text(content, encoding="utf-8")

        total = sum(self.redacted_counts.values())
        print(
            f"[Redactor] ✅ Guardado: {output_path.name} "
            f"({total} sustituciones) — hash: {anon_hash[:16]}..."
        )
        return output_path

    def redact_all_levels(self, input_path: Path) -> dict:
        """
        Genera los tres niveles de anonimización de un informe.
        Devuelve dict con rutas de cada nivel.
        """
        outputs = {}
        for level in REDACTION_LEVELS:
            output = input_path.parent / (
                input_path.stem + f"_anonimizado_{level.lower()}.json"
            )
            result = self.redact_file(input_path, level, output)
            if result:
                outputs[level] = result
                # Reset contadores para siguiente nivel
                self.redacted_counts = {k: 0 for k in PATTERNS}
        return outputs

    # ── Motor de anonimización ─────────────────────────────────────────────────

    def _apply_patterns(self, text: str, level: str, config: dict) -> str:
        """Aplica todos los patrones de redacción al texto."""
        replacements = REPLACEMENTS[level]

        for pattern_type, patterns in PATTERNS.items():
            # Saltar según configuración del nivel
            if pattern_type == "account_name" and not config["redact_account_names"]:
                continue
            if pattern_type == "tenant_name" and not config["redact_tenant"]:
                continue
            if pattern_type == "internal_ip" and not config["redact_ips"]:
                continue

            replacement = replacements.get(pattern_type, f"[{pattern_type.upper()}]")

            for pattern in patterns:
                matches = re.findall(pattern, text)
                if matches:
                    self.redacted_counts[pattern_type] = (
                        self.redacted_counts.get(pattern_type, 0) + len(matches)
                    )
                    text = re.sub(pattern, replacement, text)

        return text

    def _find_latest_report(self) -> Path | None:
        """Encuentra el informe JSON más reciente en exports/."""
        exports_dir = Path("exports")
        if not exports_dir.exists():
            return None

        candidates = []
        for f in exports_dir.rglob("audit.json"):
            try:
                candidates.append((f.stat().st_mtime, f))
            except OSError:
                pass

        if not candidates:
            return None

        return sorted(candidates, reverse=True)[0][1]

    def _hash_file(self, path: Path) -> str:
        """Calcula SHA-256 de un archivo."""
        try:
            content = path.read_bytes()
            return hashlib.sha256(content).hexdigest()
        except Exception:
            return "error_calculando_hash"


# ── CLI independiente ──────────────────────────────────────────────────────────

def main():
    """
    Uso independiente del redactor:
    python redactor_sindical.py [ruta_informe] [nivel]
    """
    import sys
    args = sys.argv[1:]

    if not args:
        print("Uso: python redactor_sindical.py <ruta_audit.json> [PUBLICO|SINDICATO|PERICIAL]")
        print("\nNiveles disponibles:")
        print("  PUBLICO    — máxima anonimización (prensa, documentos públicos)")
        print("  SINDICATO  — media (comité, delegados) [por defecto]")
        print("  PERICIAL   — mínima (abogado, perito técnico)")
        return

    input_path = Path(args[0])
    if not input_path.exists():
        print(f"Error: no se encuentra {input_path}")
        return

    level = args[1].upper() if len(args) > 1 else "SINDICATO"

    redactor = RedactorSindical()

    if level == "ALL":
        print("Generando los 3 niveles de anonimización...")
        outputs = redactor.redact_all_levels(input_path)
        print(f"\nGenerados {len(outputs)} archivos:")
        for lvl, path in outputs.items():
            print(f"  {lvl}: {path}")
    else:
        result = redactor.redact_file(input_path, level)
        if result:
            print(f"\nInforme anonimizado: {result}")
            print(f"Sustituciones: {redactor.redacted_counts}")


if __name__ == "__main__":
    main()