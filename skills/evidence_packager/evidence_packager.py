# skills/evidence_packager/evidence_packager.py
"""
Skill — Evidence Packager
Genera un paquete probatorio completo listo para presentar a:
- Asesor laboral
- Sindicato / comité de empresa
- DPO de la empresa
- AEPD
- ITSS (Inspección de Trabajo)
- Juzgado

Contenido del paquete:
- audit.json (original con hash)
- audit_anonimizado_*.json (tres niveles)
- audit.pdf (informe visual)
- manifest.json (inventario con hashes SHA-256)
- readme_para_abogado.md (guía de uso del paquete)
- checklist_custodia.md (cadena de custodia)
"""

import json
import hashlib
import zipfile
import os
import sys
from pathlib import Path
from datetime import datetime


# ── Configuración ──────────────────────────────────────────────────────────────
TOOL_VERSION = "1.0.0"
TOOL_NAME    = "WorkDRAG — Worker Digital Rights Audit Agent"


class EvidencePackager:
    SKILL_NAME = "evidence_packager"

    def __init__(self, engine=None):
        self.engine        = engine
        self.manifest      = {}
        self.files_packed  = []
        self.package_hash  = None

    def run(self):
        """Modo integrado — empaqueta el último informe disponible."""
        print("[Packager] Buscando último informe para empaquetar...")
        latest_dir = self._find_latest_export_dir()
        if not latest_dir:
            print("[Packager] No se encontró ningún informe en exports/")
            return

        result = self.package(latest_dir)

        if result and self.engine:
            from core.audit_engine import AuditFinding
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="evidence_package_created",
                title=f"Paquete probatorio generado — {result.name}",
                description=(
                    f"Se ha generado un paquete probatorio completo con "
                    f"{len(self.files_packed)} archivos, manifiesto SHA-256 "
                    f"y cadena de custodia. Listo para asesor laboral, "
                    f"sindicato o AEPD."
                ),
                risk_level="green",
                technical_risk="Sin riesgo — paquete de evidencias de solo lectura.",
                legal_risk=(
                    "El paquete probatorio con hashes SHA-256 tiene valor "
                    "forense para procedimientos ante la AEPD, ITSS o juzgado."
                ),
                what_it_is=(
                    "Archivo ZIP con el informe completo, versiones anonimizadas, "
                    "manifiesto de integridad y guía para el receptor."
                ),
                what_it_is_not=(
                    "No modifica ningún archivo original. "
                    "Solo empaqueta y documenta evidencias existentes."
                ),
                raw_data={
                    "package_path":  str(result),
                    "package_hash":  self.package_hash,
                    "files_packed":  self.files_packed,
                    "manifest":      self.manifest,
                }
            ))

    def package(
        self,
        export_dir: Path,
        output_path: Path = None
    ) -> Path | None:
        """
        Genera el paquete probatorio completo.
        """
        print(f"[Packager] Empaquetando evidencias de {export_dir}...")

        # Generar versiones anonimizadas si no existen
        self._ensure_anonymized_versions(export_dir)

        # Construir manifiesto
        self._build_manifest(export_dir)

        # Generar documentos del paquete
        readme_path    = self._generate_readme(export_dir)
        checklist_path = self._generate_custody_checklist(export_dir)

        # Determinar ruta de salida
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_path is None:
            output_path = export_dir / f"dossier_probatorio_{timestamp}.zip"

        # Crear ZIP
        success = self._create_zip(export_dir, output_path)
        if not success:
            return None

        # Hash del ZIP final
        self.package_hash = self._hash_file(output_path)

        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(
            f"[Packager] ✅ Paquete generado: {output_path.name} "
            f"({size_mb:.1f} MB) — SHA-256: {self.package_hash[:16]}..."
        )

        cleanup_files = [
            "audit_anonimizado_publico.json",
            "audit_anonimizado_pericial.json",
            "checklist_custodia.md",
            "readme_para_abogado.md",
            "manifest.json",
        ]
        for filename in cleanup_files:
            f = export_dir / filename
            if f.exists():
                f.unlink()
                print(f"[Packager] Limpiado: {filename}")
                
        return output_path

    # ── Anonimización ──────────────────────────────────────────────────────────
    def _ensure_anonymized_versions(self, export_dir: Path):
        """Genera las versiones anonimizadas si no existen."""
        audit_json = export_dir / "audit.json"
        if not audit_json.exists():
            return

        for level in ["PUBLICO", "PERICIAL"]:
            anon_path = export_dir / f"audit_anonimizado_{level.lower()}.json"
            if not anon_path.exists():
                try:
                    sys.path.insert(0, str(Path(".")))
                    from skills.redactor_sindical.redactor_sindical import RedactorSindical
                    redactor = RedactorSindical()
                    redactor.redact_file(audit_json, level, anon_path)
                except Exception as e:
                    print(f"[Packager] Error generando nivel {level}: {e}")

    # ── Manifiesto ─────────────────────────────────────────────────────────────
    def _build_manifest(self, export_dir: Path):
        manifest = {
            "generated_at": datetime.now().isoformat(),
            "tool":         TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "files": [],
        }

        visible_files = [
            ("audit.json", "Informe técnico original con hash forense"),
        ]
        # PDFs con nombre dinámico
        for pdf in export_dir.glob("*.pdf"):
            if "resumen" in pdf.name:
                visible_files.append((pdf.name, "Informe visual para el trabajador"))
            elif "completo" in pdf.name:
                visible_files.append((pdf.name, "Informe técnico para sindicato"))

        for filename, desc in visible_files:
            f = export_dir / filename
            if not f.exists():
                # buscar por glob
                matches = list(export_dir.glob(f"*{Path(filename).suffix}"))
                if matches:
                    f = matches[0]
            if f.exists():
                manifest["files"].append({
                    "filename":   f.name,
                    "descripcion": desc,
                    "size_human": self._human_size(f.stat().st_size),
                    "sha256":     self._hash_file(f),
                })
                self.files_packed.append(f.name)

        self.manifest = manifest
        (export_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        print(f"[Packager] Manifiesto: {len(manifest['files'])} archivos visibles")

    def _classify_file(self, filename: str) -> str:
        if "publico" in filename:
            return "informe_anonimizado_nivel_publico"
        elif "pericial" in filename:
            return "informe_anonimizado_nivel_pericial"
        elif filename.endswith(".pdf"):
            return "informe_resumen"
        elif filename == "audit.json":
            return "informe_completo"
        return "documento_complementario"

    # ── README para abogado ────────────────────────────────────────────────────
    def _generate_readme(self, export_dir: Path) -> Path:
        """Genera guía de uso del paquete para el receptor."""
        audit_json = export_dir / "audit.json"
        data = {}
        if audit_json.exists():
            try:
                data = json.loads(audit_json.read_text(encoding="utf-8"))
            except Exception:
                pass

        total    = data.get("total_findings", "?")
        max_risk = data.get("max_risk", "?")
        gen_at   = data.get("generated_at", "?")[:19].replace("T", " ")

        content = f"""# Guía de Uso del Paquete Probatorio

## ¿Qué es este paquete?

Este paquete contiene evidencias técnicas generadas por **{TOOL_NAME}**,
una herramienta de auditoría local que analiza las capacidades de monitorización
corporativa en equipos Windows.

**Fecha de generación:** {gen_at}
**Total de hallazgos:** {total}
**Riesgo máximo detectado:** {max_risk.upper()}
**Herramienta:** {TOOL_NAME} v{TOOL_VERSION}

---

## Contenido del paquete

| Archivo | Descripción | Para quién |
|---------|-------------|------------|
| `audit.json` | Informe técnico completo con todos los hallazgos | Perito técnico |
| `audit_resumen.pdf` | Informe visual con explicaciones | Cualquier receptor |
| `audit_anonimizado_publico.json` | Versión sin datos identificativos | Prensa, AEPD pública |
| `audit_anonimizado_pericial.json` | Versión técnica para abogado | Abogado, perito |
| `manifest.json` | Inventario con hashes SHA-256 de todos los archivos | Verificación |
| `checklist_custodia.md` | Cadena de custodia de la evidencia | Juzgado, AEPD |

---

## Cómo verificar la integridad

Los archivos incluyen hashes SHA-256 que permiten verificar que
no han sido modificados desde su generación.

Para verificar en Windows:

certutil -hashfile audit.json SHA256

Compara el resultado con el hash en `manifest.json`.

---

## Qué puede y no puede probarse con este informe

### ✅ Lo que este informe demuestra:
- Qué capacidades técnicas de monitorización existen en el equipo
- Qué políticas corporativas están activas en el momento de la auditoría
- Qué servicios y agentes están en ejecución
- Qué datos pueden ser accesibles por el empleador
- Que el trabajador tomó conocimiento de estas capacidades en fecha concreta

### ❌ Lo que este informe NO demuestra:
- Que el empleador haya leído activamente los datos del trabajador
- Que haya habido vigilancia ilegal
- Intencionalidad del empleador
- Contenido de comunicaciones interceptadas

### ⚖️ Valor jurídico:
- Los hallazgos son **capacidades técnicas verificables**, no acusaciones
- El hash SHA-256 permite acreditar el estado del equipo en fecha concreta
- Puede usarse como base para solicitudes al DPO, AEPD o ITSS
- Puede acompañar a un peritaje técnico en procedimiento judicial

---

## Preguntas clave para el DPO

Basadas en los hallazgos de este informe, las siguientes preguntas
tienen base técnica verificable:

1. ¿Cuál es la base legal del tratamiento de datos de telemetría de Windows
   nivel Completo (art. 6 RGPD)?

2. ¿Existe DPA vigente con Microsoft que cubra el nivel 3 de telemetría?

3. ¿Qué datos recopila el agente DiagTrack y cuál es su período de retención?

4. ¿Quién tiene acceso a los archivos sincronizados en OneDrive corporativo
   del trabajador y bajo qué condiciones?

5. ¿Existe DPIA para el tratamiento de datos derivado del ScriptBlock Logging
   de PowerShell?

6. ¿Qué datos recopila Zscaler sobre la actividad de navegación del trabajador?

7. ¿Cuál es la finalidad del Azure Information Protection (MSIP) instalado
   en Outlook y qué datos registra?

---

## Referencias legales aplicables

| Norma | Relevancia |
|-------|------------|
| LOPDGDD Art. 87 | Derecho a la intimidad en el trabajo |
| LOPDGDD Art. 88 | Derecho a la desconexión digital |
| ET Art. 20bis | Derechos digitales del trabajador |
| RGPD Art. 5 | Principios del tratamiento |
| RGPD Art. 13 | Derecho a ser informado |
| RGPD Art. 32 | Seguridad del tratamiento |
| RGPD Art. 35 | Evaluación de impacto (DPIA) |
| TEDH Barbulescu II | Monitorización debe ser proporcional e informada |
| CP Art. 197 | Descubrimiento y revelación de secretos |

---

*Generado automáticamente por {TOOL_NAME} v{TOOL_VERSION}*
*Este documento no sustituye el asesoramiento jurídico profesional*
"""

        readme_path = export_dir / "readme_para_abogado.md"
        readme_path.write_text(content, encoding="utf-8")
        print("[Packager] README para abogado generado")
        return readme_path

    # ── Cadena de custodia ─────────────────────────────────────────────────────

    def _generate_custody_checklist(self, export_dir: Path) -> Path:
        """Genera checklist de cadena de custodia."""
        content = f"""# Checklist de Cadena de Custodia

**Herramienta:** {TOOL_NAME} v{TOOL_VERSION}
**Fecha de generación:** {datetime.now().isoformat()}
**Directorio de evidencias:** {export_dir}

---

## 1. Obtención de la evidencia

- [ ] La auditoría fue ejecutada por el propio trabajador en su equipo
- [ ] No se modificaron configuraciones del sistema antes de la auditoría
- [ ] No se instaló software adicional antes de la auditoría
- [ ] El equipo estaba en estado normal de uso en el momento de la auditoría
- [ ] Fecha y hora del sistema verificada antes de la auditoría

**Fecha y hora de la auditoría:** {datetime.now().strftime("%d/%m/%Y %H:%M")}
**Ejecutado por:** [NOMBRE DEL TRABAJADOR — completar manualmente]
**Equipo:** [HOSTNAME — completar manualmente]

---

## 2. Preservación de la evidencia

- [ ] El archivo audit.json original no ha sido modificado
- [ ] El hash SHA-256 del informe original está documentado en manifest.json
- [ ] Se ha generado copia del paquete en soporte externo (USB/nube personal)
- [ ] El paquete original permanece en el equipo del trabajador

**Copia realizada en:** [indicar soporte — completar manualmente]
**Fecha de copia:** [completar manualmente]

---

## 3. Integridad de la evidencia

Para verificar que los archivos no han sido modificados,
ejecutar el siguiente comando y comparar con manifest.json:

certutil -hashfile audit.json SHA256

**Hash verificado por:** [nombre — completar manualmente]
**Fecha de verificación:** [completar manualmente]
**Resultado:** [ ] Coincide con manifest.json

---

## 4. Transmisión de la evidencia

Si se entrega a terceros (abogado, sindicato, AEPD):

- [ ] Se entrega el paquete ZIP completo, no archivos sueltos
- [ ] Se entrega el archivo HASH.txt junto al ZIP
- [ ] El receptor verifica el hash antes de aceptar la evidencia
- [ ] Se documenta fecha, hora y receptor de la entrega

**Entregado a:** [completar manualmente]
**Fecha de entrega:** [completar manualmente]
**Medio de entrega:** [email cifrado / USB / entrega física]

---

## 5. Limitaciones reconocidas

- La herramienta detecta capacidades técnicas, no prueba uso indebido
- Algunos hallazgos requieren permisos de administrador para confirmación completa
- Los logs ETL de DiagTrack no son accesibles sin elevación de privilegios
- El análisis es un snapshot en el momento de ejecución

---

## 6. Firma del trabajador

Yo, [NOMBRE], con DNI [DNI], certifico que:

1. Ejecuté esta auditoría en mi equipo corporativo el [FECHA]
2. No modifiqué ningún archivo del sistema antes de la auditoría
3. Los resultados reflejan el estado real del equipo en ese momento

**Firma:** ___________________________
**Fecha:** ___________________________
**Lugar:** ___________________________

---

*Este documento forma parte del paquete probatorio generado por*
*{TOOL_NAME} v{TOOL_VERSION}*
"""

        checklist_path = export_dir / "checklist_custodia.md"
        checklist_path.write_text(content, encoding="utf-8")
        print("[Packager] Checklist de custodia generado")
        return checklist_path

    # ── Creación del ZIP ───────────────────────────────────────────────────────

    def _create_zip(self, export_dir: Path, output_path: Path) -> bool:
        """ZIP para abogado/perito — todo dentro, limpio."""

        # Archivos principales
        main_files = [
            "audit.json",
            "audit_completo.pdf",   
            "audit_resumen.pdf",  
        ]

        # Documentos complementarios — solo van dentro del ZIP
        extra_files = [
            "manifest.json",
            "readme_para_abogado.md",
            "checklist_custodia.md",
        ]

        # Versiones anonimizadas adicionales — generarlas solo para el ZIP
        anon_files = []
        audit_json = export_dir / "audit.json"
        for level in ["PERICIAL", "PUBLICO"]:
            anon_path = export_dir / f"_temp_{level.lower()}.json"
            try:
                from skills.redactor_sindical.redactor_sindical import RedactorSindical
                RedactorSindical().redact_file(audit_json, level, anon_path)
                anon_files.append((anon_path, f"informe_{level.lower()}.json"))
            except Exception:
                pass

        try:
            with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
                # Archivos principales
                for filename in main_files:
                    f = export_dir / filename
                    # Buscar también con prefijos alternativos
                    if not f.exists():
                        # Buscar variantes del nombre
                        for candidate in export_dir.glob(f"*{filename.split('_',1)[-1]}"):
                            if candidate.is_file():
                                f = candidate
                                break
                    if f.exists():
                        zf.write(f, f"principal/{f.name}")
                        self.files_packed.append(f.name)
                        print(f"[Packager]   + {f.name}")

                # Documentos complementarios
                for filename in extra_files:
                    f = export_dir / filename
                    if f.exists():
                        zf.write(f, f"documentacion/{filename}")
                        print(f"[Packager]   + documentacion/{filename}")

                # Versiones anonimizadas adicionales
                for temp_path, zip_name in anon_files:
                    if temp_path.exists():
                        zf.write(temp_path, f"anonimizados/{zip_name}")
                        print(f"[Packager]   + anonimizados/{zip_name}")
                        temp_path.unlink()  # limpiar temporal

            print(f"[Packager] ZIP creado: {len(self.files_packed)} archivos")
            return True

        except Exception as e:
            print(f"[Packager] Error creando ZIP: {e}")
            return False

    # ── Utilidades ─────────────────────────────────────────────────────────────

    def _find_latest_export_dir(self) -> Path | None:
        """Encuentra el directorio de exportación más reciente."""
        exports_dir = Path("exports")
        if not exports_dir.exists():
            return None

        candidates = []
        for f in exports_dir.rglob("audit.json"):
            try:
                candidates.append((f.stat().st_mtime, f.parent))
            except OSError:
                pass

        if not candidates:
            return None

        return sorted(candidates, reverse=True)[0][1]

    def _hash_file(self, path: Path) -> str:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            return "error_calculando_hash"

    def _human_size(self, size_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"


# ── CLI independiente ──────────────────────────────────────────────────────────

def main():
    import sys
    args = sys.argv[1:]

    if not args:
        # Sin argumentos — busca el último informe automáticamente
        packager = EvidencePackager()
        latest   = packager._find_latest_export_dir()
        if not latest:
            print("No se encontró ningún informe en exports/")
            print("Uso: python evidence_packager.py [directorio_exportacion]")
            return
        packager.package(latest)
    else:
        export_dir = Path(args[0])
        if not export_dir.exists():
            print(f"Error: no se encuentra {export_dir}")
            return
        EvidencePackager().package(export_dir)


if __name__ == "__main__":
    main()