# Documentación unificada de carpetas

Este documento concentra la descripción de todas las carpetas relevantes del proyecto para evitar dispersión de información.

## `worker-rights-agent/` (raíz)

### Propósito de la raíz

Contiene el punto de entrada, documentación principal y carpetas funcionales del proyecto.

### Contenido principal de la raíz

- `main.py`: ejecución de auditoría completa.
- `README.md`: guía de uso general.
- `CONTRIBUTING.md`: normas de colaboración.
- `requirements.txt`: dependencias Python.
- `core/`: motor y exportación.
- `skills/`: módulos de detección.
- `evidence/`: base de datos local.
- `exports/`: artefactos de salida.
- `ui/`: interfaz web.
- `.docs/`: documentación técnica.

## `core/`

### Propósito de core

Aloja la orquestación central de auditoría y las salidas de informe.

### Módulos de core

- `audit_engine.py`
  - Define `AuditFinding`.
  - Orquesta skills.
  - Persiste hallazgos en SQLite.
  - Exporta JSON con hash de integridad.
- `pdf_exporter.py`
  - Convierte hallazgos y evaluación legal en PDF forense.

### Nota

La lógica de `core/` debe mantenerse desacoplada de la UI.

## `skills/`

### Propósito de skills

Agrupa módulos de análisis técnico y evaluación legal.

### Subcarpetas de skills

- `mdm_audit/`: gestión corporativa y control MDM.
- `surveillance_audit/`: capacidades de vigilancia/monitorización.
- `persistence_audit/`: mecanismos de persistencia.
- `compliance_engine/`: lectura legal de hallazgos.
- `activity_monitor/`: reservado para evolución futura.

### Flujo de skills

Cada skill ejecuta comprobaciones y reporta hallazgos al `AuditEngine`.

## `skills/compliance_engine/`

### Propósito de compliance_engine

Contener el motor de evaluación legal a partir de hallazgos técnicos.

### Módulo de compliance_engine

- `legal_engine.py`: aplica reglas y referencias normativas.

### Salida esperada de compliance_engine

- Lista priorizada de conflictos legales.
- Recomendaciones prácticas por hallazgo.

## `skills/mdm_audit/`

### Propósito de mdm_audit

Detectar grado de gestión corporativa del dispositivo.

### Indicadores de mdm_audit

- Inscripción MDM
- Intune Management Extension
- Azure AD Join
- Políticas de AppLocker
- Bloqueo de desinscripción manual
- Certificados raíz corporativos

## `skills/persistence_audit/`

### Propósito de persistence_audit

Detectar infraestructura persistente potencialmente relacionada con monitorización.

### Áreas cubiertas de persistence_audit

- Autorun (`Run` / `RunOnce`)
- Servicios
- Tareas programadas
- WMI subscriptions
- Drivers de kernel

## `skills/surveillance_audit/`

### Propósito de surveillance_audit

Detectar software de vigilancia, inspección de red y control remoto.

### Categorías evaluadas en surveillance_audit

- EDR/XDR
- DLP
- Inspección de red/SSL
- Monitorización de productividad
- Soporte remoto
- Inspección de navegador

## `skills/activity_monitor/`

### Estado actual de activity_monitor

Carpeta reservada para evolución futura.

### Objetivo previsto de activity_monitor

Incorporar monitorización temporal (timeline) de cambios relevantes.

## `ui/`

### Propósito de ui

Alojar la interfaz web de visualización de resultados.

### Estado de ui

Base funcional con `server.py`, `index.html`, y recursos estáticos.

### Subcarpetas de ui

- `ui/components/`: componentes reutilizables de interfaz.
- `ui/dashboard/`: vista consolidada de auditoría.

## `evidence/`

### Propósito de evidence

Persistir evidencia estructurada de auditorías locales.

### Archivo principal de evidence

- `audit.db` (SQLite)

### Tablas relevantes de evidence

- `findings`
- `audit_sessions`

## `exports/`

### Propósito de exports

Guardar artefactos generados tras cada auditoría.

### Formatos actuales de exports

- `audit_YYYY-MM-DD.json`
- `audit_YYYY-MM-DD.pdf`

## `.docs/`

### Propósito de .docs

Centralizar documentación funcional y técnica del proyecto.

### Contenido de .docs

- `Worker Digital Rights Audit Agent.md`: visión amplia del proyecto.
- `README.md`: índice de documentación.
- `folders/FOLDERS.md`: documentación unificada de carpetas.
- `modules/MODULES.md`: documentación unificada de módulos.
