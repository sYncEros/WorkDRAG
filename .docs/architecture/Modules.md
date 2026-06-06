# Documentación unificada de módulos

Este documento concentra la descripción funcional de los módulos principales para evitar fragmentación.

## `main.py`

- **Responsabilidad:** punto de entrada del programa.
- **Flujo principal:** muestra aviso, ejecuta auditoría técnica, ejecuta evaluación legal y exporta JSON/PDF.
- **Salida típica:** tabla de hallazgos, resumen legal y rutas de exportación.

## `core/audit_engine.py`

- **Responsabilidad:** orquestar skills, persistir resultados y exportar JSON firmado.
- **Entidades clave:** `AuditFinding`, `AuditEngine`.
- **Métodos clave:** `_init_db()`, `add_finding()`, `run_all_skills()`, `export_json()`, `summary()`.
- **Salida típica:** `Total hallazgos: N | Riesgo máximo: ...`.

## `core/pdf_exporter.py`

- **Responsabilidad:** generar informe PDF forense desde hallazgos y evaluación legal.
- **Secciones:** portada, resumen, detalle, evaluación legal e integridad.
- **Función principal:** `export_pdf(findings, legal_issues, out_path) -> Path`.

## `skills/compliance_engine/legal_engine.py`

- **Responsabilidad:** convertir hallazgos técnicos en riesgos legales.
- **Bloques clave:** `LEGAL_FRAMEWORK`, `COMPLIANCE_RULES`, `LegalEngine`.
- **Métodos clave:** `evaluate()`, `summary_text()`, `to_dict()`.
- **Ejemplo de issue:** monitorización continua de productividad (`high`).

## `skills/mdm_audit/mdm_scanner.py`

- **Responsabilidad:** evaluar control corporativo del dispositivo.
- **Señales:** inscripción MDM, Intune, AppLocker, restricción de desinscripción, certificados corporativos, Azure AD Join.
- **Método principal:** `run()`.
- **Salida típica:** hallazgo `MDM / Gestión corporativa del dispositivo`.

## `skills/persistence_audit/persistence_scanner.py`

- **Responsabilidad:** detectar persistencia relevante para monitorización.
- **Áreas:** autorun, servicios, tareas, WMI, controladores.
- **Método principal:** `run()`.
- **Ejemplo de hallazgo:** persistencia WMI con riesgo `orange`.

## `skills/surveillance_audit/surveillance_scanner.py`

- **Responsabilidad:** detectar capacidades de vigilancia por catálogo y políticas del sistema.
- **Categorías:** `edr_xdr`, `dlp`, `network_inspection`, `productivity_monitoring`, `remote_support`, `ssl_inspection`, `browser_inspection`, `input_monitoring`.
- **Método principal:** `run()`.
- **Salida típica:** detección de producto con nivel de riesgo.

## `skills/identity_audit/identity_scanner.py`

- **Responsabilidad:** auditar identidad y acceso en el endpoint (cuentas, grupos privilegiados, sesiones y credenciales almacenadas).
- **Método principal:** `run()`.
- **Estado actual:** cobertura ampliada de cuentas locales, grupo de administradores, sesiones remotas, credenciales y procesos privilegiados.

### Mejoras implementadas

#### 1) Enriquecimiento por cuenta (implementado)

Para cada cuenta:

- Nombre y tipo de identidad (local / dominio / AAD).
- Fecha de creación (cuando esté disponible por fuente del sistema).
- Último inicio de sesión y origen del inicio (local/remoto cuando sea trazable).
- Grupos a los que pertenece.
- Procesos abiertos actualmente bajo esa identidad.
- Servicios que se ejecutan bajo esa cuenta.

#### 2) Enriquecimiento por sesión activa (implementado)

Para cada sesión activa:

- Usuario y tipo de sesión (local / RDP / servicio).
- IP de origen si la sesión es remota.
- Tiempo de actividad (duración/uptime de la sesión).
- Procesos ejecutándose dentro de la sesión.

#### 3) Foco en administradores (implementado)

Para cuentas con privilegios administrativos:

- Trazar altas al grupo de admins (event log 4732) con cuenta que añadió y timestamp.
- Diferenciar administradores locales vs dominio.
- Verificar inicios de sesión recientes de cuentas privilegiadas.

#### 4) Con privilegios administrativos (implementado, modo forense controlado)

Con ejecución en contexto admin y dentro de política defensiva:

- Auditoría de credenciales **sin exfiltrar secretos en claro** (metadatos y superficies de riesgo).
- Correlación de sesiones remotas activas (metadatos de sesión y proceso, sin captura de contenido).
- Trazabilidad de acciones por cuenta en logs de seguridad/sistema.

> Nota de alcance: la implementación mantiene enfoque de auditoría defensiva y cumplimiento. Se aplica minimización de datos, proporcionalidad y marco legal aplicable (RGPD/LOPDGDD/ET art. 20 bis).
