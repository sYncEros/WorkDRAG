# WorkDRAG — Inventario de Categorías y Arquitectura de Auditoría

## 1. CATEGORÍAS DETECTABLES (64 categorías totales)

### Segmentos principales

- **MDM/Gestión corporativa** (4): mdm_software_install_policy, mdm_dlp_device_policy, mdm_usb_restrictions
- **Vigilancia/Monitorización** (6): ssl_inspection, edr_xdr, behavior_logging_capabilities
- **Red** (2): network_external, network_dns
- **Actividad/Procesos** (3): activity_resources, activity_new_services, activity_data_senders
- **Privacidad** (6): privacy_clipboard, privacy_microphone, privacy_location, privacy_input_hooks, privacy_screenshot, privacy_screen_recording
- **Telemetría/IA** (6): telemetry_windows_level, telemetry_services, telemetry_office, ai_connected_experiences, ai_copilot, ai_windows_recall
- **Cloud Sync** (3): cloud_sync_service, cloud_sync_folder_redirect, cloud_sync_policy
- **Navegador** (3): browser_forced_extensions, browser_inspection, browser_policies
- **Hardening** (6): hardening_missing, hardening_encryption, hardening_boot, hardening_network, hardening_antimalware, hardening_credentials
- **Persistencia** (5): persistence_registry, persistence_services, persistence_drivers, persistence_dll_hijacking, persistence_untrusted_certs
- **Identidad** (10): identity_local_accounts, identity_admin_group, identity_remote_access, identity_stored_credentials, identity_service_accounts, identity_privileged_monitoring, identity_account_profiles, identity_suspicious_account, identity_logon_rights, identity_multiple_sessions
- **USB** (4): usb_dlp_policies, usb_connected_now, usb_storage_history, usb_full_history
- **Email** (3): email_outlook_addins, email_outlook_profiles, email_forwarding_rules
- **Terceros** (3): third_party_apps_policies, third_party_apps_installed, vscode_extensions
- **Exfiltración** (3): exfiltration_dlp_monitoring, exfiltration_cloud_cli, exfiltration_large_files
- **Git** (2): gitconfig_recently_modified, ssh_config_present
- **Event Viewer** (2): event_viewer_collection_status, event_viewer_sensitive_events
- **Incident Response** (1): incident_response_evidence

## 2. REPRESENTACIÓN EN RESULTADOS

### Estructura de hallazgo (AuditFinding dataclass)

```bash
- skill: str (nombre del módulo)
- category: str (categoría anterior)
- title: str (título descriptivo)
- description: str (explicación del hallazgo)
- risk_level: str (green/yellow/orange/red)
- technical_risk: str (descripción técnica)
- legal_risk: str (evaluación legal)
- what_it_is: str (clarificación)
- what_it_is_not: str (falsas positivas)
- raw_data: dict (datos técnicos específicos)
- timestamp: str (ISO 8601)
```

### Niveles de riesgo legal (en legal_engine.py)

- LOW, MEDIUM, MEDIUM-HIGH, HIGH, VERY_HIGH
- Mapeos RGPD/LOPDGDD/ET/CP por categoría

### Riesgos de color (interfaz)

- green: Seguridad corporativa estándar
- yellow: Telemetría relevante
- orange: Vigilancia potencialmente intrusiva
- red: Capacidad altamente invasiva

## 3. BASE LEGAL POR CATEGORÍA

**SECCIÓN compliance_engine/legal_engine.py** contiene:

- 64 reglas COMPLIANCE_RULES con mapeo category → legal_risk → referencias legislativas
- LEGAL_FRAMEWORK con 11 referencias (RGPD art. 5/13/22/32/35, LOPDGDD art. 87/88, ET art. 20bis, TEDH Barbulescu, CP art. 197, AEPD guía laboral)

**Asociaciones documentadas:**

- Cada categoría tiene `legal_risk` asignado (low→very_high)
- Cada regla tiene `references[]` a artículos legales específicos
- Cobertura: RGPD completo, LOPDGDD (laborales), ET (derechos digitales), CP (secretos), TEDH (jurisprudencia)

## 4. TESTS EXISTENTES

### test_audit_engine.py

- `TestAuditFinding`: timestamp, risk_levels, raw_data validation
- `TestAuditEngine`: init, add_finding, compute_max_risk, export_json, validate_schema
- `TestLegalEngine`: (parcial en archivo)
- Total: ~15 tests unitarios

### test_api.py (Flask endpoints)

- Status endpoint, reports, skills list, recommendation_modes
- Report not found (404), comparison, run audit, validation
- Total: ~12 tests de integración

**FALTAS OBSERVADAS:**

- NO hay tests por skill individual (mdm_audit, surveillance, persistence, etc.)
- NO hay tests de validación de raw_data por categoría
- NO hay tests de exportación PDF (solo JSON probado)
- NO hay tests de comparación entre auditorías

## 5. FORMATOS DE SALIDA ESPERADOS

### JSON

- Ubicación: exports/audit_{YYYY-MM-DD}.json (por defecto)
- Estructura:
  - generated_at (ISO)
  - total_findings (int)
  - max_risk (string: green/yellow/orange/red)
  - findings[] (lista de AuditFinding as dict)
  - integrity_hash (SHA256 del contenido)
- Validación: AuditEngine.validate_schema() comprueba campos obligatorios

### PDF

- Ubicación: exports/audit_{YYYY-MM-DD}.pdf
- Generador: core/pdf_exporter.py (reportlab)
- Estructura:
  - Portada con resumen ejecutivo (hallazgos, riesgo máximo)
  - Tabla de hallazgos por skill/categoría/riesgo
  - Detalles de cada hallazgo con descripción técnica y legal
  - Hash de integridad del JSON asociado
  - Referencias legislativas
  - Recomendaciones automáticas (si aplica)

### Markdown

- NO ENCONTRADO en codebase actual
- TODO.md menciona "addon_audit" como pendiente (cobertura de extensiones/add-ins)
- recomendaciones_vulneraciones.md existe pero es salida manual, NO automática

## 6. AMBIGÜEDADES Y FALTAS DE COBERTURA

### Ambigüedades detectadas

1. **raw_data structure**: No hay esquema definido para raw_data por categoría
   - Cada skill genera raw_data diferente sin validación de campos

2. **Legal risk levels vs technical risk**:
   - legal_engine.py usa strings: "low", "medium", "medium-high", "high", "very_high"
   - AuditFinding.legal_risk es string libre sin enum
   - Inconsistencia posible: ¿qué valores son válidos?

3. **Recommendation modes**:
   - test_api.py menciona "urgente", "completo", "personalizado"
   - NO implementado en audit_engine.py (solo en UI/server.py)
   - Filtros por category y risk level presentes en API pero sin base en engine

4. **Email forwarding rules**: Categoría "email_forwarding_rules" en legal_engine pero NO hay scanner que la detecte

5. **SSH config present**: Categoría "ssh_config_present" en legal_engine pero NO hay implementación en git_identity_audit

6. **comparison API**: GET /api/compare existe en tests pero NO hay implementación visible en server.py

### Faltas de cobertura observadas

1. **addon_audit**: PENDIENTE (mencionado en TODO.md)
   - Add-ins forzados de Office 365, navegadores, Teams, JetBrains, VSCode
   - Impacto: alto (acceso a datos corporativos y personales)
   - Status: TODO

2. **clipboard_watcher**: PENDIENTE (mencionado en TODO.md)
   - Apps que acceden al portapapeles
   - Status: TODO

3. **windows_event_forwarding detail**:
   - Categoría presente (behavior_logging_capabilities)
   - PERO: event_viewer_audit puede no capturar CONFIG ACTUAL de WEF/PS Transcription

4. **PowerShell Transcription config**:
   - event_viewer_audit busca LOGS
   - ¿Busca también los settings que HABILITAN transcripción? (HKLM\SOFTWARE\Policies\Microsoft\PowerShell\ScriptBlockLogging)

5. **DiagTrack detail**:
   - Detecta servicio pero NO valida:
     - Si está realmente enviando datos
     - Destinos exactos (Microsoft EU vs US)
     - Contenido de payload

6. **DPA validation**:
   - cloud_sync_audit menciona "verificar si existe DPA con Microsoft"
   - NO hay implementación que lo valide

7. **Custom recommendations**:
   - Modo "personalizado" (test_api.py) acepta filtros
   - PERO: ¿dónde se generan las recomendaciones automáticas?
   - recomendaciones_vulneraciones.md es ESTÁTICA, no por auditoria

8. **Markdown export**:
   - NO existe exportador a MD automático
   - TODO.md es manual
   - generate_recommendations_md.py existe pero desconocido contenido

## 7. ESTRUCTURA DE SKILLS (20 módulos)

Ejecutados en core/audit_engine.run_all_skills():

1. mdm - MDM scanning
2. surveillance - Proxy/DLP/EDR/XDR/remote access
3. persistence - Registry/services/drivers/DLL hijacking/certs
4. network - Network connections
5. activity - Process monitoring
6. privacy - Clipboard/microphone/location/input hooks/screenshot/screen recording
7. ai_telemetry - Telemetría Windows, Office, IA
8. cloud_sync - OneDrive/SharePoint/KFM
9. browser - Extensions/policies
10. hardening - Encryption/Secure Boot/Firewall/Antimalware/Credentials
11. identity - Local accounts/admin/RDP/credentials/services
12. git_identity - Git config integrity
13. scheduled_tasks - Tareas programadas
14. usb - USB history and policies
15. email - Outlook add-ins/profiles/forwarding
16. third_party_apps - Teams/Zoom/VSCode policies
17. user_behavior - User behavior and logins
18. data_exfiltration - Large files/CLI tools
19. incident_response - Incident playbooks
20. event_viewer - Event logs and security events

## 8. RECOMENDACIONES PARA AMPLIAR AUTOMATIZACIÓN

1. **Crear tests por skill**:
   - Cada skill debería tener test_*.py en skills/*/tests/
   - Validar estructura de raw_data generada

2. **Normalizar legal_risk enum**:
   - Usar enum.Enum en lugar de strings
   - Validar en AuditFinding.**post_init**()

3. **Implementar addon_audit**:
   - Escanear políticas de extensiones en navegadores
   - Escanear add-ins forzados en Outlook/Office
   - Escanear extensiones en VSCode/JetBrains

4. **Exportador Markdown automático**:
   - Generar recomendaciones_vulneraciones.md dinámico
   - Basado en findings + legal_engine rules
   - Sustituir TODO.md manual

5. **Validación de raw_data**:
   - Definir schema por categoría
   - Validar en add_finding()

6. **Completion checks**:
   - Verificar que email_forwarding_rules se implementa
   - Verificar que ssh_config_present se implementa
