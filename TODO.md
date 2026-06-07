# TODO

## Punto 1 — poner el TODO al día

### 🟡 En progreso real

- **Comparación visual** existe en versión básica; aún puede mejorarse el diff por campos y la UX.
- **Tests** existen, pero falta ampliar cobertura de integración y casos reales de exportación/skills.

### 🎯 Prioridad sugerida para seguir punto a punto

1. **Limpiar duplicados y estados del TODO** para que lo pendiente sea fiable.
2. **Completar `addon_audit`** porque desbloquea varios hallazgos de navegador, Office, VSCode, Teams y EDR.
3. **Completar `onedrive_mapper`** porque cubre varios hallazgos de alto riesgo y es muy tangible para usuario final.
4. **Completar correlación temporal avanzada en `event_logs`** (WEF/PowerShell/USB por ventana e identidad) para reforzar trazabilidad forense.
5. **Mejorar `account_profiler`** porque afecta a varias categorías de identidad sin crear skill nueva desde cero.

## Mejoras

- **Email Client Audit** — Queda como mejora concreta la detección explícita de delegaciones de buzón (SendAs / FullAccess / SendOnBehalf).

- **Third Party Apps Audit** — ampliar el mapeo de permisos por app/extensión/add-in y añadir tests por perfiles simulados.

- **User Behavior Analysis** — ampliar pruebas funcionales con datos simulados (eventos de horario/anomalía y objetos sensibles) para robustecer evidencia reproducible.

- **Data Exfiltration Detection** — monitoreo de tráfico saliente, uso de herramientas de transferencia de archivos, análisis de logs de red

- **Persistence Mechanisms** — análisis de mecanismos de persistencia comunes: Run keys, servicios, WMI, tareas programadas, DLL hijacking

- **Incident Response Playbook** — desarrollo de un playbook específico para incidentes de insider

### Mejora de skills existentes

- **MDM / gestión corporativa** — añadir detección de políticas de restricción de USB, DLP de dispositivos, bloqueo de instalación de software

- **Superficie de monitorización** — ampliar detección a herramientas de análisis de comportamiento, monitoreo de red, extensiones de navegador con acceso a contenido

- **Persistencia e infraestructura oculta** — añadir análisis de DLL hijacking, drivers sospechosos, certificados raíz no confiables, WMI persistente

- **Evaluación legal** — incorporar referencias a doctrina Barbulescu, guía de relaciones laborales de la AEPD, y casos legales relevantes

---

## Skills nuevos a desarrollar para automatizar recomendaciones

| Skill   | Qué automatiza  | Estado actual  |
| ------- | --------------- | -------------- |
| `addon_audit` | Listado de add-ins de Office, Teams, VSCode, navegadores | Pendiente |
| `onedrive_mapper` | Documenta carpetas redirigidas y crea carpetas locales seguras | Pendiente |
| `diagtrack_inspector` | Estado de DiagTrack, qué envía, con qué frecuencia | Pendiente |
| `event_log_monitor` | Windows Event Forwarding y PowerShell Transcription activos | En Desarrollo |
| `clipboard_watcher` | Qué apps acceden al portapapeles y con qué frecuencia | Pendiente |
| `dpa_checker` | Verifica nivel de telemetría real vs DPA declarado con Microsoft | Pendiente |
| `service_hardener` | Intenta deshabilitar DiagTrack, WEF, PS Transcription | Pendiente |
| `rdp_log_exporter` | Exporta logs de accesos RDP con timestamps y usuarios | En Desarrollo |

---

## 1. Telemetría completa de Windows activa

- Categoría: `telemetry_windows_level` — Riesgo: **HIGH**

### ✅ Automatizado

- Detecta nivel de telemetría via registro
- Reporta si hay política GPO restrictiva o no

### 🔧 Pendiente — skill `diagtrack_inspector`

- Consultar qué datos concretos envía DiagTrack (endpoints destino)
- Medir frecuencia de envío via logs de eventos
- Exportar lista de endpoints de telemetría activos
- Comparar nivel configurado vs nivel real transmitido

### 🔧 Pendiente — skill `dpa_checker`

- Verificar si existe DPA con Microsoft en el registro/políticas
- Comparar nivel de telemetría con lo declarado en el DPA
- Generar evidencia de discrepancia si existe

### 📋 Recomendación manual

- Solicitar al DPO base legal de la transferencia internacional
- Exigir registro de actividades que incluya esta telemetría

---

## 2. Servicio DiagTrack — telemetría continua activa

- Categoría: `telemetry_services` — Riesgo: **HIGH**

✅ Automatizado

- Detecta si DiagTrack está en estado Running
- Detecta otros servicios de telemetría activos

🔧 Pendiente — skill `service_hardener`

- Intentar deshabilitar DiagTrack si no hay política que lo impida
- Si falla (bloqueado por GPO), documentar el bloqueo como evidencia
- Registrar intento + resultado en el informe forense

🔧 Pendiente — skill `diagtrack_inspector`

- Extraer logs de DiagTrack de Event Viewer (canal ETW)
- Documentar últimas transmisiones: timestamp, destino, volumen
- Exportar como evidencia con hash SHA-256

📋 Recomendación manual

- Solicitar a IT deshabilitación via GPO
- Si se niegan, documentar la negativa por escrito

---

## 3. Carpetas del sistema redirigidas a nube corporativa

- Categoría: `cloud_sync_folder_redirect` — Riesgo: **HIGH**

✅ Automatizado

- Detecta carpetas Shell redirigidas a OneDrive/SharePoint
- Cuenta y lista las 7 carpetas afectadas

🔧 Pendiente — skill `onedrive_mapper`

- Listar contenido de cada carpeta redirigida (solo metadatos: nombres, fechas, tamaños)
- Crear automáticamente `C:\TrabajoLocal\` fuera de OneDrive
- Generar script de migración segura para el usuario
- Documentar qué hay en nube que no debería estar

📋 Recomendación manual

- Mover documentos personales fuera de carpetas redirigidas
- No guardar nada en Escritorio, Documentos o Imágenes hasta resolver

---

## 4. Cifrado de disco no activo — datos en claro

- Categoría: `hardening_encryption` — Riesgo: **HIGH**

✅ Automatizado

- Detecta ausencia de BitLocker via PowerShell
- Lo reporta como hallazgo crítico con referencia RGPD art. 32

🔧 Pendiente — skill `service_hardener`

- Verificar si TPM está disponible para activar BitLocker
- Intentar activar BitLocker si hay permisos
- Si no hay permisos, generar solicitud formal documentada a IT
- Registrar el intento y resultado como evidencia

📋 Recomendación manual

- Solicitar a IT activación inmediata
- Si hay datos sensibles en el disco, avisar al DPO como brecha latente

---

## 5. Acceso remoto habilitado (RDP)

- Categoría: `identity_remote_access` — Riesgo: **HIGH**

✅ Automatizado

- Detecta si RDP está habilitado
- Detecta conexiones RDP activas en el momento de la auditoría

🔧 Pendiente — skill `rdp_log_exporter`

- Extraer log completo de accesos RDP históricos (Event ID 4624, 4778, 4779)
- Para cada acceso: usuario, IP origen, timestamp, duración
- Detectar accesos fuera de horario laboral
- Exportar como evidencia con hash SHA-256
- Alertar si hay IPs externas que hayan accedido

📋 Recomendación manual

- Solicitar política de acceso remoto documentada
- Exigir notificación previa antes de cualquier acceso futuro

---

## 6. Acceso al portapapeles del trabajador

- Categoría: `privacy_clipboard` — Riesgo: **MEDIUM-HIGH**

✅ Automatizado

- Detecta apps con acceso al portapapeles via registro y procesos

🔧 Pendiente — skill `clipboard_watcher`

- Monitorizar en tiempo real qué procesos leen el portapapeles
- Registrar: proceso, PID, timestamp, frecuencia de acceso
- Ejecutar durante 5 minutos y generar informe de actividad
- Detectar si algún proceso envía datos de portapapeles a red

📋 Recomendación manual

- No copiar contraseñas, tokens ni datos bancarios en el equipo corporativo
- Solicitar al DPO qué app accede y con qué finalidad

---

## 7. Configuraciones de seguridad ausentes

- Categoría: `hardening_missing` — Riesgo: **MEDIUM-HIGH**

✅ Automatizado

- Verifica 14 configuraciones de seguridad
- Detecta 8 ausentes con nivel de importancia
- Genera hallazgos individuales para críticos y altos

🔧 Pendiente — skill `service_hardener`

- Para cada configuración ausente, intentar activarla automáticamente
- Registrar éxito o fracaso con el motivo (sin permisos, bloqueado por GPO)
- Si bloqueado por GPO, documentar que la empresa impide la protección

📋 Recomendación manual

- Solicitar plan de hardening al empleador
- Presentar lista de ausencias al DPO como incumplimiento RGPD art. 32

---

## 8. Credenciales almacenadas en Credential Manager

- Categoría: `identity_stored_credentials` — Riesgo: **MEDIUM-HIGH**

✅ Automatizado

- Cuenta y lista credenciales almacenadas (42 detectadas)
- Identifica credenciales corporativas de acceso remoto

🔧 Pendiente — skill `addon_audit`

- Clasificar cada credencial: corporativa vs personal vs desconocida
- Detectar credenciales de servicios externos no corporativos
- Alertar si hay credenciales personales (banco, email privado) almacenadas

📋 Recomendación manual

- Ejecutar `cmdkey /list` y eliminar credenciales personales
- Usar gestor de contraseñas personal independiente (Bitwarden)

---

## 9. Cuenta específica con características de riesgo

- Categoría: `identity_suspicious_account` — Riesgo: **MEDIUM-HIGH**

✅ Automatizado

- Perfila cuentas: DevToolsUser, EMEAL-IT, Local-Admin
- Muestra grupos, último acceso, servicios que ejecuta, alertas

🔧 Pendiente — `account_profiler` (mejorar existente)

- Añadir historial de accesos de los últimos 30 días por cuenta
- Detectar si alguna cuenta accedió fuera de horario laboral
- Cruzar con logs RDP para ver si alguna entró remotamente
- Generar ficha individual exportable por cuenta sospechosa

📋 Recomendación manual

- Solicitar justificación escrita de Local-Admin y DevToolsUser
- Consultar asesor laboral si no hay respuesta en 15 días

---

## 10. Experiencias conectadas de Office enviando contenido a Microsoft

- Categoría: `ai_connected_experiences` — Riesgo: **MEDIUM-HIGH**

✅ Automatizado

- Detecta si experiencias conectadas están activas sin política restrictiva
- Detecta nivel de telemetría de Office

🔧 Pendiente — skill `addon_audit`

- Listar qué experiencias conectadas específicas están activas
- Detectar si Editor IA, PowerPoint Designer, Traducción automática están enviando datos
- Intentar desactivar experiencias no esenciales via registro si hay permisos

🔧 Pendiente — skill `dpa_checker`

- Verificar si el DPA empresa-Microsoft cubre el procesamiento de IA
- Comprobar si existe DPIA para experiencias conectadas

📋 Recomendación manual

- Solicitar DPA actualizado al DPO
- Desactivar manualmente: Archivo > Opciones > Centro de confianza > Experiencias conectadas

---

## 11. Extensiones forzadas con acceso completo al navegador

- Categoría: `browser_forced_extensions` — Riesgo: **MEDIUM-HIGH**

✅ Automatizado

- Detecta extensiones forzadas por GPO en Chrome, Edge, Firefox
- Identifica extensiones conocidas de vigilancia en catálogo

🔧 Pendiente — skill `addon_audit`

- Para cada extensión forzada: nombre, editor, versión, permisos completos
- Detectar si la extensión tiene acceso a `webRequest` (puede interceptar tráfico)
- Verificar si la extensión envía datos a servidores externos
- Comparar con base de datos de extensiones de monitorización conocidas

📋 Recomendación manual

- Abrir `chrome://extensions` > Detalles de cada extensión forzada > anotar permisos
- Solicitar al DPO función y datos que recopila cada extensión

---

## 12. Inspección de tráfico HTTPS (certificado SSL corporativo)

- Categoría: `ssl_inspection` — Riesgo: **MEDIUM-HIGH**

✅ Automatizado

- Detecta certificados raíz corporativos que permiten inspección SSL
- Identifica certificados de vendors conocidos (Netskope, Zscaler, etc.)

🔧 Pendiente — skill `dpa_checker`

- Verificar si hay proxy activo en la red actual
- Detectar si el tráfico HTTPS está siendo descifrado (test de certificado)
- Documentar qué certificados raíz corporativos están instalados con thumbprint

📋 Recomendación manual

- Solicitar política AUP por escrito
- Usar datos móviles personales para cualquier comunicación privada

---

## 13. Políticas GPO de OneDrive forzando sincronización (KFM)

- Categoría: `cloud_sync_policy` — Riesgo: **MEDIUM-HIGH**

✅ Automatizado

- Detecta KFMSilentOptIn y KFMBlockOptOut via registro
- Confirma que el trabajador no puede desactivar la sincronización

🔧 Pendiente — skill `onedrive_mapper`

- Documentar exactamente qué carpetas están en KFM
- Calcular volumen total de datos sincronizados a Microsoft
- Detectar si hay archivos personales ya en OneDrive corporativo
- Generar evidencia de que la desactivación está bloqueada por GPO

📋 Recomendación manual

- Solicitar al empleador información sobre políticas GPO
- Documentar la imposibilidad de desactivar como evidencia

---

## 14. Políticas corporativas en navegadores (Chrome, Edge, Firefox)

- Categoría: `browser_policies` — Riesgo: **MEDIUM**

✅ Automatizado

- Detecta políticas activas en los 3 navegadores
- Identifica CloudReportingEnabled y bloqueo de modo incógnito

🔧 Pendiente — skill `addon_audit`

- Extraer listado completo de todas las políticas activas con su valor
- Identificar cuáles afectan a privacidad vs cuáles son de seguridad
- Detectar si hay URLBlocklist que impida acceso a sindicatos o recursos laborales
- Exportar como evidencia el volcado completo de `chrome://policy`

📋 Recomendación manual

- Verificar `chrome://policy` manualmente y hacer captura
- No usar navegador corporativo para comunicaciones con sindicato o asesor

---

## 15. Extensiones de navegador forzadas (duplicado con #11)

- Categoría: `browser_inspection` — Riesgo: **MEDIUM**

✅ Automatizado

- Ya cubierto por hallazgo #11

🔧 Pendiente

- Consolidar en el mismo hallazgo para evitar duplicidad en el informe

---

## 16. Políticas corporativas sobre apps de terceros (Teams, Zoom, VSCode)

- Categoría: `third_party_apps_policies` — Riesgo: **MEDIUM-HIGH**

✅ Automatizado

- El skill `third_party_apps_audit` detecta apps con telemetría

🔧 Pendiente — skill `addon_audit`

- Para Teams: detectar si Compliance Recording está activo
- Para VSCode: listar extensiones instaladas y detectar time trackers
- Para Zoom: detectar si hay grabación automática o transcripción activa
- Para JetBrains: detectar si hay plugins de monitorización de actividad
- Documentar configuración de privacidad de cada app

📋 Recomendación manual

- Solicitar al DPO listado de políticas activas sobre cada app
- Verificar en Teams > Configuración si hay grabación o transcripción automática

---

## 17. Software DLP corporativo monitorizando transferencias

- Categoría: `exfiltration_dlp_monitoring` — Riesgo: **MEDIUM-HIGH**

✅ Automatizado

- El skill `surveillance_audit` detecta presencia de DLP (Purview, Forcepoint, etc.)

🔧 Pendiente — skill `addon_audit`

- Detectar qué tipos de datos inspecciona el DLP (emails, archivos, USB)
- Verificar si el DLP tiene acceso a contenido de documentos personales
- Detectar si hay reglas DLP que registren intentos de envío de datos

📋 Recomendación manual

- Solicitar al DPO política DLP y qué datos inspecciona
- No transferir datos personales mediante canales corporativos

---

## 18. Agentes de monitorización con privilegios de SISTEMA

- Categoría: `identity_privileged_monitoring` — Riesgo: **MEDIUM**

✅ Automatizado

- Detecta CrowdStrike, MSSense y similares corriendo como SYSTEM
- Confirma nivel de privilegio

🔧 Pendiente — `account_profiler` (mejorar)

- Para cada agente SYSTEM: listar endpoints de red a los que se conecta
- Detectar si envía datos fuera del horario laboral
- Cruzar con el catálogo de surveillance para evaluar capacidades reales

📋 Recomendación manual

- Solicitar al DPO qué datos recopila CrowdStrike y quién tiene acceso
- Pedir política de uso de datos del EDR por escrito

---

## 19. Cuentas con alertas de seguridad sin documentar

- Categoría: `identity_account_profiles` — Riesgo: **MEDIUM**

✅ Automatizado

- Perfila 5 cuentas con alertas, 3 de alto riesgo
- Genera hallazgo resumen y hallazgos individuales

🔧 Pendiente — `account_profiler` (mejorar)

- Monitorización temporal: detectar si alguna cuenta nueva aparece entre auditorías
- Alertar si una cuenta deshabilitada se habilita entre dos auditorías

📋 Recomendación manual

- Solicitar inventario oficial de cuentas con justificación

---

## 20. Cuentas locales no documentadas

- Categoría: `identity_local_accounts` — Riesgo: **MEDIUM**

✅ Automatizado

- Detecta 8 cuentas locales, 2 sospechosas
- Analiza flags: contraseña permanente, nunca usada, nombre sospechoso

### 🔧 Pendiente — `account_profiler` (mejorar)

- Detectar cuándo fue creada cada cuenta (registro de creación)
- Comparar con fecha de incorporación del trabajador
- Alertar si hay cuentas creadas después del inicio de una disputa laboral

📋 Recomendación manual

- Solicitar inventario y justificación de cada cuenta local

---

## 21. Extensiones de VSCode con telemetría de actividad

- Categoría: `vscode_extensions` — Riesgo: **MEDIUM**

✅ Automatizado

- El skill `third_party_apps_audit` detecta VSCode

🔧 Pendiente — skill `addon_audit`

- Listar todas las extensiones de VSCode instaladas
- Clasificar: productividad, time tracking, corporativas, personales
- Detectar extensiones conocidas de monitorización (WakaTime, CodeTime, etc.)
- Verificar si hay extensiones forzadas via `settings.json` corporativo

📋 Recomendación manual

- Abrir VSCode > Extensiones > revisar cuáles no reconoces
- Desinstalar time trackers si no son necesarios para el trabajo

---

## 22. Herramientas CLI de nube con credenciales

- Categoría: `exfiltration_cloud_cli` — Riesgo: **MEDIUM**

✅ Automatizado

- El skill `data_exfiltration_audit` detecta rclone, AWS CLI, etc.

🔧 Pendiente — skill `addon_audit`

- Verificar si las credenciales configuradas son personales o corporativas
- Detectar si hay tokens de acceso personal (PAT) almacenados
- Alertar si hay herramientas de transferencia masiva no autorizadas

📋 Recomendación manual

- Verificar que todas las credenciales configuradas son corporativas
- Consultar con IT si el uso está autorizado

---

## 23. Múltiples administradores con acceso completo

- Categoría: `identity_admin_group` — Riesgo: **MEDIUM**

✅ Automatizado

- Detecta 4 administradores locales
- Lista miembros del grupo con tipo y origen

🔧 Pendiente — skill `rdp_log_exporter`

- Para cada admin: ¿ha accedido remotamente alguna vez?
- Exportar historial de accesos por cuenta de admin
- Detectar accesos de admins fuera de horario laboral

📋 Recomendación manual

- Solicitar justificación de cada cuenta admin
- Exigir registro de auditoría de accesos administrativos

---

## 24. Políticas USB corporativas

- Categoría: `usb_dlp_policies` — Riesgo: **MEDIUM**

✅ Automatizado

- El skill `usb_audit` detecta políticas de control USB

🔧 Pendiente — skill `event_log_monitor`

- Extraer log de intentos de conexión USB (Event ID 2003, 2100)
- Para cada intento: dispositivo, timestamp, usuario, resultado
- Detectar si RRHH tiene acceso a estos logs
- Exportar como evidencia

📋 Recomendación manual

- Solicitar política USB y período de retención de logs
- Consultar si los intentos de conexión se reportan a RRHH

---

## 25. OneDrive Empresarial y SharePoint activos

- Categoría: `cloud_sync_service` — Riesgo: **MEDIUM**

✅ Automatizado

- Detecta OneDrive y SharePoint activos
- Detecta KFM forzado por GPO

🔧 Pendiente — skill `onedrive_mapper`

- Calcular volumen total de datos sincronizados
- Detectar si hay archivos personales en la nube corporativa
- Generar lista de archivos en OneDrive con metadatos (no contenido)
- Verificar a qué tenant/región van los datos

📋 Recomendación manual

- Solicitar DPA con Microsoft actualizado
- Verificar región de almacenamiento (UE vs EEUU)

---

## 26. Políticas corporativas de navegador (CloudReporting)

- Categoría: `browser_policies` — Riesgo: **MEDIUM**

✅ Automatizado

- Ya cubierto en hallazgo #14 — consolidar

🔧 Pendiente

- Unificar hallazgos de políticas de navegador para evitar duplicidad

---

## 27. Servicios con cuentas de usuario específicas

- Categoría: `identity_service_accounts` — Riesgo: **MEDIUM**

✅ Automatizado

- Detecta 8 servicios con cuentas no-sistema
- Lista nombre, display y cuenta de cada uno

🔧 Pendiente — `account_profiler` (mejorar)

- Para cada cuenta de servicio: qué recursos de red accede
- Detectar si alguna cuenta de servicio tiene acceso a datos del usuario
- Cruzar con catálogo de surveillance

📋 Recomendación manual

- Solicitar inventario de servicios y su justificación al DPO

---

## 28. Telemetría de Office sin política restrictiva

- Categoría: `telemetry_office` — Riesgo: **MEDIUM**

✅ Automatizado

- Detecta ausencia de política GPO restrictiva de Office
- Detecta experiencias conectadas activas

🔧 Pendiente — skill `dpa_checker`

- Verificar nivel de telemetría real de Office via registro
- Detectar si hay Add-ins que envían datos adicionales
- Comparar configuración actual con configuración mínima recomendada AEPD

📋 Recomendación manual

- Solicitar a IT política GPO de privacidad de Office
- Desactivar manualmente experiencias conectadas no esenciales

---

## 29. Agente EDR/XDR corporativo (CrowdStrike, Defender)

- Categoría: `edr_xdr` — Riesgo: **LOW**

✅ Automatizado

- Detecta CrowdStrike Falcon y Microsoft Defender for Endpoint
- Confirma que son seguridad corporativa estándar
- Documenta con contexto legal apropiado (bajo riesgo)

🔧 Pendiente — skill `addon_audit`

- Detectar qué módulos específicos de CrowdStrike están activos
- Verificar si el módulo de Identity Protection está habilitado
- Documentar capacidades reales vs capacidades activadas

📋 Recomendación manual

- Solicitar política de uso de datos del EDR
- Verificar que el uso se limita a finalidades de seguridad

---

## 30. Windows Event Forwarding y PowerShell Transcription *(Hallazgo transversal — aparece en múltiples skills)*

✅ Automatizado

- Parcialmente detectado via `event_viewer_audit`

🔧 Pendiente — skill `event_log_monitor`

- Detectar si WEF está activo y a qué servidor reenvía los logs
- Detectar si PowerShell Transcription está habilitada y dónde guarda los transcripts
- Si hay transcripts locales: contar cuántos, período que cubren
- Detectar si los transcripts incluyen actividad personal del usuario
- Intentar deshabilitar si no hay GPO que lo bloquee
- Si hay GPO: documentar que la empresa registra toda la actividad PowerShell

📋 Recomendación manual

- Solicitar al DPO qué se hace con los logs de WEF
- Solicitar DPIA si los logs se usan para evaluar empleados

---

## RESUMEN DE SKILLS A CREAR

### `addon_audit` — Auditor de Add-ins y Extensiones

Cubre: hallazgos 11, 13, 14, 16, 17, 21, 22, 29

- Extensiones de navegador forzadas con permisos completos
- Add-ins de Office/Teams/Outlook
- Extensiones de VSCode con telemetría
- Políticas de apps de terceros
- Módulos activos de EDR

### `onedrive_mapper` — Mapeador de OneDrive y KFM

Cubre: hallazgos 3, 13, 25

- Documenta carpetas redirigidas
- Calcula volumen en nube
- Crea carpetas locales seguras fuera de OneDrive
- Detecta archivos personales ya sincronizados

### `diagtrack_inspector` — Inspector de Telemetría

Cubre: hallazgos 1, 2

- Estado y actividad de DiagTrack
- Endpoints de destino de telemetría
- Logs de transmisiones recientes

### `event_log_monitor` — Monitor de Logs de Seguridad

Cubre: hallazgos 24, 30

- Windows Event Forwarding activo y destino
- PowerShell Transcription activa y transcripts
- Logs de conexión USB
- Intenta deshabilitarlos si no hay GPO

### `clipboard_watcher` — Monitor de Portapapeles

Cubre: hallazgo 6

- Monitoriza qué apps acceden al portapapeles
- Detecta envío de datos de portapapeles a red

### `dpa_checker` — Verificador de DPA y Telemetría Real

Cubre: hallazgos 1, 10, 12, 28

- Verifica DPA con Microsoft
- Compara nivel de telemetría declarado vs real
- Verifica DPIA para experiencias conectadas

### `service_hardener` — Endurecedor de Servicios

Cubre: hallazgos 2, 4, 7

- Intenta deshabilitar DiagTrack, WEF, PS Transcription
- Intenta activar BitLocker si TPM disponible
- Documenta éxitos y fracasos como evidencia

### `rdp_log_exporter` — Exportador de Logs RDP

Cubre: hallazgos 5, 23

- Historial completo de accesos RDP
- Accesos por cuenta de administrador
- Accesos fuera de horario laboral
- IPs externas que han accedido

## Others Functions & Features

**Backend**:

- **Ejecutar skills específicos** — opción para ejecutar solo un skill o categoría de skills, con resultados acumulativos

- **Modo vigilancia** — monitorización en tiempo real de aspectos críticos (tareas programadas, conexiones USB, etc.) con alertas inmediatas

- **Temporización de auditorías** — programar auditorías periódicas automáticas con notificaciones de resultados

- **Comparación entre auditorías** — ver diferencias entre dos informes(ya parcialmente presente con varios informes en la barra lateral)

- **Incorporar validación de esquema** para salidas JSON.
- **Añadir ejemplos anonimizados completos**
 en `.docs/examples/` para demo.
- **Añadir tests automáticos** (unidad/integración) para skills y exportadores.
- **Configurar CI** para lint + validación de documentación.
- **Versión CLI** — opción para ejecutar auditorías desde línea de comandos sin interfaz gráfica

**UI**:

- **Vista detalle de raw_data** — expandir los datos técnicos por hallazgo + búsqueda
- **Gráfico de riesgo** — visualización tipo donut con Chart.js
- **Exportación avanzada** — opciones para incluir/excluir secciones, personalizar formato de exportación
- **Dashboard de tendencias** — mostrar tendencias a lo largo del tiempo con múltiples auditorías
- **Comparación visual** — comparar dos auditorías lado a lado con diferencias resaltadas
- **Integración con herramientas de análisis** — exportar a formatos compatibles con herramientas como Jupyter, Excel, etc.
- **Modo oscuro** — opción de tema oscuro para la interfaz
- **Notificaciones** — alertas visuales o sonoras para hallazgos críticos

**Distribución**:

- **Empaquetado** — script de instalación para distribuir a técnicos o sindicatos
- **Integración con SIEM** — exportar resultados en formato compatible para ingestión en sistemas SIEM corporativos
- **Divulgación** — crear materiales de divulgación para sindicatos y trabajadores sobre la importancia de la auditoría de seguridad interna y cómo usar la herramienta

⏳ Mejora del PDF para presentación sindical
⏳ Ejecutar main_auto.py y generar informe completo actualizado
⏳ Refactorización de skills grandes
⏳ Modo portable — PyInstaller .exe para USB
