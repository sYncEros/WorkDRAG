# Recomendaciones por vulneración detectada

- Documento actualizado: `2026-05-31T05:10:21`
- Informe fuente: `exports\2026-05-31\04h.35m\audit.json`
- Vulneraciones con evaluación legal: **30**

## Lista de Automatizacion

### Realizadas

- Verificar si existe registro de accesos remotos realizados. OK

### Pendientes

addon_audit — el más gordo, cubre extensiones, add-ins, VSCode, Teams

- Listado de add-ins forzados y su funcion + datos envian y a donde:
  · Microsof 365 (Outlook, Office, Teams...),
  · Navegadores (Edge, Chrome, ...)
  · Corporativos (Teams, IAs, Accesos)etc
  · Herramientas de desarrollo (VSCode, JetBrains, etc)

- Documentar qué carpetas están redirigidas y crear carpetas locales fuera de OneDrive para uso personal.

- Obtener un informe de:

  · Logs de Windows Event Forward y PowerShell Transcription para evaluar qué actividad se monitoriza y su período de retención. Verificar si se han usado para evaluar empleados o si hay logs de actividad personal (DPIA)

  · Documentar estado de DiagTrack: qué datos se recopilan, con qué frecuencia y a dónde se envían.

  · Base legal de la telemetría de Windows que justifica esta transferencia internacional de datos personales. Verificar si se ha informado al trabajador (incluso al empleador)

  · Aplicaciones que acceden al portapapeles y qué datos recopilan.
  
- Verificar si existe DPA con Microsoft, que nivel de telemetría y que cubre.

- Intentar deshabilitar:
  · Windows Event Forwarding
  · PowerShell Transcription
  · DiagTrack
  · Telemetría de Windows o al menos reducirla al mínimo.

clipboard_watcher — qué apps tocan el portapapeles y que datos exportan y a donde

### Recomendaciones

- No usar el email corporativo para comunicaciones privadas.
- No almacenar datos personales en el equipo corporativo.
- No usar el navegador corporativo para asuntos personales.

- Solicitar al DPO:
  · Los logs de Windows Event Forwarding y PowerShell Transcription se analizan para evaluar empleados o que uso se les da. Solicitar la evaluación de impacto (DPIA) si existe.
  · Eliminacion o reducción de la telemetría de Windows. Justificación legal de esta transferencia internacional de datos personales.

## 9. Configuraciones de seguridad básicas ausentes

- Categoría: `hardening_missing`
- Riesgo legal: **MEDIUM-HIGH**

### Motivo

El empleador tiene obligación bajo RGPD art. 32 de implementar medidas técnicas apropiadas. La ausencia de protecciones básicas puede constituir incumplimiento y aumenta el riesgo para los datos del trabajador.

### Recomendaciones

- Solicitar al empleador el plan de hardening de equipos.
- Exigir activación de BitLocker si no está presente.
- Documentar las ausencias como parte del informe forense.
- Presentar al DPO como posible incumplimiento RGPD art. 32.

### Referencias

- [RGPD Art. 5 — Principios del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 10. Credenciales almacenadas accesibles para administradores

- Categoría: `identity_stored_credentials`
- Riesgo legal: **MEDIUM-HIGH**

### Motivo

Las credenciales en Windows Credential Manager pueden ser extraídas por administradores. Si incluyen contraseñas personales del trabajador, su acceso no autorizado vulnera LOPDGDD y CP art. 197.

### Recomendaciones

- No guardar contraseñas personales en Windows Credential Manager.
- Usar un gestor de contraseñas personal independiente.
- Revisar qué credenciales están almacenadas con cmdkey /list.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 5 — Principios del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 11. Cuenta específica con características de riesgo

- Categoría: `identity_suspicious_account`
- Riesgo legal: **MEDIUM-HIGH**

### Motivo

Una cuenta habilitada con privilegios elevados y sin uso documentado puede ser una puerta trasera para acceso no autorizado al equipo del trabajador.

### Recomendaciones

- Solicitar justificación específica de esta cuenta al empleador.
- Verificar si aparece en el inventario oficial de cuentas.
- Consultar con asesor laboral si no hay justificación.
- Preservar este informe como evidencia.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 32 — Seguridad del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [ET Art. 20 bis — Derechos de los trabajadores a la intimidad](https://www.boe.es/buscar/act.php?id=BOE-A-2015-11430)

## 12. Experiencias conectadas de Office enviando contenido a Microsoft

- Categoría: `ai_connected_experiences`
- Riesgo legal: **MEDIUM-HIGH**

### Motivo

Office 365 envía contenido de documentos a Microsoft para funciones de IA: traducción, diseño, sugerencias. Puede incluir datos personales de clientes y empleados sin base legal adecuada o sin conocimiento del trabajador.

### Recomendaciones

- Solicitar el DPA entre la empresa y Microsoft.
- Verificar qué experiencias conectadas están activas.
- Solicitar DPIA si se procesan datos de categoría especial.
- Desactivar experiencias conectadas no necesarias para el trabajo.

### Referencias

- [RGPD Art. 5 — Principios del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)

## 13. Extensiones forzadas con acceso completo al navegador

- Categoría: `browser_forced_extensions`
- Riesgo legal: **MEDIUM-HIGH**

### Motivo

Extensiones GPO con permisos amplios pueden interceptar formularios, contraseñas y contenido web. Requieren información previa al trabajador sobre qué datos recopilan.

### Recomendaciones

- Solicitar al empleador listado de extensiones forzadas y su función.
- Verificar los permisos de cada extensión en chrome://extensions.
- No introducir datos personales en formularios web en equipos corporativos.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 14. Inspección de tráfico HTTPS sin información acreditada

- Categoría: `ssl_inspection`
- Riesgo legal: **MEDIUM-HIGH**

### Motivo

La inspección SSL permite al empleador leer contenido de comunicaciones cifradas. La doctrina Barbulescu II exige informar previamente al trabajador del alcance.

### Recomendaciones

- Verificar si la empresa ha informado por escrito sobre la inspección de tráfico.
- Evitar uso de cuentas personales en dispositivos corporativos.
- Solicitar la política de uso aceptable (AUP) de la empresa.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [TEDH — Doctrina Barbulescu II (2017)](https://hudoc.echr.coe.int/eng?i=001-177082)

## 15. Políticas GPO de OneDrive forzando sincronización

- Categoría: `cloud_sync_policy`
- Riesgo legal: **MEDIUM-HIGH**

### Motivo

KFMBlockOptOut impide que el trabajador desactive la sincronización de sus carpetas principales. El trabajador no puede controlar qué datos van a la nube corporativa.

### Recomendaciones

- Solicitar al empleador información sobre las políticas GPO.
- Verificar qué datos son accesibles por el admin de M365.
- Documentar la imposibilidad de desactivar la sincronización.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [ET Art. 20 bis — Derechos de los trabajadores a la intimidad](https://www.boe.es/buscar/act.php?id=BOE-A-2015-11430)
- [RGPD Art. 5 — Principios del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 16. Políticas corporativas aplicadas a apps de terceros (Teams, Zoom, Chrome...)

- Categoría: `third_party_apps_policies`
- Riesgo legal: **MEDIUM-HIGH**

### Motivo

Las políticas GPO sobre apps de terceros pueden forzar telemetría, desactivar cifrado E2E o habilitar supervisión corporativa. El trabajador debe ser informado de qué funciones de control están activas en cada aplicación.

### Recomendaciones

- Solicitar al DPO listado de políticas activas sobre apps de terceros.
- Verificar si hay funciones de compliance o supervisión activas.
- Consultar con IT qué datos se envían desde cada aplicación.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [TEDH — Doctrina Barbulescu II (2017)](https://hudoc.echr.coe.int/eng?i=001-177082)

## 17. Software DLP corporativo monitorizando transferencias de datos

- Categoría: `exfiltration_dlp_monitoring`
- Riesgo legal: **MEDIUM-HIGH**

### Motivo

El DLP corporativo puede inspeccionar el contenido de archivos y comunicaciones del trabajador. La AEPD exige informar previamente sobre el alcance de la inspección de contenidos, especialmente si afecta a archivos personales del trabajador.

### Recomendaciones

- Solicitar al DPO la política DLP y qué datos inspecciona.
- Verificar si el DLP inspecciona contenido personal.
- No almacenar datos personales en el equipo corporativo.
- Consultar con asesor laboral sobre el alcance del DLP.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [AEPD — Guía de Protección de Datos en Relaciones Laborales](https://www.aepd.es/guias/guia-proteccion-datos-relaciones-laborales.pdf)

## 18. Agentes de monitorización con privilegios de SISTEMA

- Categoría: `identity_privileged_monitoring`
- Riesgo legal: **MEDIUM**

### Motivo

Procesos de SISTEMA tienen acceso sin restricciones a todos los datos del equipo. Los agentes EDR con estos privilegios tienen capacidad técnica de acceso total.

### Recomendaciones

- Solicitar al DPO qué datos recopilan estos agentes.
- Verificar que existe política de uso de datos del EDR.
- Documentar qué agentes corren como SISTEMA.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 5 — Principios del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 19. Cuentas con alertas de seguridad sin documentar

- Categoría: `identity_account_profiles`
- Riesgo legal: **MEDIUM**

### Motivo

Cuentas habilitadas con privilegios elevados o nunca usadas pueden ser vectores de acceso no autorizado. El trabajador tiene derecho a saber qué cuentas tienen acceso a su dispositivo.

### Recomendaciones

- Solicitar inventario completo de cuentas y su justificación.
- Exigir que IT deshabilite cuentas no necesarias.
- Documentar este informe como evidencia del estado actual.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 32 — Seguridad del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 20. Cuentas locales no documentadas con acceso al equipo

- Categoría: `identity_local_accounts`
- Riesgo legal: **MEDIUM**

### Motivo

Cuentas habilitadas con contraseña permanente o nunca usadas pueden ser puertas traseras. El trabajador tiene derecho a saber qué cuentas tienen acceso a su dispositivo.

### Recomendaciones

- Solicitar al empleador inventario de cuentas locales y su función.
- Verificar si hay cuentas de soporte remoto no documentadas.
- Solicitar que IT deshabilite cuentas no necesarias.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 32 — Seguridad del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 21. Extensiones de VSCode con indicadores de telemetría de actividad

- Categoría: `vscode_extensions`
- Riesgo legal: **MEDIUM**

### Motivo

Extensiones de time tracking o productividad en VSCode pueden monitorizar el tiempo de trabajo, los proyectos activos y la actividad del desarrollador. Si son instaladas corporativamente sin información, puede vulnerar LOPDGDD art. 87.

### Recomendaciones

- Revisar qué extensiones están instaladas y su origen.
- Identificar extensiones de time tracking o productividad.
- Verificar si hay extensiones forzadas por políticas corporativas.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 22. Extensiones de navegador forzadas con acceso a contenido web

- Categoría: `browser_inspection`
- Riesgo legal: **MEDIUM**

### Motivo

Las extensiones corporativas con acceso completo a páginas web pueden leer formularios, contraseñas y contenido personal.

### Recomendaciones

- Identificar qué extensiones están instaladas y su editor.
- Solicitar información sobre su función a IT.
- No usar el navegador corporativo para asuntos personales.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 23. Herramientas CLI de nube con acceso a credenciales configuradas

- Categoría: `exfiltration_cloud_cli`
- Riesgo legal: **MEDIUM**

### Motivo

Herramientas CLI de nube (rclone, AWS CLI) con credenciales preconfiguradas en el equipo corporativo pueden usarse para transferir datos masivamente. Su uso puede ser monitorizado por el DLP corporativo.

### Recomendaciones

- Verificar que las credenciales de nube son corporativas, no personales.
- Asegurar que el uso de estas herramientas está autorizado.
- Consultar con IT la política de uso de herramientas de nube.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 32 — Seguridad del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 24. Múltiples administradores con acceso completo al equipo

- Categoría: `identity_admin_group`
- Riesgo legal: **MEDIUM**

### Motivo

Un número elevado de administradores locales aumenta el riesgo de acceso no autorizado. El trabajador tiene derecho a saber quién puede acceder a su equipo y con qué finalidad.

### Recomendaciones

- Solicitar al empleador lista de cuentas con acceso admin.
- Verificar que el número de admins está justificado.
- Exigir registro de auditoría de accesos administrativos.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 32 — Seguridad del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 25. Políticas corporativas de control de almacenamiento USB

- Categoría: `usb_dlp_policies`
- Riesgo legal: **MEDIUM**

### Motivo

La empresa tiene activas políticas GPO de control de dispositivos USB. Si estas políticas registran intentos de conexión o uso, se está tratando información del trabajador. Requiere información previa bajo LOPDGDD art. 87 y RGPD art. 13.

### Recomendaciones

- Solicitar al empleador la política de uso de dispositivos USB.
- Verificar si se registran los intentos de conexión USB.
- Comprobar si el registro es accesible por Recursos Humanos.
- Consultar con el DPO qué datos se conservan y por cuánto tiempo.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 26. Políticas corporativas de navegador activas

- Categoría: `browser_policies`
- Riesgo legal: **MEDIUM**

### Motivo

CloudReportingEnabled envía actividad del navegador al administrador. El bloqueo del modo incógnito elimina una herramienta de privacidad del trabajador.

### Recomendaciones

- Verificar si CloudReporting está activo en chrome://policy.
- Solicitar al DPO qué datos de navegación se recopilan.
- No usar el navegador corporativo para asuntos personales.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 27. Servicio de sincronización en nube activo

- Categoría: `cloud_sync_service`
- Riesgo legal: **MEDIUM**

### Motivo

La sincronización automática puede constituir transferencia internacional de datos personales bajo RGPD cap. V. El empleador debe tener DPA con el proveedor y base legal adecuada.

### Recomendaciones

- Solicitar al DPO el DPA con cada proveedor de nube activo.
- Verificar qué datos se sincronizan y hacia qué región.
- Solicitar el registro de actividades de tratamiento.

### Referencias

- [RGPD Art. 5 — Principios del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)

## 28. Servicios con cuentas de usuario específicas

- Categoría: `identity_service_accounts`
- Riesgo legal: **MEDIUM**

### Motivo

Servicios que corren bajo cuentas de dominio tienen acceso a recursos de red con privilegios de esa cuenta. Si son cuentas de monitorización, su alcance real puede ser mayor del esperado.

### Recomendaciones

- Solicitar inventario de servicios y cuentas asociadas.
- Verificar que cada servicio tiene justificación documentada.
- Consultar al DPO si algún servicio trata datos del trabajador.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 32 — Seguridad del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 29. Telemetría de Microsoft Office sin política restrictiva

- Categoría: `telemetry_office`
- Riesgo legal: **MEDIUM**

### Motivo

Office 365 recopila datos de uso, nombres de archivos y en configuración por defecto fragmentos de contenido. Sin política GPO restrictiva aplica la configuración más permisiva por defecto.

### Recomendaciones

- Solicitar a IT política GPO de privacidad de Office.
- Verificar el nivel de telemetría configurado.
- Comprobar que el DPA con Microsoft está actualizado.

### Referencias

- [RGPD Art. 5 — Principios del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## 30. Agente EDR/XDR corporativo

- Categoría: `edr_xdr`
- Riesgo legal: **LOW**

### Motivo

Los EDR son considerados seguridad corporativa estándar y generalmente cumplen el principio de proporcionalidad si están orientados a la detección de amenazas.

### Recomendaciones

- Verificar que existe política de seguridad documentada.
- Comprobar que el uso de datos del EDR se limita a finalidades de seguridad.

### Referencias

- [LOPDGDD Art. 87 — Derecho a la intimidad en el trabajo](https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673)
- [RGPD Art. 5 — Principios del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
