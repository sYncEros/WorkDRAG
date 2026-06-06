// ui/static/js/legal.js
const LEGAL_MAP = {
  ssl_inspection: {
    issue: 'Inspección de tráfico HTTPS sin información acreditada',
    risk: 'medium-high',
    reason: 'La inspección SSL permite al empleador leer contenido de comunicaciones cifradas. La doctrina Barbulescu II exige informar previamente al trabajador.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13', 'TEDH Barbulescu II (2017)'],
    recs: [
      'Verificar si la empresa ha informado por escrito sobre la inspección de tráfico.',
      'Evitar uso de cuentas personales en dispositivos corporativos.',
      'Solicitar la política de uso aceptable (AUP) de la empresa.'
    ]
  },
  browser_inspection: {
    issue: 'Extensiones de navegador forzadas con acceso a contenido web',
    risk: 'medium',
    reason: 'Las extensiones corporativas con acceso completo a páginas web pueden leer formularios, contraseñas y contenido personal.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13'],
    recs: [
      'Identificar qué extensiones están instaladas y su editor.',
      'Solicitar información sobre su función a IT.',
      'No usar el navegador corporativo para asuntos personales.'
    ]
  },
  edr_xdr: {
    issue: 'Agente EDR/XDR corporativo',
    risk: 'low',
    reason: 'Los EDR son seguridad corporativa estándar y generalmente cumplen proporcionalidad si están orientados a detección de amenazas.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5'],
    recs: [
      'Verificar que existe política de seguridad documentada.',
      'Comprobar que el uso de datos del EDR se limita a finalidades de seguridad.'
    ]
  },
  productivity_monitoring: {
    issue: 'Monitorización continua de productividad',
    risk: 'high',
    reason: 'Puede vulnerar el principio de proporcionalidad del RGPD y el derecho a la intimidad del ET art. 20bis.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis', 'TEDH Barbulescu II'],
    recs: [
      'Solicitar al empleador la política de monitorización por escrito.',
      'Verificar si existe cláusula en contrato o convenio colectivo.',
      'Consultar al DPO de la empresa.',
      'Presentar consulta a la AEPD si no hay información previa.'
    ]
  },
  network_inspection: {
    issue: 'Proxy/agente de inspección de red corporativo',
    risk: 'medium',
    reason: 'Los proxies corporativos pueden registrar URLs visitadas y, con inspección SSL, contenido. La AEPD exige informar al trabajador.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13', 'AEPD Guía Laboral'],
    recs: [
      'Solicitar política de uso de red corporativa.',
      'Asumir que el tráfico corporativo puede ser inspeccionado.',
      'Usar red personal para comunicaciones privadas.'
    ]
  },
  input_monitoring: {
    issue: 'Captura de pulsaciones de teclado (keylogging)',
    risk: 'very_high',
    reason: 'El keylogging captura absolutamente todo lo que escribe el trabajador. Raramente supera el test de proporcionalidad del RGPD.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis', 'TEDH Barbulescu II', 'RGPD Art. 5'],
    recs: [
      'Documentar técnicamente la presencia del keylogger.',
      'Consultar inmediatamente con asesor laboral.',
      'Presentar denuncia ante la AEPD.',
      'Informar a la representación sindical.'
    ]
  },
  // ── Privacy Invasions ─────────────────────────────────────────────
  privacy_clipboard: {
    issue: 'Acceso al portapapeles del trabajador',
    risk: 'medium-high',
    reason: 'El portapapeles puede contener contraseñas, tokens y datos bancarios. Su acceso por software corporativo sin consentimiento puede capturar datos especialmente sensibles bajo RGPD art. 9.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 9', 'ET Art. 20bis'],
    recs: [
      'Identificar qué aplicación accede al portapapeles.',
      'No copiar credenciales ni datos sensibles en equipos corporativos.',
      'Solicitar al DPO información sobre el tratamiento de estos datos.'
    ]
  },
  privacy_camera: {
    issue: 'Aplicaciones con acceso a cámara web',
    risk: 'medium',
    reason: 'Apps no-videollamada con permiso de cámara pueden activarla sin indicación visual. La grabación sin consentimiento vulnera LOPDGDD art. 89.',
    refs: ['LOPDGDD Art. 89', 'ET Art. 20bis'],
    recs: [
      'Revisar qué apps tienen permiso de cámara en Configuración > Privacidad.',
      'Tapar físicamente la cámara cuando no se use.',
      'Solicitar justificación a IT de cada app con acceso.'
    ]
  },
  privacy_microphone: {
    issue: 'Apps no-videollamada con acceso a micrófono',
    risk: 'high',
    reason: 'La grabación de audio sin consentimiento puede constituir delito bajo art. 197 Código Penal además de vulnerar LOPDGDD. El micrófono puede capturar conversaciones privadas.',
    refs: ['LOPDGDD Art. 87', 'Código Penal Art. 197', 'RGPD Art. 9'],
    recs: [
      'Identificar inmediatamente qué app tiene el permiso.',
      'Revocar permisos en Configuración > Privacidad > Micrófono.',
      'Consultar con asesor laboral si no hay justificación.'
    ]
  },
  privacy_location: {
    issue: 'Geolocalización activa con apps autorizadas',
    risk: 'high',
    reason: 'La geolocalización de trabajadores está expresamente regulada en ET art. 20bis y requiere base legal específica, información previa y proporcionalidad.',
    refs: ['ET Art. 20bis', 'LOPDGDD Art. 87', 'RGPD Art. 5'],
    recs: [
      'Verificar si la empresa ha informado sobre geolocalización.',
      'Desactivar el servicio de ubicación si no es necesario para el trabajo.',
      'Solicitar la base legal del tratamiento al DPO.'
    ]
  },
  privacy_input_hooks: {
    issue: 'Hooks de entrada de teclado/ratón detectados',
    risk: 'very_high',
    reason: 'Los hooks de input interceptan absolutamente todo lo escrito. Sin consentimiento explícito vulnera LOPDGDD, ET art. 20bis y posiblemente art. 197 Código Penal.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis', 'Código Penal Art. 197'],
    recs: [
      'Documentar técnicamente con este informe.',
      'Consultar inmediatamente con asesor laboral o sindicato.',
      'Presentar denuncia ante la AEPD.',
      'Contactar con la representación sindical.'
    ]
  },
  privacy_screenshot: {
    issue: 'Herramientas de captura de pantalla activas',
    risk: 'high',
    reason: 'La captura periódica de pantalla es una de las formas más invasivas de vigilancia. Incluye comunicaciones privadas, contraseñas visibles y datos sensibles.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5', 'TEDH Barbulescu II'],
    recs: [
      'Identificar si la captura es automática o manual.',
      'Solicitar política de uso de herramientas de screenshot.',
      'Consultar con el DPO si hay retención de capturas.'
    ]
  },
  privacy_screen_recording: {
    issue: 'Windows Recall activo — captura continua de pantalla',
    risk: 'very_high',
    reason: 'Windows Recall captura snapshots continuos indexados. En equipos corporativos sin desactivar por política es extremadamente problemático bajo LOPDGDD y RGPD.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5', 'ET Art. 20bis'],
    recs: [
      'Desactivar Recall en Configuración > Privacidad > Recall.',
      'Solicitar a IT que aplique política GPO de desactivación.',
      'Documentar que estaba activo en este informe.'
    ]
  },
  // ── Network Monitoring ───────────────────────────────────────────
  network_monitoring_destination: {
    issue: 'Conexión activa a infraestructura de monitorización',
    risk: 'medium',
    reason: 'Confirma operación activa de software de monitorización enviando datos a servidores externos. El tipo de datos transmitidos determina el riesgo real.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13'],
    recs: [
      'Solicitar al DPO qué datos envía cada producto.',
      'Verificar que existe registro de actividades de tratamiento.',
      'Pedir la evaluación de impacto (DPIA) si existe.'
    ]
  },
  network_proxy: {
    issue: 'Proxy corporativo interceptando tráfico web',
    risk: 'medium-high',
    reason: 'Todo el tráfico HTTP/HTTPS pasa por el proxy corporativo. Combinado con inspección SSL puede descifrar y registrar comunicaciones.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13', 'TEDH Barbulescu II'],
    recs: [
      'Solicitar política de uso aceptable (AUP) por escrito.',
      'Verificar si el proxy registra URLs y durante cuánto tiempo.',
      'Asumir que todo el tráfico corporativo puede ser inspeccionado.'
    ]
  },
  // ── Activity Monitoring ─────────────────────────────────────────────
  activity_security_events: {
    issue: 'Cambios críticos de configuración recientes',
    risk: 'medium',
    reason: 'Eventos como creación de tareas, instalación de servicios o cambios de política en las últimas 24h pueden indicar modificaciones recientes de infraestructura de vigilancia.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5'],
    recs: [
      'Documentar la fecha y hora de los cambios detectados.',
      'Correlacionar con comunicaciones recientes de IT.',
      'Preservar este informe como evidencia del estado actual.'
    ]
  },
  activity_autostart_changes: {
    issue: 'Modificaciones recientes en claves de autostart',
    risk: 'medium',
    reason: 'Cambios recientes en autostart son evidencia forense sobre cuándo se instaló software. Relevante para establecer si la vigilancia es previa o posterior al contrato.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13'],
    recs: [
      'Conservar este informe como snapshot del estado actual.',
      'Solicitar al empleador qué software fue instalado recientemente.',
      'Comparar con auditorías anteriores si existen.'
    ]
  },
  // ── AI Telemetry ──────────────────────────────────────────────────
  telemetry_windows_level: {
    issue: 'Telemetría completa de Windows activa',
    risk: 'high',
    reason: 'Windows en nivel de telemetría completo envía datos de actividad, contenido de documentos y uso de aplicaciones a Microsoft en EEUU. Transferencia internacional sin control explícito del trabajador.',
    refs: ['RGPD Art. 5', 'RGPD Cap. V — Transferencias internacionales', 'LOPDGDD Art. 87'],
    recs: [
      'Solicitar al DPO la base legal de la telemetría de Windows.',
      'Verificar si existe DPA entre la empresa y Microsoft.',
      'Solicitar que IT aplique política GPO de telemetría mínima.',
    ]
  },
  ai_windows_recall: {
    issue: 'Windows Recall indexando toda la actividad mediante IA',
    risk: 'very_high',
    reason: 'Recall captura screenshots continuos y los indexa con IA. En equipos corporativos el empleador puede acceder a esta base de datos. Riesgo extremo bajo LOPDGDD art. 87 y RGPD art. 5.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5', 'ET Art. 20bis'],
    recs: [
      'Desactivar Recall inmediatamente en Configuración > Privacidad.',
      'Solicitar a IT política GPO de desactivación.',
      'Documentar que estaba activo en este informe como evidencia.',
      'Consultar con asesor laboral si hay acceso corporativo a los datos.'
    ]
  },
  ai_connected_experiences: {
    issue: 'Experiencias conectadas de Office enviando contenido a Microsoft',
    risk: 'medium-high',
    reason: 'Office 365 envía contenido de documentos a Microsoft para funciones de IA. Puede incluir datos personales de clientes y empleados sin base legal adecuada.',
    refs: ['RGPD Art. 6', 'RGPD Art. 28', 'RGPD Cap. V'],
    recs: [
      'Solicitar el DPA entre la empresa y Microsoft.',
      'Verificar qué experiencias conectadas están activas.',
      'Solicitar DPIA si se procesan datos de categoría especial.',
      'Desactivar experiencias conectadas no necesarias.'
    ]
  },
  telemetry_services: {
    issue: 'Servicio DiagTrack (telemetría continua) activo',
    risk: 'high',
    reason: 'DiagTrack recopila y envía datos de actividad continuamente. No se puede desactivar completamente en Windows 11 Home. Opera como tratamiento continuo de datos personales.',
    refs: ['RGPD Art. 5', 'RGPD Art. 6', 'LOPDGDD Art. 87'],
    recs: [
      'Solicitar a IT que deshabilite DiagTrack via GPO en equipos corporativos.',
      'Verificar que la empresa tiene DPA vigente con Microsoft.',
      'Documentar el estado actual como evidencia.'
    ]
  },
  cloud_sync_service: {
    issue: 'Servicio de sincronización en nube activo',
    risk: 'medium',
    reason: 'La sincronización automática puede constituir transferencia internacional de datos personales bajo RGPD cap. V. El empleador debe tener DPA con el proveedor y base legal adecuada.',
    refs: ['RGPD Art. 5', 'RGPD Cap. V — Transferencias internacionales', 'LOPDGDD Art. 87'],
    recs: [
      'Solicitar al DPO el DPA con cada proveedor de nube activo.',
      'Verificar qué datos se sincronizan y hacia qué región.',
      'Solicitar el registro de actividades de tratamiento.',
    ]
  },
  // ── Cloud Sync ──────────────────────────────────────────────────
  cloud_sync_onedrive_detail: {
    issue: 'OneDrive sincronizando carpetas del sistema (KFM)',
    risk: 'high',
    reason: 'Known Folder Move redirige Escritorio y Documentos a OneDrive. Cualquier archivo guardado va automáticamente a Microsoft 365, accesible por el empleador. Requiere información previa bajo LOPDGDD art. 87.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis', 'RGPD Art. 5'],
    recs: [
      'Verificar si el trabajador fue informado de la redirección de carpetas.',
      'No guardar documentos personales en Escritorio o Documentos.',
      'Solicitar política de acceso del empleador a OneDrive corporativo.',
      'Consultar con el DPO qué datos del trabajador están accesibles.',
    ]
  },
  cloud_sync_folder_redirect: {
    issue: 'Carpetas del sistema redirigidas a nube corporativa',
    risk: 'high',
    reason: 'Las carpetas principales de Windows apuntan a OneDrive/SharePoint. Todo lo guardado es inmediatamente accesible por el empleador a través de Microsoft 365.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis', 'RGPD Art. 5'],
    recs: [
      'Documentar qué carpetas están redirigidas.',
      'Solicitar política de acceso a datos del empleador.',
      'Crear carpetas locales fuera de OneDrive para uso personal.',
      'Consultar con asesor laboral sobre el alcance del acceso corporativo.',
    ]
  },
  cloud_sync_policy: {
    issue: 'Políticas GPO de OneDrive forzando sincronización',
    risk: 'medium-high',
    reason: 'KFMBlockOptOut impide que el trabajador desactive la sincronización de sus carpetas principales. El trabajador no puede controlar qué datos van a la nube corporativa.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis', 'RGPD Art. 5'],
    recs: [
      'Solicitar al empleador información sobre las políticas GPO de OneDrive.',
      'Verificar qué datos son accesibles por el administrador de M365.',
      'Documentar la imposibilidad de desactivar la sincronización.',
    ]
  },
  // ── Browser ────────────────────────────────────────────────────
  browser_forced_extensions: {
    issue: 'Extensiones forzadas con acceso completo al navegador',
    risk: 'medium-high',
    reason: 'Extensiones GPO con permisos amplios pueden interceptar formularios, contraseñas y contenido web sin conocimiento del trabajador.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13'],
    recs: [
      'Solicitar al empleador listado de extensiones forzadas y su función.',
      'Verificar los permisos de cada extensión en chrome://extensions.',
      'No introducir datos personales en formularios web en equipos corporativos.',
    ]
  },
  browser_policies: {
    issue: 'Políticas corporativas de navegador activas',
    risk: 'medium',
    reason: 'CloudReportingEnabled envía actividad del navegador al administrador. El bloqueo del modo incógnito elimina una herramienta de privacidad del trabajador.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13'],
    recs: [
      'Verificar si CloudReporting está activo en chrome://policy.',
      'Solicitar al DPO qué datos de navegación se recopilan.',
      'No usar el navegador corporativo para asuntos personales.',
    ]
  },
  browser_credential_sync: {
    issue: 'Contraseñas del navegador sincronizándose a la nube',
    risk: 'medium-high',
    reason: 'Las contraseñas sincronizadas en perfiles corporativos pueden ser accesibles para el administrador de M365 o Google Workspace.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5'],
    recs: [
      'No guardar contraseñas personales en navegadores corporativos.',
      'Usar un gestor de contraseñas personal independiente.',
      'Desactivar la sincronización de contraseñas en el perfil corporativo.',
    ]
  },
  browser_corporate_profile: {
    issue: 'Navegación bajo perfil corporativo monitorizable',
    risk: 'medium',
    reason: 'La navegación bajo perfil corporativo puede ser monitorizada por el empleador a través de la consola de administración de M365 o Google Workspace.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13', 'TEDH Barbulescu II (2017)'],
    recs: [
      'Asumir que la navegación corporativa puede ser monitorizada.',
      'Usar perfil personal separado para navegación privada.',
      'Solicitar al empleador política de uso del navegador.',
    ]
  },

  // ── Hardening ──────────────────────────────────────────────────
  hardening_missing: {
    issue: 'Configuraciones de seguridad básicas ausentes',
    risk: 'medium-high',
    reason: 'El empleador tiene obligación bajo RGPD art. 32 de implementar medidas técnicas apropiadas. La ausencia de protecciones básicas puede constituir incumplimiento y aumenta el riesgo para los datos del trabajador.',
    refs: ['RGPD Art. 5', 'RGPD Art. 13'],
    recs: [
      'Solicitar al empleador el plan de hardening de equipos.',
      'Exigir activación de BitLocker si no está presente.',
      'Documentar las ausencias como parte del informe forense.',
      'Presentar al DPO como posible incumplimiento RGPD art. 32.',
    ]
  },
  hardening_encryption: {
    issue: 'Cifrado de disco no activo — datos en claro',
    risk: 'high',
    reason: 'Sin BitLocker, en caso de pérdida o robo todos los datos son accesibles sin autenticación. El empleador incumple RGPD art. 32 al no aplicar cifrado en equipos corporativos.',
    refs: ['RGPD Art. 5', 'RGPD Art. 13'],
    recs: [
      'Solicitar a IT la activación inmediata de BitLocker.',
      'Documentar la ausencia como riesgo de seguridad.',
      'Notificar al DPO como posible brecha de seguridad latente.',
    ]
  },
  hardening_credentials: {
    issue: 'Protección de credenciales insuficiente',
    risk: 'medium',
    reason: 'Sin LSASS Protection o Credential Guard las credenciales del trabajador son vulnerables a extracción de memoria, incluyendo contraseñas personales guardadas en el sistema.',
    refs: ['RGPD Art. 5'],
    recs: [
      'Solicitar a IT activación de RunAsPPL para LSASS.',
      'Verificar si Credential Guard está disponible en el hardware.',
      'No guardar contraseñas personales en el gestor del sistema.',
    ]
  },
  // ── Identity & Access ──────────────────────────────────────────
  identity_local_accounts: {
    issue: 'Cuentas locales no documentadas con acceso al equipo',
    risk: 'medium',
    reason: 'Cuentas habilitadas con contraseña permanente o nunca usadas pueden ser puertas traseras. El trabajador tiene derecho a saber qué cuentas tienen acceso a su dispositivo.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 32'],
    recs: [
      'Solicitar al empleador inventario de cuentas locales y su función.',
      'Verificar si hay cuentas de soporte remoto no documentadas.',
      'Solicitar que IT deshabilite cuentas no necesarias.',
    ]
  },
  identity_remote_access: {
    issue: 'Acceso remoto habilitado al equipo del trabajador',
    risk: 'high',
    reason: 'RDP habilitado permite acceso completo al escritorio sin notificación. Una conexión activa sin aviso puede constituir vigilancia encubierta y vulnerar CP art. 197.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis', 'TEDH Barbulescu II (2017)'],
    recs: [
      'Solicitar al empleador política de acceso remoto documentada.',
      'Exigir notificación previa antes de cualquier acceso remoto.',
      'Verificar si existe registro de accesos remotos realizados.',
      'Consultar con asesor laboral si hay accesos no comunicados.',
    ]
  },
  identity_admin_group: {
    issue: 'Múltiples administradores con acceso completo al equipo',
    risk: 'medium',
    reason: 'Un número elevado de administradores locales aumenta el riesgo de acceso no autorizado. El trabajador tiene derecho a saber quién puede acceder a su equipo y con qué finalidad.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 32'],
    recs: [
      'Solicitar al empleador lista de cuentas con acceso admin.',
      'Verificar que el número de admins está justificado.',
      'Exigir registro de auditoría de accesos administrativos.',
    ]
  },
  identity_stored_credentials: {
    issue: 'Credenciales almacenadas accesibles para administradores',
    risk: 'medium-high',
    reason: 'Las credenciales en Windows Credential Manager pueden ser extraídas por administradores. Si incluyen contraseñas personales, su acceso no autorizado vulnera LOPDGDD y CP art. 197.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5'],
    recs: [
      'No guardar contraseñas personales en Windows Credential Manager.',
      'Usar un gestor de contraseñas personal independiente.',
      'Revisar qué credenciales están almacenadas con cmdkey /list.',
    ]
  },
  identity_multiple_sessions: {
    issue: 'Múltiples sesiones activas — posible acceso remoto simultáneo',
    risk: 'high',
    reason: 'Sesiones simultáneas pueden indicar que alguien está accediendo remotamente mientras el trabajador usa el equipo, pudiendo ver su actividad en tiempo real.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis'],
    recs: [
      "Verificar qué sesiones están activas con 'query session'.",
      'Solicitar al empleador política de acceso remoto.',
      'Documentar el momento de detección como evidencia.',
    ]
  },
  identity_account_profiles: {
    issue: 'Cuentas con alertas de seguridad sin documentar',
    risk: 'medium',
    reason: 'Cuentas habilitadas con privilegios elevados, contraseña permanente o nunca usadas pueden ser vectores de acceso no autorizado. El trabajador tiene derecho a saber qué cuentas existen y con qué finalidad.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 32'],
    recs: [
      'Solicitar al empleador inventario completo de cuentas y su justificación.',
      'Exigir que IT deshabilite cuentas no necesarias.',
      'Documentar este informe como evidencia del estado actual.',
    ]
  },
  identity_suspicious_account: {
    issue: 'Cuenta específica con características de riesgo',
    risk: 'medium-high',
    reason: 'Una cuenta habilitada con privilegios elevados y sin uso documentado puede ser una puerta trasera para acceso remoto no autorizado al equipo del trabajador.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 32', 'ET Art. 20bis'],
    recs: [
      'Solicitar al empleador justificación específica de esta cuenta.',
      'Verificar si aparece en el inventario oficial de cuentas.',
      'Consultar con asesor laboral si no hay justificación documentada.',
      'Preservar este informe como evidencia.',
    ]
  },
  identity_logon_rights: {
    issue: 'Derechos de acceso remoto con alcance amplio',
    risk: 'medium',
    reason: 'Si grupos amplios tienen derecho de inicio de sesión remoto, muchos usuarios pueden acceder al escritorio del trabajador sin que lo sepa.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis'],
    recs: [
      'Verificar qué cuentas tienen SeRemoteInteractiveLogonRight.',
      'Solicitar política de acceso remoto documentada.',
      'Exigir notificación previa de cualquier acceso remoto.',
    ]
  },
  identity_service_accounts: {
    issue: 'Servicios con cuentas de usuario específicas',
    risk: 'medium',
    reason: 'Servicios que corren bajo cuentas de dominio tienen acceso a recursos de red con los privilegios de esa cuenta. Si son cuentas de monitorización, su alcance real puede ser mayor del esperado.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 32'],
    recs: [
      'Solicitar inventario de servicios y las cuentas bajo las que corren.',
      'Verificar que cada servicio tiene justificación documentada.',
      'Consultar al DPO si algún servicio trata datos del trabajador.',
    ]
  },
  identity_privileged_monitoring: {
    issue: 'Agentes de monitorización con privilegios de SISTEMA',
    risk: 'medium',
    reason: 'Procesos de SISTEMA tienen acceso sin restricciones a todos los datos del equipo. Los agentes EDR/vigilancia con estos privilegios tienen capacidad técnica de acceso total.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5'],
    recs: [
      'Solicitar al DPO qué datos recopilan estos agentes.',
      'Verificar que existe política de uso de datos del EDR.',
      'Documentar qué agentes corren como SISTEMA.',
    ]
  },
  // ── Git Identity ───────────────────────────────────────────────
  git_config_mismatch: {
    issue: 'Identidad Git no coincide con el usuario del sistema',
    risk: 'medium',
    reason: 'Commits realizados con identidad incorrecta pueden atribuir trabajo a otra persona o dificultar la autoría técnica. En contexto laboral puede usarse para desacreditar contribuciones del trabajador.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis'],
    recs: [
      'Verificar git config user.name y user.email en todos los repos.',
      'Activar git config --global user.useConfigOnly true.',
      'Documentar commits propios con evidencia de autoría correcta.',
    ]
  },
  git_recent_changes: {
    issue: 'Configuración Git modificada recientemente',
    risk: 'low',
    reason: 'Cambios recientes en .gitconfig pueden indicar modificación de identidad o configuración por parte de terceros con acceso al equipo.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5'],
    recs: [
      'Verificar qué cambió en .gitconfig y cuándo.',
      'Confirmar que la identidad configurada es la correcta.',
    ]
  },

  // ── Scheduled Tasks ────────────────────────────────────────────
  scheduled_tasks_suspicious: {
    issue: 'Tareas programadas con características de monitorización',
    risk: 'medium-high',
    reason: 'Tareas programadas pueden ejecutar scripts de vigilancia en segundo plano de forma periódica sin conocimiento del trabajador.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5', 'ET Art. 20bis'],
    recs: [
      'Solicitar inventario de tareas programadas no-Microsoft y su función.',
      'Verificar qué ejecuta cada tarea y con qué frecuencia.',
      'Solicitar al DPO si alguna tarea recopila datos del trabajador.',
    ]
  },
  scheduled_tasks_new: {
    issue: 'Tareas programadas creadas recientemente',
    risk: 'medium',
    reason: 'Tareas creadas recientemente pueden ser herramientas de vigilancia instaladas sin notificación al trabajador.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13'],
    recs: [
      'Documentar fecha de creación de cada tarea nueva.',
      'Correlacionar con comunicaciones recientes de IT.',
      'Preservar como evidencia del momento de instalación.',
    ]
  },

  // ── USB ────────────────────────────────────────────────────────
  usb_dlp_policies: {
    issue: 'Políticas de control de dispositivos USB activas',
    risk: 'medium',
    reason: 'Las políticas USB registran intentos de conexión del trabajador. Si RRHH tiene acceso a estos logs, se trata datos personales sin base legal clara.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13'],
    recs: [
      'Solicitar política USB y período de retención de logs.',
      'Verificar si los logs son accesibles por RRHH.',
      'Solicitar al DPO base legal del registro de conexiones USB.',
    ]
  },
  usb_blocked: {
    issue: 'Puertos USB bloqueados por política corporativa',
    risk: 'low',
    reason: 'El bloqueo de USB es medida de seguridad estándar. El problema es si no se informa al trabajador y si los intentos de conexión quedan registrados.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13'],
    recs: [
      'Verificar si existe política documentada de uso de USB.',
      'Solicitar información sobre qué se registra al intentar conectar un USB.',
    ]
  },

  // ── Email ──────────────────────────────────────────────────────
  email_addins_forced: {
    issue: 'Add-ins de correo forzados con acceso al buzón',
    risk: 'high',
    reason: 'Add-ins corporativos en Outlook pueden leer, clasificar y reenviar correos del trabajador. El acceso al buzón sin información previa vulnera LOPDGDD art. 87 y la doctrina Barbulescu.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13', 'TEDH Barbulescu II (2017)'],
    recs: [
      'Solicitar listado de add-ins forzados y qué datos acceden.',
      'Verificar si hay reglas de reenvío automático activas.',
      'No usar el email corporativo para comunicaciones personales.',
      'Solicitar al DPO política de acceso al buzón corporativo.',
    ]
  },
  email_forwarding_rules: {
    issue: 'Reglas de reenvío automático detectadas',
    risk: 'high',
    reason: 'Las reglas de reenvío pueden desviar correos del trabajador a cuentas corporativas de RRHH o compliance sin su conocimiento, vulnerando LOPDGDD art. 87.',
    refs: ['LOPDGDD Art. 87', 'TEDH Barbulescu II (2017)', 'CP Art. 197'],
    recs: [
      'Verificar todas las reglas activas en Outlook > Administrar reglas.',
      'Eliminar cualquier regla de reenvío que no hayas creado tú.',
      'Consultar asesor laboral si hay reenvíos a cuentas desconocidas.',
    ]
  },
  email_dlp_active: {
    issue: 'DLP de email inspeccionando contenido de correos',
    risk: 'medium-high',
    reason: 'El DLP de email puede inspeccionar el contenido de correos del trabajador. Requiere información previa y base legal bajo LOPDGDD art. 87 y doctrina Barbulescu.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13', 'TEDH Barbulescu II (2017)'],
    recs: [
      'Solicitar política DLP de email al DPO.',
      'Verificar si el DLP inspecciona contenido o solo metadatos.',
      'No usar email corporativo para comunicaciones privadas.',
    ]
  },

  // ── Third Party Apps ───────────────────────────────────────────
  third_party_apps_telemetry: {
    issue: 'Apps de terceros con telemetría activa enviando datos',
    risk: 'medium',
    reason: 'Apps como Teams, Zoom o Slack envían datos de uso a sus servidores. En entorno corporativo el empleador puede acceder a estos datos a través de consolas de administración.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13', 'RGPD Cap. V'],
    recs: [
      'Solicitar al DPO qué datos envía cada app y a qué región.',
      'Verificar si el empleador tiene acceso a la consola de admin de Teams/Zoom.',
      'No usar apps corporativas para comunicaciones personales.',
    ]
  },
  third_party_apps_policies: {
    issue: 'Políticas corporativas sobre apps de terceros',
    risk: 'medium-high',
    reason: 'Políticas GPO sobre Teams, Zoom o VSCode pueden activar grabación, transcripción o monitorización sin que el trabajador lo sepa.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13', 'TEDH Barbulescu II (2017)'],
    recs: [
      'Solicitar listado de políticas activas sobre apps de terceros.',
      'Verificar si Teams tiene Compliance Recording activo.',
      'Solicitar al DPO si hay grabación o transcripción automática.',
    ]
  },

  // ── User Behavior ──────────────────────────────────────────────
  user_behavior_anomaly: {
    issue: 'Análisis de comportamiento del usuario activo',
    risk: 'high',
    reason: 'Los sistemas UEBA analizan patrones de comportamiento del trabajador (horas, recursos accedidos, velocidad de escritura). Sin información previa vulneran LOPDGDD art. 87 y el principio de minimización.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5', 'ET Art. 20bis'],
    recs: [
      'Solicitar al DPO si existe sistema UEBA y qué analiza.',
      'Exigir DPIA para el tratamiento de datos de comportamiento.',
      'Solicitar información sobre decisiones automatizadas (RGPD art. 22).',
    ]
  },
  user_behavior_baseline: {
    issue: 'Línea base de comportamiento del usuario establecida',
    risk: 'medium-high',
    reason: 'El establecimiento de una línea base de comportamiento implica tratamiento continuo de datos personales del trabajador para elaborar su perfil.',
    refs: ['RGPD Art. 5', 'RGPD Art. 22', 'LOPDGDD Art. 87'],
    recs: [
      'Solicitar al DPO qué datos se usan para la línea base.',
      'Exigir derecho de acceso a los datos de comportamiento propios.',
      'Solicitar DPIA si existe perfilado automatizado.',
    ]
  },

  // ── Data Exfiltration ──────────────────────────────────────────
  exfiltration_dlp_monitoring: {
    issue: 'DLP corporativo monitorizando transferencias de datos',
    risk: 'medium-high',
    reason: 'El DLP puede inspeccionar el contenido de archivos transferidos. Si incluye archivos personales del trabajador requiere información previa bajo LOPDGDD art. 87.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13', 'AEPD — Guía de Protección de Datos en Relaciones Laborales'],
    recs: [
      'Solicitar al DPO la política DLP y qué datos inspecciona.',
      'Verificar si el DLP registra transferencias a dispositivos personales.',
      'No transferir datos personales mediante canales corporativos.',
    ]
  },
  exfiltration_cloud_cli: {
    issue: 'Herramientas CLI de nube con credenciales configuradas',
    risk: 'medium',
    reason: 'Credenciales personales en herramientas corporativas pueden ser accesibles para el empleador. El DLP puede registrar transferencias realizadas con estas herramientas.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 32'],
    recs: [
      'Verificar que las credenciales configuradas son corporativas.',
      'Eliminar credenciales personales de herramientas en equipo corporativo.',
      'Consultar con IT si el uso está autorizado.',
    ]
  },
  exfiltration_suspicious_transfer: {
    issue: 'Transferencia de datos sospechosa detectada',
    risk: 'high',
    reason: 'Transferencias de datos a destinos no corporativos pueden ser registradas por el DLP y usadas contra el trabajador. También pueden ser falsas atribuciones si hay acceso no autorizado al equipo.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5', 'CP Art. 197'],
    recs: [
      'Documentar cualquier transferencia propia con justificación.',
      'Verificar si hay accesos remotos que puedan haber causado la transferencia.',
      'Consultar asesor laboral inmediatamente si hay acusación.',
    ]
  },

  // ── Incident Response ──────────────────────────────────────────
  incident_detected: {
    issue: 'Indicadores de incidente de seguridad detectados',
    risk: 'high',
    reason: 'La detección de un incidente de seguridad en el equipo del trabajador puede desencadenar investigaciones que acceden a todos los datos del equipo sin notificación.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 32', 'RGPD Art. 33'],
    recs: [
      'Documentar el estado del equipo antes de cualquier intervención de IT.',
      'Solicitar por escrito el alcance de cualquier investigación forense.',
      'Consultar asesor laboral antes de cooperar con investigación interna.',
    ]
  },

  // ── Event Viewer ───────────────────────────────────────────────
  event_viewer_collection_status: {
    issue: 'Cobertura de Event Viewer y accesibilidad de registros',
    risk: 'medium',
    reason: 'El estado de cobertura indica si el informe tiene base forense suficiente o hay limitaciones de acceso a registros clave que reducen la evidencia disponible.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13'],
    recs: [
      'Si hay logs no accesibles, solicitar ejecución con permisos adecuados.',
      'Conservar el estado de cobertura como parte de la cadena de evidencia.',
      'Documentar ventana temporal y alcance para trazabilidad del análisis.',
    ]
  },
  event_viewer_full_logs_export: {
    issue: 'Volcado histórico completo de logs del equipo',
    risk: 'medium-high',
    reason: 'El volcado completo aporta evidencia exhaustiva de actividad histórica y facilita detectar patrones de vigilancia o tratamiento desproporcionado.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5', 'RGPD Art. 13', 'RGPD Art. 35'],
    recs: [
      'Conservar manifest y logs exportados fuera del equipo corporativo.',
      'Priorizar revisión de muestras marcadas como sospechosas.',
      'Solicitar al DPO base legal y finalidad de tratamientos detectados.',
    ]
  },
  event_viewer_full_logs_export_error: {
    issue: 'Error al exportar histórico completo de logs',
    risk: 'medium',
    reason: 'Si falla la exportación masiva el informe pierde cobertura forense relevante. El error puede indicar restricciones activas que impiden auditar el equipo.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13'],
    recs: [
      'Repetir exportación con permisos elevados cuando proceda.',
      'Conservar mensaje de error técnico como parte del expediente.',
      'Ejecutar exportación por bloques si el entorno limita recursos.',
    ]
  },
  event_viewer_sensitive_events: {
    issue: 'Eventos sensibles detectados — tareas, servicios y políticas',
    risk: 'high',
    reason: 'La correlación de eventos críticos (creación de tareas, instalación de servicios, cambios de políticas de auditoría) puede evidenciar despliegues de monitorización que requieren información previa y proporcionalidad.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 13', 'TEDH Barbulescu II (2017)'],
    recs: [
      'Solicitar al DPO detalle de los cambios operativos en la ventana temporal.',
      'Pedir trazabilidad de quién autorizó cada cambio y con qué finalidad.',
      'Preservar el informe y exportes como evidencia cronológica.',
    ]
  },
  event_viewer_powershell_audit: {
    issue: 'Auditoría detallada de PowerShell registrada en Event Viewer',
    risk: 'medium-high',
    reason: 'El registro de script blocks de PowerShell permite reconstruir acciones técnicas con alto detalle. Si se usa para evaluar desempeño del trabajador requiere DPIA y base legal.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5', 'RGPD Art. 35'],
    recs: [
      'Solicitar al DPO la finalidad concreta del logging de PowerShell.',
      'Verificar período de retención y acceso a los logs de script blocks.',
      'Solicitar DPIA si se usan para evaluación de desempeño.',
    ]
  },
  event_viewer_remote_access_patterns: {
    issue: 'Patrones de acceso privilegiado detectados en Security log',
    risk: 'medium-high',
    reason: 'Los eventos de credenciales explícitas y privilegios elevados pueden reflejar accesos administrativos al equipo del trabajador. Deben estar documentados y comunicados conforme al principio de transparencia.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis', 'TEDH Barbulescu II (2017)'],
    recs: [
      'Solicitar al empleador registro de accesos administrativos y justificación.',
      'Exigir política de notificación previa para accesos remotos.',
      'Contrastar eventos con ventanas de mantenimiento aprobadas.',
    ]
  },
  // ── PowerShell ───────────────────────────────────────────────────
  powershell_transcription: {
    issue: 'PowerShell Transcription registrando todos los comandos',
    risk: 'high',
    reason: 'PS Transcription graba cada comando PowerShell ejecutado. En equipos de desarrolladores incluye credenciales, rutas de archivos y actividad técnica completa.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 5', 'ET Art. 20bis'],
    recs: [
      'Verificar dónde se guardan los transcripts y quién los lee.',
      'Solicitar al DPO período de retención y acceso a los transcripts.',
      'Intentar deshabilitar si no hay GPO que lo bloquee.',
    ]
  },

  // ── RDP Logs ───────────────────────────────────────────────────
  rdp_access_history: {
    issue: 'Historial de accesos remotos al equipo del trabajador',
    risk: 'medium',
    reason: 'El historial RDP es evidencia directa de quién ha accedido al equipo y cuándo. El trabajador tiene derecho a conocer qué cuentas han accedido y con qué finalidad.',
    refs: ['LOPDGDD Art. 87', 'ET Art. 20bis', 'RGPD Art. 32'],
    recs: [
      'Solicitar al empleador registro completo de accesos remotos.',
      'Exigir notificación previa de cualquier acceso futuro.',
      'Preservar este log como evidencia forense.',
    ]
  },
  rdp_after_hours: {
    issue: 'Accesos remotos fuera del horario laboral',
    risk: 'high',
    reason: 'Accesos al equipo fuera de horario pueden violar el derecho a la desconexión digital (LOPDGDD art. 88) y constituir vigilancia en tiempo personal.',
    refs: ['LOPDGDD Art. 88', 'ET Art. 20bis', 'LOPDGDD Art. 87'],
    recs: [
      'Documentar cada acceso fuera de horario con fecha y hora.',
      'Solicitar justificación escrita de cada acceso detectado.',
      'Consultar asesor laboral si hay patrón sistemático.',
    ]
  },
  rdp_external_access: {
    issue: 'Accesos RDP desde IPs externas a la red corporativa',
    risk: 'high',
    reason: 'Accesos desde IPs externas sin conocimiento del trabajador tienen mayor gravedad legal y pueden constituir acceso no autorizado bajo CP art. 197.',
    refs: ['LOPDGDD Art. 87', 'RGPD Art. 32', 'CP Art. 197'],
    recs: [
      'Solicitar identificación de cada IP externa y su justificación.',
      'Verificar si hay VPN corporativa que justifique los accesos.',
      'Consultar asesor laboral si no hay justificación documentada.',
    ]
  },
  rdp_failed_attempts: {
    issue: 'Equipo expuesto a ataques de acceso remoto',
    risk: 'medium',
    reason: 'Múltiples intentos fallidos indican exposición a ataques externos. El empleador incumple RGPD art. 32 si no protege adecuadamente el acceso remoto.',
    refs: ['RGPD Art. 32', 'LOPDGDD Art. 87'],
    recs: [
      'Solicitar a IT que limite RDP a IPs corporativas.',
      'Exigir autenticación de dos factores para RDP.',
      'Documentar la exposición como incumplimiento RGPD art. 32.',
    ]
  },
};

const LEGAL_RISK_ORDER = { low:0, medium:1, 'medium-high':2, high:3, very_high:4 };

function renderLegal(findings) {
  const categories = [...new Set(findings.map(f => f.category))];
  const issues = categories
    .filter(c => LEGAL_MAP[c])
    .map(c => LEGAL_MAP[c])
    .sort((a,b) => (LEGAL_RISK_ORDER[b.risk]||0) - (LEGAL_RISK_ORDER[a.risk]||0));

  document.getElementById('legalCount').textContent = issues.length;
  const container = document.getElementById('legalDetail');

  if (!issues.length) {
    container.innerHTML = `
      <div class="card" style="text-align:center;padding:40px">
        <div style="font-size:32px;margin-bottom:12px">✅</div>
        <div style="font-weight:600">Sin conflictos legales significativos</div>
        <div style="color:var(--text-muted);font-size:13px;margin-top:6px">
          La configuración parece corresponder a seguridad corporativa estándar.
        </div>
      </div>`;
    return;
  }

  container.innerHTML = issues.map(issue => `
    <div class="legal-card">
      <div class="legal-header">
        <div style="font-size:14px;font-weight:600">${issue.issue}</div>
        ${badge(issue.risk)}
      </div>
      <div class="legal-body">
        <div class="legal-reason">${issue.reason}</div>
        <div class="legal-refs">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.8px;
            color:var(--text-muted);margin-bottom:8px">Referencias legales</div>
          ${issue.refs.map(r => `
            <div class="legal-ref">
              <div class="legal-ref-name">${r}</div>
            </div>`).join('')}
        </div>
        <div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.8px;
            color:var(--text-muted);margin-bottom:8px">Recomendaciones</div>
          <ul class="recs-list">
            ${issue.recs.map(r => `<li>${r}</li>`).join('')}
          </ul>
        </div>
      </div>
    </div>
  `).join('');
}