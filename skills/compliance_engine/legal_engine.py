# skills/compliance_engine/legal_engine.py
"""
Motor de Derechos y Cumplimiento — WorkDRAG
Cruza hallazgos técnicos con legislación española.
Sin recomendaciones manuales: las mitiga el auditor automáticamente.
"""
 
# ── Marco legal de referencia ──────────────────────────────────────────────────
 
LEGAL_FRAMEWORK = {
    "rgpd_art5": {
        "name": "RGPD Art. 5 — Principios del tratamiento",
        "url": "https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679"
    },
    "rgpd_art13": {
        "name": "RGPD Art. 13 — Información al interesado",
        "url": "https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679"
    },
    "rgpd_art22": {
        "name": "RGPD Art. 22 — Decisiones automatizadas y perfilado",
        "url": "https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679"
    },
    "rgpd_art32": {
        "name": "RGPD Art. 32 — Seguridad del tratamiento",
        "url": "https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679"
    },
    "rgpd_art35": {
        "name": "RGPD Art. 35 — Evaluación de impacto (DPIA)",
        "url": "https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679"
    },
    "lopdgdd_art87": {
        "name": "LOPDGDD Art. 87 — Intimidad en el trabajo",
        "url": "https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673"
    },
    "lopdgdd_art88": {
        "name": "LOPDGDD Art. 88 — Desconexión digital",
        "url": "https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673"
    },
    "et_art20bis": {
        "name": "ET Art. 20bis — Derechos digitales del trabajador",
        "url": "https://www.boe.es/buscar/act.php?id=BOE-A-2015-11430"
    },
    "tedh_barbulescu": {
        "name": "TEDH — Doctrina Barbulescu II (2017)",
        "url": "https://hudoc.echr.coe.int/eng?i=001-177082"
    },
    "aepd_guia_laboral": {
        "name": "AEPD — Guía Protección de Datos en Relaciones Laborales",
        "url": "https://www.aepd.es/guias/guia-proteccion-datos-relaciones-laborales.pdf"
    },
    "cp_art197": {
        "name": "CP Art. 197 — Descubrimiento y revelación de secretos",
        "url": "https://www.boe.es/buscar/act.php?id=BOE-A-1995-25444"
    },
}
 
# ── Reglas por categoría real ──────────────────────────────────────────────────
# Formato: { category, issue, legal_risk, reason, references[] }
# Sin recomendaciones manuales — el auditor las automatiza.
 
COMPLIANCE_RULES = [
 
    # ── MDM ───────────────────────────────────────────────────────
    {"category": "Corporate Control",
     "issue": "Equipo bajo gestión corporativa MDM",
     "legal_risk": "medium",
     "reason": "MDM permite instalar software, aplicar políticas y borrar el dispositivo remotamente. Requiere información previa al trabajador sobre su alcance.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "mdm_software_install_policy",
     "issue": "Política MDM de instalación de software activa",
     "legal_risk": "medium",
     "reason": "La empresa puede instalar o desinstalar software silenciosamente. Cualquier agente de monitorización puede desplegarse sin acción del trabajador.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "mdm_dlp_device_policy",
     "issue": "Política MDM de DLP de dispositivo activa",
     "legal_risk": "medium-high",
     "reason": "DLP via MDM puede inspeccionar y bloquear transferencias de datos. La AEPD exige información previa sobre qué datos se inspeccionan.",
     "references": ["lopdgdd_art87", "rgpd_art13", "aepd_guia_laboral"]},
 
    {"category": "mdm_usb_restrictions",
     "issue": "Restricciones USB aplicadas via MDM",
     "legal_risk": "medium",
     "reason": "El control de USB via MDM puede registrar intentos de conexión. Si RRHH accede a esos logs se trata datos personales sin base legal clara.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    # ── Vigilancia ─────────────────────────────────────────────────
    {"category": "ssl_inspection",
     "issue": "Inspección de tráfico HTTPS activa",
     "legal_risk": "medium-high",
     "reason": "El proxy corporativo puede descifrar y registrar comunicaciones HTTPS. La doctrina Barbulescu II exige información previa y proporcionalidad.",
     "references": ["lopdgdd_art87", "rgpd_art13", "tedh_barbulescu"]},
 
    {"category": "edr_xdr",
     "issue": "Agente EDR/XDR corporativo activo",
     "legal_risk": "low",
     "reason": "Los EDR son seguridad corporativa estándar. El riesgo depende de si los datos recopilados se usan para vigilar al trabajador.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    {"category": "behavior_logging_capabilities",
     "issue": "Logging centralizado de actividad del equipo",
     "legal_risk": "high",
     "reason": "WEF y PS Transcription centralizan toda la actividad del equipo. Su análisis puede constituir perfilado del trabajador que requiere DPIA.",
     "references": ["lopdgdd_art87", "rgpd_art5", "rgpd_art35"]},
 
    # ── Red ────────────────────────────────────────────────────────
    {"category": "network_external",
     "issue": "Conexiones salientes activas a IPs externas",
     "legal_risk": "yellow",
     "reason": "Las conexiones externas pueden corresponder a agentes de monitorización enviando telemetría. El tipo de datos transmitidos determina el riesgo real.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "network_dns",
     "issue": "DNS corporativo registrando consultas de dominio",
     "legal_risk": "medium",
     "reason": "El DNS corporativo registra cada dominio consultado. Su análisis revela patrones de uso sin descifrar tráfico.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    # ── Actividad ──────────────────────────────────────────────────
    {"category": "activity_resources",
     "issue": "Procesos con alto consumo sostenido de recursos",
     "legal_risk": "yellow",
     "reason": "Procesos con consumo elevado pueden estar procesando o transmitiendo datos del trabajador en segundo plano.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    {"category": "activity_new_services",
     "issue": "Servicios instalados recientemente",
     "legal_risk": "medium",
     "reason": "Servicios nuevos pueden incluir agentes de monitorización instalados sin conocimiento del trabajador. La fecha de instalación es evidencia forense.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "activity_data_senders",
     "issue": "Procesos con múltiples conexiones salientes simultáneas",
     "legal_risk": "medium",
     "reason": "Múltiples conexiones simultáneas pueden indicar envío paralelo de datos a varios servidores de monitorización.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    # ── Privacidad ─────────────────────────────────────────────────
    {"category": "privacy_clipboard",
     "issue": "Acceso al portapapeles del trabajador detectado",
     "legal_risk": "medium-high",
     "reason": "El portapapeles puede contener contraseñas y datos bancarios. Su acceso por software corporativo puede capturar datos especialmente sensibles bajo RGPD art. 9.",
     "references": ["lopdgdd_art87", "rgpd_art5", "et_art20bis"]},
 
    {"category": "privacy_microphone",
     "issue": "Apps no-videollamada con acceso a micrófono",
     "legal_risk": "high",
     "reason": "La grabación de audio sin consentimiento puede constituir delito bajo CP art. 197. El micrófono puede capturar conversaciones privadas.",
     "references": ["lopdgdd_art87", "rgpd_art5", "cp_art197"]},
 
    {"category": "privacy_location",
     "issue": "Geolocalización activa con apps autorizadas",
     "legal_risk": "high",
     "reason": "La geolocalización de trabajadores está regulada en ET art. 20bis y requiere base legal específica, información previa y proporcionalidad.",
     "references": ["et_art20bis", "lopdgdd_art87", "rgpd_art5"]},
 
    {"category": "privacy_input_hooks",
     "issue": "Hooks de entrada de teclado/ratón detectados",
     "legal_risk": "very_high",
     "reason": "Los hooks interceptan absolutamente todo lo escrito, incluyendo contraseñas. Sin consentimiento explícito puede constituir delito bajo CP art. 197.",
     "references": ["lopdgdd_art87", "et_art20bis", "cp_art197"]},
 
    {"category": "privacy_screenshot",
     "issue": "Herramientas de captura de pantalla activas",
     "legal_risk": "high",
     "reason": "La captura periódica de pantalla incluye comunicaciones privadas y contraseñas visibles. Es una de las formas más invasivas de vigilancia.",
     "references": ["lopdgdd_art87", "rgpd_art5", "tedh_barbulescu"]},
 
    {"category": "privacy_screen_recording",
     "issue": "Windows Recall — captura continua indexada por IA",
     "legal_risk": "very_high",
     "reason": "Recall captura snapshots continuos de toda la pantalla. En equipos corporativos el empleador puede acceder a esta base de datos.",
     "references": ["lopdgdd_art87", "rgpd_art5", "et_art20bis"]},
 
    # ── IA y Telemetría ────────────────────────────────────────────
    {"category": "telemetry_windows_level",
     "issue": "Telemetría completa de Windows activa — sin política restrictiva",
     "legal_risk": "high",
     "reason": "Windows en nivel completo envía contenido de documentos, historial y actividad a Microsoft en EEUU. Transferencia internacional sin control del trabajador.",
     "references": ["rgpd_art5", "rgpd_art13", "lopdgdd_art87"]},
 
    {"category": "telemetry_services",
     "issue": "DiagTrack — telemetría continua activa",
     "legal_risk": "high",
     "reason": "DiagTrack recopila y envía datos de actividad continuamente. En equipos corporativos el empleador es corresponsable bajo RGPD art. 26.",
     "references": ["rgpd_art5", "rgpd_art13", "lopdgdd_art87"]},
 
    {"category": "telemetry_office",
     "issue": "Telemetría de Office 365 sin política restrictiva",
     "legal_risk": "medium",
     "reason": "Office recopila datos de uso y fragmentos de contenido. Sin GPO restrictiva aplica la configuración más permisiva por defecto.",
     "references": ["rgpd_art5", "rgpd_art13"]},
 
    {"category": "ai_connected_experiences",
     "issue": "Experiencias conectadas de Office enviando contenido a Microsoft",
     "legal_risk": "medium-high",
     "reason": "Office envía contenido de documentos para funciones de IA. Puede incluir datos personales de clientes o empleados sin base legal adecuada.",
     "references": ["rgpd_art5", "rgpd_art13", "lopdgdd_art87"]},
 
    {"category": "ai_copilot",
     "issue": "Microsoft Copilot con acceso a contenido laboral",
     "legal_risk": "medium-high",
     "reason": "Copilot accede a emails, documentos y reuniones. Requiere DPIA y base legal explícita bajo RGPD art. 35.",
     "references": ["rgpd_art5", "rgpd_art13", "rgpd_art35"]},
 
    {"category": "ai_windows_recall",
     "issue": "Windows Recall indexando actividad mediante IA local",
     "legal_risk": "very_high",
     "reason": "Recall indexa toda la pantalla con IA. La base de datos local es accesible para procesos con privilegios de administrador.",
     "references": ["lopdgdd_art87", "rgpd_art5", "et_art20bis"]},
 
    # ── Cloud Sync ─────────────────────────────────────────────────
    {"category": "cloud_sync_service",
     "issue": "Servicio de sincronización en nube activo",
     "legal_risk": "medium",
     "reason": "La sincronización automática puede constituir transferencia internacional de datos personales sin control explícito del trabajador.",
     "references": ["rgpd_art5", "rgpd_art13", "lopdgdd_art87"]},
 
    {"category": "cloud_sync_folder_redirect",
     "issue": "Carpetas del sistema redirigidas a nube corporativa",
     "legal_risk": "high",
     "reason": "Todo lo guardado en Escritorio o Documentos va automáticamente a Microsoft 365 y es accesible por el empleador.",
     "references": ["lopdgdd_art87", "et_art20bis", "rgpd_art5"]},
 
    {"category": "cloud_sync_policy",
     "issue": "KFM forzado por GPO — trabajador no puede desactivar la sincronización",
     "legal_risk": "medium-high",
     "reason": "KFMBlockOptOut impide al trabajador controlar qué datos van a la nube corporativa. Elimina el derecho de control sobre sus propios datos.",
     "references": ["lopdgdd_art87", "et_art20bis", "rgpd_art5"]},
 
    # ── Navegador ──────────────────────────────────────────────────
    {"category": "browser_forced_extensions",
     "issue": "Extensiones forzadas por GPO con acceso completo al navegador",
     "legal_risk": "medium-high",
     "reason": "Extensiones con permisos amplios pueden interceptar formularios, contraseñas y contenido web sin conocimiento del trabajador.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "browser_inspection",
     "issue": "Extensiones corporativas con acceso a contenido web",
     "legal_risk": "medium",
     "reason": "Extensiones con acceso a todas las páginas pueden leer formularios y contraseñas introducidas en el navegador.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "browser_policies",
     "issue": "Políticas corporativas de navegador activas",
     "legal_risk": "medium",
     "reason": "CloudReportingEnabled envía actividad al administrador. El bloqueo del modo incógnito elimina una herramienta de privacidad del trabajador.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    # ── Hardening ──────────────────────────────────────────────────
    {"category": "hardening_missing",
     "issue": "Configuraciones de seguridad básicas ausentes",
     "legal_risk": "medium-high",
     "reason": "La ausencia de medidas técnicas básicas incumple RGPD art. 32. El empleador es responsable de garantizar la seguridad de los datos tratados.",
     "references": ["rgpd_art32", "rgpd_art5"]},
 
    {"category": "hardening_encryption",
     "issue": "Cifrado de disco no activo — datos en claro",
     "legal_risk": "high",
     "reason": "Sin BitLocker, si el equipo se pierde o roba todos los datos son accesibles sin autenticación. Incumplimiento directo de RGPD art. 32.",
     "references": ["rgpd_art32", "rgpd_art5"]},
 
    {"category": "hardening_boot",
     "issue": "Secure Boot no activo — arranque sin verificación",
     "legal_risk": "medium",
     "reason": "Sin Secure Boot puede instalarse software antes del arranque de Windows, invisible para cualquier herramienta de seguridad.",
     "references": ["rgpd_art32"]},
 
    {"category": "hardening_network",
     "issue": "Cortafuegos de Windows no activo",
     "legal_risk": "medium",
     "reason": "Sin firewall el equipo está expuesto a conexiones entrantes desde la red corporativa sin filtrado.",
     "references": ["rgpd_art32"]},
 
    {"category": "hardening_antimalware",
     "issue": "Protección antimalware en tiempo real no activa",
     "legal_risk": "medium",
     "reason": "Sin protección en tiempo real, software malicioso puede ejecutarse sin detección, incluyendo keyloggers o agentes de vigilancia no autorizados.",
     "references": ["rgpd_art32"]},
 
    {"category": "hardening_credentials",
     "issue": "Protección de credenciales insuficiente (LSASS/Credential Guard)",
     "legal_risk": "medium",
     "reason": "Sin LSASS Protection las credenciales del trabajador son vulnerables a extracción de memoria por procesos con privilegios.",
     "references": ["rgpd_art32"]},
 
    # ── Persistencia ───────────────────────────────────────────────
    {"category": "persistence_registry",
     "issue": "Entradas de autorun sospechosas en registro",
     "legal_risk": "orange",
     "reason": "Software en autorun puede ejecutarse silenciosamente al inicio de sesión. Es el vector más común para agentes de monitorización persistentes.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "persistence_services",
     "issue": "Servicios con características de monitorización activos",
     "legal_risk": "medium",
     "reason": "Servicios que corren en segundo plano con nombres relacionados con telemetría o monitorización pueden tratar datos del trabajador continuamente.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    {"category": "persistence_drivers",
     "issue": "Drivers con características de monitorización detectados",
     "legal_risk": "medium",
     "reason": "Drivers de kernel con acceso privilegiado pueden interceptar cualquier actividad del sistema: red, ficheros, entrada de usuario.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    {"category": "persistence_dll_hijacking",
     "issue": "Indicadores de DLL hijacking detectados",
     "legal_risk": "high",
     "reason": "DLL hijacking permite ejecutar código malicioso bajo la identidad de aplicaciones legítimas. Puede instalar vigilancia encubierta de forma persistente.",
     "references": ["lopdgdd_art87", "rgpd_art32", "cp_art197"]},
 
    {"category": "persistence_untrusted_certs",
     "issue": "Certificados raíz no confiables detectados",
     "legal_risk": "high",
     "reason": "Certificados raíz no estándar pueden permitir interceptar tráfico HTTPS cifrado. Es el mecanismo técnico detrás de la inspección SSL.",
     "references": ["lopdgdd_art87", "tedh_barbulescu"]},
 
    # ── Identidad ──────────────────────────────────────────────────
    {"category": "identity_local_accounts",
     "issue": "Cuentas locales no documentadas con acceso al equipo",
     "legal_risk": "medium",
     "reason": "Cuentas habilitadas con contraseña permanente o nunca usadas pueden ser puertas traseras para acceso no autorizado.",
     "references": ["lopdgdd_art87", "rgpd_art32"]},
 
    {"category": "identity_admin_group",
     "issue": "Múltiples administradores con acceso completo al equipo",
     "legal_risk": "medium",
     "reason": "Administradores locales tienen acceso irrestricto a todos los archivos, credenciales y actividad del equipo del trabajador.",
     "references": ["lopdgdd_art87", "rgpd_art32"]},
 
    {"category": "identity_remote_access",
     "issue": "RDP habilitado — acceso remoto al escritorio posible",
     "legal_risk": "high",
     "reason": "RDP permite acceso completo al escritorio sin que el trabajador lo sepa. Acceso sin notificación puede constituir vigilancia encubierta.",
     "references": ["lopdgdd_art87", "et_art20bis", "tedh_barbulescu"]},
 
    {"category": "identity_stored_credentials",
     "issue": "Credenciales almacenadas accesibles para administradores",
     "legal_risk": "medium-high",
     "reason": "Credenciales en Windows Credential Manager pueden ser extraídas por administradores. Incluye posibles contraseñas personales del trabajador.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    {"category": "identity_service_accounts",
     "issue": "Servicios con cuentas de usuario específicas",
     "legal_risk": "medium",
     "reason": "Servicios bajo cuentas de dominio tienen acceso a recursos de red con sus privilegios. Si son de monitorización, su alcance real puede ser mayor.",
     "references": ["lopdgdd_art87", "rgpd_art32"]},
 
    {"category": "identity_privileged_monitoring",
     "issue": "Agentes de monitorización con privilegios de SISTEMA",
     "legal_risk": "medium",
     "reason": "Procesos SYSTEM tienen acceso sin restricciones a todos los datos del equipo. Capacidad técnica de acceso total.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    {"category": "identity_account_profiles",
     "issue": "Cuentas con alertas de seguridad detectadas",
     "legal_risk": "medium",
     "reason": "Cuentas habilitadas con privilegios elevados o nunca usadas son vectores de acceso no autorizado potencial.",
     "references": ["lopdgdd_art87", "rgpd_art32"]},
 
    {"category": "identity_suspicious_account",
     "issue": "Cuenta específica con perfil de alto riesgo",
     "legal_risk": "medium-high",
     "reason": "Cuenta habilitada con privilegios elevados y sin uso documentado puede ser puerta trasera para acceso no autorizado.",
     "references": ["lopdgdd_art87", "rgpd_art32", "et_art20bis"]},
 
    {"category": "identity_logon_rights",
     "issue": "Derechos de acceso remoto con alcance amplio",
     "legal_risk": "medium",
     "reason": "Si grupos amplios tienen SeRemoteInteractiveLogonRight, muchos usuarios pueden acceder al escritorio del trabajador sin notificación.",
     "references": ["lopdgdd_art87", "et_art20bis"]},
 
    {"category": "identity_multiple_sessions",
     "issue": "Múltiples sesiones activas simultáneas",
     "legal_risk": "high",
     "reason": "Sesiones simultáneas pueden indicar acceso remoto mientras el trabajador usa el equipo — vigilancia en tiempo real.",
     "references": ["lopdgdd_art87", "et_art20bis"]},
 
    # ── USB ────────────────────────────────────────────────────────
    {"category": "usb_dlp_policies",
     "issue": "Políticas de control USB registrando conexiones",
     "legal_risk": "medium",
     "reason": "Las políticas USB registran intentos de conexión del trabajador. Si RRHH accede a esos logs se trata datos personales.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "usb_connected_now",
     "issue": "Dispositivo USB conectado actualmente",
     "legal_risk": "low",
     "reason": "La conexión de USB puede estar registrada por el DLP corporativo. El tipo de dispositivo y datos transferidos determinan el riesgo.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    {"category": "usb_storage_history",
     "issue": "Historial de dispositivos USB de almacenamiento",
     "legal_risk": "medium",
     "reason": "El historial de USB es evidencia de qué dispositivos de almacenamiento han conectado al equipo. El DLP puede haberlo registrado.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    {"category": "usb_full_history",
     "issue": "Historial completo de dispositivos USB conectados",
     "legal_risk": "medium",
     "reason": "El registro completo de USB puede usarse para analizar el comportamiento del trabajador con dispositivos externos.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    # ── Email ──────────────────────────────────────────────────────
    {"category": "email_outlook_addins",
     "issue": "Add-ins de Outlook con acceso al buzón corporativo",
     "legal_risk": "high",
     "reason": "Add-ins corporativos pueden leer, clasificar y reenviar correos. La doctrina Barbulescu exige información previa sobre el alcance.",
     "references": ["lopdgdd_art87", "rgpd_art13", "tedh_barbulescu"]},
 
    {"category": "email_outlook_profiles",
     "issue": "Perfil de Outlook configurado con cuenta corporativa",
     "legal_risk": "medium",
     "reason": "El perfil corporativo de Outlook puede estar bajo políticas de archivado y compliance que registran toda la actividad de email.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "email_forwarding_rules",
     "issue": "Reglas de reenvío en el buzón corporativo",
     "legal_risk": "high",
     "reason": "Reglas de reenvío pueden desviar correos a cuentas de compliance sin conocimiento del trabajador, vulnerando el secreto de las comunicaciones.",
     "references": ["lopdgdd_art87", "tedh_barbulescu", "cp_art197"]},
 
    # ── Terceras partes ────────────────────────────────────────────
    {"category": "third_party_apps_policies",
     "issue": "Políticas corporativas sobre apps de terceros",
     "legal_risk": "medium-high",
     "reason": "Políticas GPO pueden activar grabación o transcripción en Teams/Zoom sin que el trabajador lo sepa.",
     "references": ["lopdgdd_art87", "rgpd_art13", "tedh_barbulescu"]},
 
    {"category": "third_party_apps_installed",
     "issue": "Apps de terceros con telemetría corporativa instaladas",
     "legal_risk": "medium",
     "reason": "Apps como Teams, Zoom o Slack envían datos de uso. El empleador puede acceder vía consolas de administración.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "vscode_extensions",
     "issue": "Extensiones de VSCode con telemetría de actividad",
     "legal_risk": "medium",
     "reason": "Extensiones de time tracking en VSCode pueden monitorizar tiempo de trabajo y proyectos activos sin información previa.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    # ── Exfiltración ───────────────────────────────────────────────
    {"category": "exfiltration_dlp_monitoring",
     "issue": "DLP corporativo monitorizando transferencias de datos",
     "legal_risk": "medium-high",
     "reason": "El DLP puede inspeccionar contenido de archivos transferidos. Si incluye archivos personales requiere información previa y base legal.",
     "references": ["lopdgdd_art87", "rgpd_art13", "aepd_guia_laboral"]},
 
    {"category": "exfiltration_cloud_cli",
     "issue": "Herramientas CLI de nube con credenciales configuradas",
     "legal_risk": "medium",
     "reason": "Credenciales de nube en equipo corporativo pueden ser accesibles para el empleador. Su uso puede estar monitorizado por el DLP.",
     "references": ["lopdgdd_art87", "rgpd_art32"]},
 
    {"category": "exfiltration_large_files",
     "issue": "Transferencia de archivos de gran tamaño detectada",
     "legal_risk": "medium",
     "reason": "Transferencias masivas son registradas por el DLP corporativo. Pueden usarse para acusaciones sin contexto del trabajador.",
     "references": ["lopdgdd_art87", "rgpd_art5"]},
 
    # ── Git ────────────────────────────────────────────────────────
    {"category": "gitconfig_recently_modified",
     "issue": "Configuración Git modificada recientemente o con identidad incorrecta",
     "legal_risk": "medium",
     "reason": "Commits con identidad incorrecta pueden atribuir trabajo a otra persona. La fecha de modificación del .gitconfig es evidencia forense.",
     "references": ["lopdgdd_art87", "et_art20bis"]},
 
    {"category": "ssh_config_present",
     "issue": "Configuración SSH personalizada detectada",
     "legal_risk": "low",
     "reason": "La config SSH puede contener claves de acceso a servidores. En equipo corporativo, las claves privadas pueden ser accesibles para administradores.",
     "references": ["lopdgdd_art87", "rgpd_art32"]},
 
    # ── Event Viewer ───────────────────────────────────────────────
    {"category": "event_viewer_collection_status",
     "issue": "Cobertura del Event Viewer — accesibilidad de registros",
     "legal_risk": "medium",
     "reason": "Registros no accesibles reducen la base forense del informe. Puede indicar restricciones activas que impiden auditar el equipo.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "event_viewer_sensitive_events",
     "issue": "Eventos críticos detectados — tareas, servicios y políticas",
     "legal_risk": "high",
     "reason": "Eventos de creación de tareas e instalación de servicios pueden evidenciar despliegues de monitorización sin información previa.",
     "references": ["lopdgdd_art87", "rgpd_art13", "tedh_barbulescu"]},
 
    {"category": "event_viewer_collection_status",
     "issue": "Auditoría de PowerShell registrada en Event Viewer",
     "legal_risk": "medium-high",
     "reason": "Script block logging reconstruye toda la actividad técnica del trabajador con alto detalle. Puede constituir perfilado que requiere DPIA.",
     "references": ["lopdgdd_art87", "rgpd_art5", "rgpd_art35"]},
 
    # ── Incident Response ──────────────────────────────────────────
    {"category": "incident_response_evidence",
     "issue": "Evidencia de incidente de seguridad preservada",
     "legal_risk": "medium",
     "reason": "Un incidente puede desencadenar investigaciones forenses que acceden a todos los datos del equipo sin notificación al trabajador.",
     "references": ["lopdgdd_art87", "rgpd_art32"]},
 
    {"category": "incident_response_playbook",
     "issue": "Playbook de respuesta a incidentes activo",
     "legal_risk": "medium",
     "reason": "Los procedimientos de IR pueden incluir acceso completo al equipo del trabajador. El trabajador tiene derecho a conocer el alcance.",
     "references": ["lopdgdd_art87", "rgpd_art13"]},
 
    {"category": "incident_response_rights",
     "issue": "Derechos del trabajador en contexto de incidente de seguridad",
     "legal_risk": "high",
     "reason": "Durante una investigación de IR, el empleador puede acceder a todos los datos del equipo. Los derechos del trabajador se mantienen activos.",
     "references": ["lopdgdd_art87", "et_art20bis", "rgpd_art5"]},
 
    # ── RDP Logs (skill futuro) ────────────────────────────────────
    {"category": "rdp_access_history",
     "issue": "Historial de accesos remotos al equipo",
     "legal_risk": "medium",
     "reason": "El historial RDP es evidencia de quién accedió al equipo y cuándo. El trabajador tiene derecho a conocerlo.",
     "references": ["lopdgdd_art87", "et_art20bis", "rgpd_art32"]},
 
    {"category": "rdp_after_hours",
     "issue": "Accesos remotos fuera del horario laboral",
     "legal_risk": "high",
     "reason": "Accesos fuera de horario violan el derecho a la desconexión digital bajo LOPDGDD art. 88.",
     "references": ["lopdgdd_art88", "et_art20bis", "lopdgdd_art87"]},
 
    {"category": "rdp_external_access",
     "issue": "Accesos RDP desde IPs externas a la red corporativa",
     "legal_risk": "high",
     "reason": "Accesos desde IPs externas sin notificación pueden constituir acceso no autorizado bajo CP art. 197.",
     "references": ["lopdgdd_art87", "rgpd_art32", "cp_art197"]},
 
    {"category": "rdp_failed_attempts",
     "issue": "Equipo expuesto a ataques de acceso remoto",
     "legal_risk": "medium",
     "reason": "Múltiples intentos fallidos indican exposición del equipo. El empleador incumple RGPD art. 32 sin medidas de protección adecuadas.",
     "references": ["rgpd_art32", "lopdgdd_art87"]}, 
]

class LegalEngine:
    """Cruza hallazgos técnicos con legislación. Sin recomendaciones manuales."""
 
    RISK_ORDER = {"low": 0, "yellow": 1, "medium": 2,
                  "medium-high": 3, "orange": 3, "high": 4, "very_high": 5}
 
    def __init__(self, findings: list):
        self.findings   = findings
        self.legal_issues = []
 
    def evaluate(self) -> list:
        categories_found = {f.category for f in self.findings}
        seen = set()
        issues = []
 
        for rule in COMPLIANCE_RULES:
            cat = rule["category"]
            if cat not in categories_found:
                continue
            if cat in seen:
                continue
            seen.add(cat)
            issues.append({
                "category":   cat,
                "issue":      rule["issue"],
                "legal_risk": rule["legal_risk"],
                "reason":     rule["reason"],
                "references": [
                    {"id": r, **LEGAL_FRAMEWORK.get(r, {})}
                    for r in rule.get("references", [])
                ],
                       })
 
        self.legal_issues = sorted(
            issues,
            key=lambda x: self.RISK_ORDER.get(x["legal_risk"], 0),
            reverse=True
        )
        return self.legal_issues
 
    def summary_text(self) -> str:
        if not self.legal_issues:
            return "Sin conflictos legales significativos detectados."
 
        lines = ["=== EVALUACIÓN LEGAL ===\n"]
        for i, issue in enumerate(self.legal_issues, 1):
            refs = ", ".join(
                r.get("name", r.get("id", ""))
                for r in issue["references"]
            )
            lines.append(
                f"{i}. [{issue['legal_risk'].upper()}] {issue['issue']}\n"
                f"   {issue['reason']}\n"
                f"   Referencias: {refs}\n"
            )
        return "\n".join(lines)
 
    def to_dict(self) -> dict:
        return {
            "total_issues": len(self.legal_issues),
            "issues":       self.legal_issues,
            "framework":    LEGAL_FRAMEWORK,
        }
