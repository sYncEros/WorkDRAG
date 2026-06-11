# Derechos Laborales y Minado Corporativo

Trabajar en equipo corporativo sin ser minado
Primero: entiende qué pueden ver
En un ordenador de empresa, el empleador tiene derecho legal a monitorizar todo lo que ocurre en ese dispositivo. Eso incluye:

Keyloggers de productividad (Teramind, Hubstaff, ActivTrak)
Capturas de pantalla periódicas
DNS/proxy corporativo → todo el tráfico web
EDR/antivirus (CrowdStrike, SentinelOne) que reportan procesos y archivos
MDM si es laptop gestionado (Intune, Jamf)
Lo que no pueden ver (legalmente en UE/España): contenido de comunicaciones personales si usas red propia, vida privada fuera del horario laboral.

Separación física: la regla de oro

Trabajo  →  dispositivo de empresa  (deja que lo monitoricen, no des más)Personal →  tu propio dispositivo   (nunca mezcles)

Nunca uses el WiFi corporativo para cosas personales
Nunca conectes cuentas personales (Google, GitHub personal) en el equipo de empresa
Nunca uses el VPN corporativo fuera del horario laboral si puedes evitarlo

Reducir superficie de exposición laboral
Riesgo Mitigación
KPIs de productividad via pantalla - Trabaja en ventana maximizada, desactiva notificaciones personales
Tracking de actividad de teclado - No escribas nada personal en ese equipo
Exfiltración de tu trabajo propio - No guardes proyectos personales en ese disco
Espionaje industrial inverso (tuyo → ellos) - No accedas a tus proyectos desde ese equipo
Redes: la capa más crítica
Usa tethering de tu móvil para cosas personales urgentes, no el WiFi corporativo
El proxy corporativo puede hacer TLS inspection (descifran HTTPS): todo lo que pase por su red es visible
Si necesitas privacidad real en horario laboral → datos móviles propios + dispositivo propio
Proyectos como S0φIA / Paper's Queen

Especialmente relevante para ti:

Nunca abras estos repos desde el equipo de empresa
Nunca uses VS Code del equipo corporativo con extensiones que reporten telemetría hacia su infraestructura
Si tienes que hacer algo de ambos mundos el mismo día → dos pantallas, dos máquinas
Git con SSH keys separadas: una key para trabajo, otra para tus proyectos personales
Marco legal en España/UE
RGPD Art. 88 + ET Art. 20.3 — el empleador debe informarte de qué monitoriza y con qué propósito
Tienen que existir política de uso aceptable y aviso previo — si no existe, el monitoreo puede ser ilegal
Puedes pedir al DPO (Delegado de Protección de Datos) qué datos recogen sobre ti
Resumen operativo
Separación total de dispositivos: no hay solución técnica mejor
No mezcles identidades digitales entre entornos
Lee el contrato — muchos tienen cláusulas de propiedad intelectual que aplican incluso a código escrito en tu propio tiempo si es "relacionado con el negocio"
Datos móviles propios para cualquier comunicación privada
¿Tienes un caso concreto (tipo de empresa, contrato freelance vs empleado, tipo de software que usan)?