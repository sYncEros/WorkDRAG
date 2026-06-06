# Dudas o errores

## 4. Cifrado de disco no activo — datos en claro

- Categoría: `hardening_encryption`
- Riesgo legal: **HIGH**

### Motivo

Sin BitLocker activo, en caso de pérdida o robo del equipo todos los datos del trabajador son accesibles sin autenticación. El empleador incumple RGPD art. 32 al no aplicar cifrado en equipos corporativos.

### Recomendaciones

- Solicitar a IT la activación inmediata de BitLocker.
- Documentar la ausencia como riesgo de seguridad.
- Notificar al DPO como posible brecha de seguridad latente.

### Referencias

- [RGPD Art. 5 — Principios del tratamiento](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)
- [RGPD Art. 13 — Información al interesado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:32016R0679)

## Claude

Me parece un salto serio respecto al diseño original: pasaste de 5 skills a unas 17, y las nuevas (telemetría, cloud sync, hardening, identidad, email, apps de terceros, incident response) cierran huecos reales. El mapeo legal sigue siendo lo más fuerte del proyecto — las citas a LOPDGDD 87, ET 20bis, RGPD 5/13/32/35 y Barbulescu II están bien aplicadas y bien matizadas ("puede vulnerar", no "vulnera"). Y mantienes la línea defensiva y de solo lectura, que es justo lo que le da legitimidad

Dicho eso, si quieres feedback de verdad y no aplausos: el riesgo principal del proyecto ahora mismo no es técnico sino de credibilidad, y el informe que adjuntaste lo ilustra bien.
El primer problema es que la escala de riesgo está inflada. El informe llega a ROJO empujado en buena parte por defaults de Windows, no por vigilancia: la telemetría "Completa" es el comportamiento por defecto (sobre todo en Home), no prueba de que el empleador espíe; la redirección de carpetas por KFM/OneDrive es de lo más estándar en M365; y la "ausencia de hardening" no es una capacidad invasiva. A eso se suman detecciones que son claramente keyword matching: 25 servicios "con características de monitorización", 28 drivers, 15 "vectores de DLL hijacking" y 30 certificados raíz "no estándar" son, en una máquina normal, casi todo ruido — el propio informe lo admite en los "qué NO implica", pero igual los cuenta y los pinta de color. Un perito o un abogado que vea ROJOs inflados descuenta el informe entero. Mi sugerencia concreta: separa "hechos de configuración / inventario" de "preocupaciones reales de privacidad", y reserva ROJO para lo que es invasivo por diseño y está activo (input monitoring, captura de pantalla, software tipo Teramind/ActivTrak realmente instalado y corriendo), nunca para capacidades latentes ni defaults.

El segundo es que el retrato del equipo cuesta sostenerlo entero: lo describe a la vez como fuertemente gestionado (CrowdStrike + MDE + MDM + DLP + GPOs forzadas) y sin lo básico (sin BitLocker, sin Firewall, telemetría Full tipo Home, varias cuentas locales sospechosas). Un equipo corporativo gestionado de verdad tendría BitLocker, Secure Boot y Firewall forzados por la misma GPO que aplica todo lo demás. Huele a máquina de test o a falsos positivos, y un revisor lo va a notar.

El tercero es de tono, y choca con tu propia filosofía. El diseño dice explícitamente "evitar paranoia, generar confianza", pero el "Playbook — Urgencia: INMEDIATA (<24h)" en ROJO hace lo contrario: un escaneo de configuración no debería declararle a nadie una emergencia de menos de un día. Lo mismo con las menciones al art. 197 CP: insinuar responsabilidad penal del empleador a partir de un escaneo puede llevar al trabajador a sobreactuar. Yo bajaría la urgencia y dejaría lo penal solo para evidencia de acceso real (p. ej. una sesión RDP activa no comunicada), no por la mera capacidad.

Y un punto más de fondo, porque están en la misma carpeta: cuidado con la tensión entre este proyecto y MicroBurnout. El Worker Rights Audit dice "inferir el estado del trabajador desde su huella digital es vigilancia y necesita DPIA + información previa". MicroBurnout hace exactamente eso — heatmaps horarios, actividad nocturna, "fatiga digital", ritmo oscilante son señales de comportamiento aunque solo uses metadatos. Como herramienta de autoconocimiento que corre el propio trabajador sobre sí mismo, es legítima. Pero en cuanto se la presentas a RRHH ("demostrar que hay señales previas al colapso"), se convierte en el tipo de perfilado que tu otro proyecto marca en ROJO y que el art. 35 RGPD exigiría con DPIA y transparencia previa. "Metadatos" no lo vuelve no-inferencia: sigue siendo inferir el estado de una persona. Vale la pena que decidas conscientemente cuál de los dos usos es.

En conjunto vas muy bien, y la base legal es de las mejores que he visto en un proyecto así. Lo que más subiría el valor ahora es calibrar el scoring y el tono: paradójicamente, un informe con menos ROJOs pero mejor justificados será mucho más demoledor ante la AEPD o Inspección que uno con 61 hallazgos. Si te sirve, te ayudo a rediseñar la matriz de riesgo (capacidad latente / activa / inventario) o a revisar las heurísticas de los skills con más falsos positivos.
