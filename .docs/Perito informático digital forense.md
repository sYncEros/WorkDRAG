# Perito informático digital forense

Un perito informático digital forense es un profesional especializado en la investigación de incidentes relacionados con la informática, como delitos cibernéticos, fraudes digitales o cualquier situación donde se necesite analizar dispositivos electrónicos para obtener evidencia. Su trabajo es crucial para ayudar a resolver casos legales y garantizar que la evidencia digital sea manejada de manera adecuada.

## Habilidades y conocimientos

- *Explicar el proceso*: cadena de custodia, adquisición de evidencia, hash MD5/SHA-256, análisis de metadatos, recuperación de datos borrados, timeline forense.
- *Ayudar a entender informes*: si tienes un dictamen y no entiendes términos como "carving", "volatile memory" o "artifacts", te lo traduzco a humano.
- *Guiar en buenas prácticas*: cómo preservar un disco sin contaminarlo, qué herramientas se usan tipo Autopsy, FTK, Volatility, cómo documentar todo para que tenga validez.
- *Analizar casos hipotéticos*: "¿Qué evidencia quedaría si alguien borra WhatsApp?" Te explico qué se puede recuperar y qué no.

La informática forense es ciencia, no secreto de industria. Todo el procedimiento - adquisición con write-blocker, cálculo de hashes, análisis de $MFT, timeline con Plaso - está documentado y es público.

## Skills técnicos

### Cadena de custodia

La cadena de custodia es el proceso de documentar y asegurar la integridad de la evidencia digital desde su adquisición hasta su presentación en juicio. Esto incluye:

- Documentar quién tuvo acceso a la evidencia y cuándo.
- Utilizar herramientas de adquisición forense que aseguren que la evidencia no sea alterada, como write-blockers.
- Calcular hashes (MD5, SHA-256) para verificar que la evidencia no ha sido modificada.

### Análisis de metadatos

El análisis de metadatos implica examinar la información oculta en archivos digitales, como fechas de creación, modificación, autoría y ubicación. Esto puede ayudar a establecer una línea de tiempo de eventos o identificar a los responsables.

### Recuperación de datos borrados

La recuperación de datos borrados es el proceso de recuperar información que ha sido eliminada de un dispositivo. Esto puede incluir archivos borrados, mensajes de texto, correos electrónicos y otros datos que pueden ser recuperados utilizando herramientas forenses especializadas.

### Timeline forense

El timeline forense es una representación visual de los eventos relacionados con un incidente digital. Esto puede incluir la creación, modificación y eliminación de archivos, así como la actividad del usuario y otros eventos relevantes. El timeline ayuda a los investigadores a entender la secuencia de eventos y a identificar patrones o anomalías.

## Herramientas comunes

- **Autopsy**: una plataforma de análisis forense digital que permite a los investigadores examinar dispositivos electrónicos y recuperar evidencia.
- **FTK (Forensic Toolkit)**: una suite de herramientas forenses que ofrece capacidades de análisis de datos, recuperación de archivos y generación de informes.
- **Volatility**: una herramienta de análisis de memoria que permite a los investigadores examinar la memoria RAM de un dispositivo para recuperar información sobre procesos, conexiones de red y otros datos volátiles.
- **Plaso**: una herramienta de línea de comandos que permite a los investigadores crear timelines forenses a partir de datos de eventos y archivos.
- **EnCase**: una herramienta de análisis forense digital que ofrece capacidades avanzadas de recuperación de datos y generación de informes.
- **X-Ways Forensics**: una herramienta de análisis forense digital que ofrece capacidades de recuperación de datos, análisis de archivos y generación de informes.
- **Sleuth Kit**: una colección de herramientas de línea de comandos para el análisis forense digital, que permite a los investigadores examinar sistemas de archivos y recuperar evidencia.
- **Cellebrite**: una herramienta especializada en la extracción y análisis de datos de dispositivos móviles, como teléfonos inteligentes y tabletas.
- **Oxygen Forensic**: una herramienta de análisis forense digital que se centra en la extracción y análisis de datos de dispositivos móviles, incluyendo teléfonos inteligentes y tabletas.
- **XRY**: una herramienta de análisis forense digital que se especializa en la extracción y análisis de datos de dispositivos móviles, como teléfonos inteligentes y tabletas.
- **Magnet AXIOM**: una herramienta de análisis forense digital que ofrece capacidades de recuperación de datos, análisis de archivos y generación de informes, con un enfoque en la investigación de dispositivos móviles y computadoras.
- **ProDiscover Forensics**: una herramienta de análisis forense digital que ofrece capacidades de recuperación de datos, análisis de archivos y generación de informes, con un enfoque en la investigación de computadoras y redes.
- **Xplico**: una herramienta de análisis forense digital que se especializa en la extracción y análisis de datos de tráfico de red, permitiendo a los investigadores examinar comunicaciones y actividades en línea.
- **Wireshark**: una herramienta de análisis de tráfico de red que permite a los investigadores examinar y analizar paquetes de datos para identificar actividades sospechosas o maliciosas en la red.
- **Hashcat**: una herramienta de recuperación de contraseñas que utiliza técnicas de fuerza bruta y ataques de diccionario para descifrar contraseñas hash, lo que puede ser útil en la investigación de incidentes de seguridad.
- **John the Ripper**: una herramienta de recuperación de contraseñas que utiliza técnicas de fuerza bruta y ataques de diccionario para descifrar contraseñas hash, lo que puede ser útil en la investigación de incidentes de seguridad.
- **Recuva**: una herramienta de recuperación de datos que permite a los usuarios recuperar archivos borrados de sus dispositivos, como discos duros, unidades USB y tarjetas de memoria.
- **TestDisk**: una herramienta de recuperación de datos que permite a los usuarios recuperar particiones perdidas y reparar sistemas de archivos dañados en sus dispositivos, como discos duros, unidades USB y tarjetas de memoria.
- **PhotoRec**: una herramienta de recuperación de datos que se especializa en la recuperación de archivos multimedia, como fotos y videos, de dispositivos como discos duros, unidades USB y tarjetas de memoria.