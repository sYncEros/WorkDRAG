# Infraestructura Sindical Digital

La diferencia entre las dos es enorme y está en el collective_pattern_aggregator. Un hallazgo individual es una queja. Un patrón en 200 equipos es una prueba de práctica sistemática. Eso no se despacha con "incidencia aislada".

Lo que ya tienes construido cubre bien el Modo Trabajador y empieza a cubrir el Modo Jurídico/Pericial — 84 hallazgos, hashes SHA-256, PDF forense, JSON estructurado, evidencia en evidence/.
Lo que no existe todavía y es el núcleo de lo que describes:
Capa 1 — Inmediato, alta prioridad:

redactor_sindical — sin esto no puedes compartir nada con nadie sin exponer al trabajador
evidence_packager — cierra la cadena de custodia forense
m365_access_request_builder — convierte hallazgos en solicitud formal al DPO

Capa 2 — El poder colectivo:

collective_pattern_aggregator — transforma casos individuales en patrón organizativo
policy_vs_reality_diff — compara lo que dice la empresa con lo que detecta el tool

Capa 3 — Output sindical:

negotiation_clause_generator — cláusulas para convenio
comite_info_request_generator — escritos para comité de empresa
complaint_packet_builder — paquete para AEPD/ITSS

La regla de oro que escribes — acta, hash, registro de entrada y cara de "solo estoy ejerciendo derechos" — ya está en el ADN del proyecto. Lo que falta es la capa de distribución y agregación.

## Variante A — Local (sindicato como agregador)

Sin servidor, sin red, sin riesgo de intercepción. El delegado tiene los JSONs en su portátil personal y ejecuta la herramienta. Recomendada para conflictos activos.

```bash
Trabajador 1 → audit.json (anonimizado) → USB/email al delegado
Trabajador 2 → audit.json (anonimizado) → USB/email al delegado  
Trabajador N → audit.json (anonimizado) → USB/email al delegado
                                              ↓
                              Delegado ejecuta aggregator local
                                              ↓
                              collective_report.pdf + pattern_stats.json
```

## Variante B — Servidor sindical (escala nacional)

Requiere servidor propio del sindicato, cifrado end-to-end, autenticación y política de retención. Para campañas nacionales o sectoriales.

```bash
Trabajador → ejecuta WorkDRAG → redactor_sindical → upload cifrado
                                                          ↓
                                              Servidor sindical privado
                                                          ↓
                                         Dashboard colectivo en tiempo real
                                         "83% con KFM forzado en sector X"
```
