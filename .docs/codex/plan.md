# Plan: Recomendaciones fuera del PDF

Separar el contenido accionable del informe PDF y generarlo en un documento aparte reutilizando una sola fuente de verdad en `LegalEngine`. La vía recomendada es añadir recomendaciones estructuradas por categoría en el motor legal, hacer que el PDF muestre solo el resumen legal (sin lista extensa de acciones) y convertir `scripts/generate_recommendations_md.py` en el generador oficial del documento de recomendaciones a partir de los hallazgos actuales.

## **Steps**

1. Revisar y corregir el contrato del motor legal en `c:\WorkDRAG\skills\compliance_engine\legal_engine.py`: `LegalEngine.evaluate()` debe aceptar `recommendation_mode`, `custom_categories` y `custom_risks` porque `main_auto.py` ya los envía. Este paso bloquea el resto porque hoy la firma no coincide con su uso.

2. Añadir una sola fuente de verdad para recomendaciones en `c:\WorkDRAG\skills\compliance_engine\legal_engine.py`: ampliar `COMPLIANCE_RULES` con un campo `recommendations` para las categorías que ya salen en el informe actual y para las entradas que el usuario ya documentó en `c:\WorkDRAG\exports\recomendaciones\TODO (Solution).md`. Mantener el texto orientado a acciones concretas, no explicaciones repetidas. *Depende de 1*.

3. Implementar filtrado real de recomendaciones dentro de `LegalEngine.evaluate()` según modo: `urgente` (solo high/very_high), `completo` (todo), `personalizado` (filtrado por categorías y riesgos). El objetivo es que tanto PDF como documento aparte consuman exactamente la misma lista final. *Depende de 2*.

4. Reducir repetición en el PDF desde `c:\WorkDRAG\core\pdf_exporter.py`: mantener una sección legal breve por issue (riesgo, motivo y referencias) y omitir o resumir las recomendaciones accionables para que no dupliquen el documento aparte. Si se necesita, dejar una nota que remita al anexo/Markdown de recomendaciones. *Depende de 3*.

5. Convertir `c:\WorkDRAG\scripts\generate_recommendations_md.py` en la salida principal del documento aparte: debe leer el último JSON, invocar `LegalEngine.evaluate()` con el mismo filtrado y generar un Markdown limpio, menos narrativo y más útil para checklist. Recomiendo estructura por issue con: categoría, riesgo, motivo breve, acciones y, cuando aplique, “qué desactivar” o “qué solicitar” al empleador. *Depende de 3; puede avanzar en paralelo con 4 una vez 3 esté listo*.

6. Decidir el destino del documento generado y dejarlo estable: preferiblemente `c:\WorkDRAG\exports\recomendaciones\recomendaciones_vulneraciones.md` o una ruta consistente bajo `exports` para que quede junto a las salidas del informe y no mezclado con lógica del proyecto. Incluir limpieza del legacy solo si no rompe el flujo actual. *Depende de 5*.

7. Añadir pruebas automáticas para evitar regresiones: cubrir que `LegalEngine.evaluate()` devuelve `recommendations`, respeta filtros y no rompe los consumidores existentes; cubrir que el generador Markdown produce secciones esperadas y que el PDF ya no repite bloques accionables completos. *Depende de 3 para tests del motor; 4 y 5 para tests de salida*.

8. Validar con un informe real existente en `exports`: regenerar recomendaciones usando el último `audit.json`, comprobar que salen las categorías actuales del caso del usuario y contrastar que el PDF queda más corto y menos recargado. *Depende de 4 y 5*.

## **Fases sugeridas**

1. Fase 1 — Motor legal: pasos 1, 2 y 3.
2. Fase 2 — Salidas: pasos 4, 5 y 6.
3. Fase 3 — Verificación: pasos 7 y 8.

## **Relevant files**

- `c:\WorkDRAG\skills\compliance_engine\legal_engine.py` — fuente de verdad de `COMPLIANCE_RULES`, `LEGAL_FRAMEWORK` y `LegalEngine.evaluate()`; aquí debe vivir la automatización de recomendaciones y el filtrado.
- `c:\WorkDRAG\core\pdf_exporter.py` — `build_legal_section()` y `export_pdf()`; aquí se aligera el PDF para evitar duplicidad visual.
- `c:\WorkDRAG\scripts\generate_recommendations_md.py` — generador del documento aparte; debe pasar de “best effort” a salida oficial basada en el mismo motor legal.
- `c:\WorkDRAG\main_auto.py` — ya expone `recommendation_mode`, `recommendation_categories` y `recommendation_risks`; habrá que alinear la llamada con la firma real del motor y, si hace falta, disparar también la generación del documento aparte.
- `c:\WorkDRAG\exports\recomendaciones\TODO (Solution).md` — referencia manual para migrar el contenido ya trabajado a reglas automatizadas por categoría, sin perder las 8 primeras que ya están hechas.
- `c:\WorkDRAG\tests\test_api.py` — referencia para los modos de recomendación que ya estaban previstos; útil para adaptar o extender cobertura.
- `c:\WorkDRAG\tests\test_audit_engine.py` — base de tests del flujo de auditoría; probablemente habrá que añadir casos para salidas legales/recomendaciones.

## **Verification**

1. Ejecutar la suite de tests existente y añadir casos para `LegalEngine.evaluate()` con combinaciones de `completo`, `urgente` y `personalizado`.

2. Generar un documento de recomendaciones a partir del último `exports/**/audit*.json` y comprobar que contiene recomendaciones para las categorías ya presentes en el caso real.

3. Regenerar el PDF con ese mismo informe y verificar que la sección legal no duplica literalmente las acciones del documento de recomendaciones.

4. Comparar manualmente el nuevo Markdown con `TODO (Solution).md` para asegurar que las 8 primeras recomendaciones ya trabajadas siguen reflejadas y que las categorías actuales quedan cubiertas.

5. Comprobar que si un issue no tiene recomendaciones específicas todavía, la salida usa un fallback claro y no rompe ni el PDF ni el Markdown.

## **Decisions**

- Alcance incluido ahora: automatizar recomendaciones para lo que el programa ya detecta hoy y separar esas recomendaciones del PDF.

- Alcance excluido por ahora: crear nuevos detectores como `addon_audit` o `clipboard_watcher` y rediseñar completamente el informe PDF.

- Recomendación de arquitectura: una sola fuente de verdad en `LegalEngine`, no en el PDF ni en el script Markdown ni en el TODO manual.

- Recomendación editorial: el documento aparte debe ser más checklist y menos ensayo; el PDF debe conservar el valor probatorio/resumen.

## **Further Considerations**

1. Si se quiere “dejar el TODO listo” sin perder tu trabajo manual, la implementación puede migrar primero las categorías que aparecen en el último `audit.json` y luego completar el resto del catálogo legal.

2. Conviene normalizar el vocabulario de riesgo legal (`low`, `medium`, `medium-high`, `high`, `very_high`) porque hoy convive con valores como `yellow` y `orange` en algunas reglas; eso puede afectar ordenado y filtros.

3. Si el documento aparte va a usarse como checklist operativa, puede merecer una estructura adicional por tipo de acción: “qué desactivar”, “qué documentar”, “qué solicitar al DPO/IT”.
