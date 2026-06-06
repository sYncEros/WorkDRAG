# Exploración WorkDRAG - Flujo de Recomendaciones y PDF

## Estado Actual de Investigación

### Flujo Detectado

1. **Entrada**: Auditoría de skills → hallazgos técnicos en `AuditFinding`
2. **Motor Legal**: `LegalEngine.evaluate()` vincula hallazgos a reglas COMPLIANCE_RULES
3. **Salida esperada**: Issues con recomendaciones + JSON + PDF

### HUECO CRÍTICO ENCONTRADO

**LegalEngine.evaluate() NO genera recomendaciones**

- Devuelve issues con: category, issue, legal_risk, reason, references
- NO incluye campo "recommendations"
- Pero pdf_exporter.py y generate_recommendations_md.py ESPERAN issue["recommendations"]
- Esto significa las recomendaciones nunca llegan al PDF/MD actualmente

### Archivos Key Identificados

- [core/audit_engine.py](c:\WorkDRAG\core\audit_engine.py): AuditFinding dataclass, export_json()
- [skills/compliance_engine/legal_engine.py](c:\WorkDRAG\skills\compliance_engine\legal_engine.py): COMPLIANCE_RULES, evaluate()
- [core/pdf_exporter.py](c:\WorkDRAG\core\pdf_exporter.py): build_legal_section()
- [scripts/generate_recommendations_md.py](c:\WorkDRAG\scripts\generate_recommendations_md.py): genera MD con recomendaciones
- [main_auto.py](c:\WorkDRAG\main_auto.py): orquestador con parámetros recommendation_mode/categories/risks

### Lógica Repetitiva Detectada

- Cada skill genera `AuditFinding` con los 8 campos standard (skill, category, title, description, risk_level, technical_risk, legal_risk, what_it_is, what_it_is_not, raw_data)
- COMPLIANCE_RULES tiene ~60+ reglas por categoría de hallazgo
- Las reglas NO varían: siempre issue + reason + references (3 campos max)

### Patrón de Filtrado Detectado

main_auto.py acepta:

- `recommendation_mode`: "urgente", "completo", "personalizado"
- `recommendation_categories`: lista de categorías a filtrar
- `recommendation_risks`: ["low", "medium", "medium-high", "high", "very_high"]
Pero evaluate() no implementa estos parámetros aún.

## Próximos Pasos Clave

1. Implementar recommendations en COMPLIANCE_RULES (categoría-específicas)
2. Agregar parámetros a evaluate() para filtrado
3. Generar recommendations en LegalEngine.evaluate()
4. Verificar que PDF/MD reciban las recomendaciones
