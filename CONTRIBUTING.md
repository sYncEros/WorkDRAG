# Guía de contribución

Gracias por contribuir a `worker-rights-agent`.

## Requisitos previos

- Windows (el escaneo usa registro y utilidades nativas)
- Python 3.12+
- Entorno virtual recomendado

## Flujo recomendado

1. Crea una rama descriptiva (`feature/...`, `fix/...`).
2. Instala dependencias desde `requirements.txt`.
3. Realiza cambios pequeños y verificables.
4. Mantén comentarios y docstrings en español.
5. Actualiza documentación si cambias comportamiento.
6. Abre PR con descripción clara del problema y la solución.

## Estilo de código

- Mantener nombres de símbolos existentes salvo necesidad real.
- Preferir funciones pequeñas y legibles.
- Capturar excepciones específicas cuando sea posible.
- Evitar cambios cosméticos no relacionados.

## Documentación obligatoria

Si modificas cualquiera de estos módulos, actualiza también su ficha en `.docs/modules/`:

- `main.py`
- `core/audit_engine.py`
- `core/pdf_exporter.py`
- `skills/compliance_engine/legal_engine.py`
- `skills/mdm_audit/mdm_scanner.py`
- `skills/persistence_audit/persistence_scanner.py`
- `skills/surveillance_audit/surveillance_scanner.py`

## Formato de commits (sugerido)

- `docs: ...`
- `feat: ...`
- `fix: ...`
- `refactor: ...`

## Qué incluir en una PR

- Contexto del cambio
- Riesgos y limitaciones
- Evidencia de validación (salida de ejecución o lint)
- Impacto en exportaciones (`json`/`pdf`) si aplica

## Seguridad y ética

Este proyecto es de auditoría defensiva y transparencia técnica.

No se aceptan contribuciones orientadas a:

- intrusión,
- bypass de controles corporativos,
- extracción no autorizada de datos,
- comportamiento ofensivo.
