# Refactrización - Clean Code

## Skill: Identity Audit

Empezamos por identity_audit que es el más grande y el más crítico. El plan siguiendo Single Responsibility + Clean Code:

```bash

textskills/identity_audit/
│
├── __init__.py
├── identity_scanner.py        ← orquestador puro (~80 líneas)
├── account_profiler.py        ← ya existe ✅
├── models.py                  ← dataclasses compartidas
├── session_monitor.py         ← _check_active_sessions
│                                _check_remote_sessions
│
├── credential_inspector.py    ← _check_stored_credentials
├── privilege_analyzer.py      ← _check_admin_group   
│                                _check_local_accounts           
│                                _check_logon_rights 
│                                _check_service_accounts
│                                _check_privileged_processes
│                                                           
└── finding_builder.py         ← construcción de AuditFinding 
                                 (elimina el acoplamiento al engine)
```

Cada archivo: una responsabilidad, menos de 150 líneas, sin imports cruzados innecesarios.

### Prompt exacto

Refactoriza skills/identity_audit/ siguiendo estas reglas estrictas:

1. Single Responsibility: cada archivo tiene UNA responsabilidad
2. Máximo 150 líneas por archivo
3. identity_scanner.py es el orquestador — solo llama a los módulos, no implementa lógica
4. Crea models.py con dataclasses compartidas entre módulos
5. Extrae session_monitor.py, credential_inspector.py, privilege_analyzer.py, finding_builder.py
6. account_profiler.py ya existe — no lo toques
7. Todos los métodos privados van al módulo correspondiente
8. Los imports entre módulos solo hacia abajo — nunca circulares
9. Cada módulo tiene docstring explicando su responsabilidad única
10. Los timeouts de PowerShell: mínimo 30s para comandos WMI, 20s para el resto
11. Mantén exactamente el mismo comportamiento externo — mismos hallazgos, mismos campos
12. Verifica ejecutando: python -c "from skills.identity_audit.identity_scanner import IdentityAudit; print('OK')"
13. Después ejecuta main.py y confirma que identity sigue produciendo los mismos hallazgos

---

