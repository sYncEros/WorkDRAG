# test_skill.py — uso: edita SKILL_CLASS y SKILL_MODULE
import sys
sys.path.insert(0, r'C:\WorkDRAG')

from core.audit_engine import AuditEngine
from skills.service_hardener.service_hardener import ServiceHardener  # cambia esto

engine = AuditEngine()
ServiceHardener(engine).run()  # cambia esto

print(f'\nHallazgos: {len(engine.findings)}')
for f in engine.findings:
    print(f'  - {f.category} | {f.risk_level} | {f.title}')