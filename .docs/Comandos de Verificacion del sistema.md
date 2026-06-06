# Comandos de Verificacion del sistema

## Skills disponibles y archivos asociados

```bash
C:\WorkDRAG\python_portable\python.exe -c "
import os
skills_dir = 'skills'
for skill in sorted(os.listdir(skills_dir)):
    skill_path = os.path.join(skills_dir, skill)
    if os.path.isdir(skill_path):
        files = os.listdir(skill_path)
        py_files = [f for f in files if f.endswith('.py')]
        print(f'{skill}: {py_files}')
"
```

## Categorías de hallazgos por skill

```bash
C:\WorkDRAG\python_portable\python.exe -c "
import json, glob, os

all_cats = {}
for f in glob.glob('exports/**/*.json', recursive=True):
    try:
        data = json.load(open(f, encoding='utf-8'))
        for finding in data.get('findings', []):
            skill = finding.get('skill', 'unknown')
            cat = finding.get('category', '')
            if skill not in all_cats:
                all_cats[skill] = set()
            all_cats[skill].add(cat)
    except:
        pass

for skill in sorted(all_cats):
    print(f'\n{skill}:')
    for cat in sorted(all_cats[skill]):
        print(f'  - {cat}')
"
```

## Ejecución de un skill específico

```bash
cd C:\WorkDRAG
C:\WorkDRAG\python_portable\python.exe -c "
from core.audit_engine import AuditEngine
from skills.onedrive_mapper.onedrive_mapper import OneDriveMapper
engine = AuditEngine()
skill = OneDriveMapper(engine)
skill.run()

print(f'Hallazgos: {len(engine.findings)}')
for f in engine.findings:
    print(f'  - {f.category} | {f.risk_level} | {f.title}')
"
```

## VSCode — Listado de extensiones con telemetría

### Extensiones de VSCode con telemetría detectada

```bash
C:\WorkDRAG\python_portable\python.exe -c "
import sys, os
sys.path.insert(0, r'C:\WorkDRAG')
from pathlib import Path
vscode_path = Path(os.environ.get('USERPROFILE', '')) / '.vscode/extensions'
for ext in sorted(vscode_path.iterdir()):
    if ext.is_dir():
        print(ext.name)
"
```

### Extensiones con nombre UUID y posible telemetría

```bash
C:\WorkDRAG\python_portable\python.exe -c "
import sys, os, json
sys.path.insert(0, r'C:\WorkDRAG')
from pathlib import Path

vscode_path = Path(os.environ.get('USERPROFILE', '')) / '.vscode/extensions'
for ext in sorted(vscode_path.iterdir()):
    if ext.is_dir() and ext.name.startswith('.'):
        pkg = ext / 'package.json'
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text(encoding='utf-8', errors='ignore'))
                print(f'{ext.name}')
                print(f'  name:        {data.get(\"name\", \"?\")}')
                print(f'  publisher:   {data.get(\"publisher\", \"?\")}')
                print(f'  description: {data.get(\"description\", \"?\")[:80]}')
                print()
            except:
                print(f'{ext.name} — sin package.json legible')
        else:
            print(f'{ext.name} — sin package.json')
"
```

## GPO — Listado de políticas de grupo aplicadas

```bash
cd C:\WorkDRAG
C:\WorkDRAG\python_portable\python.exe -c "
import sys, winreg
sys.path.insert(0, r'C:\WorkDRAG')

# Extensiones forzadas por GPO
print('=== EXTENSIONES FORZADAS GPO ===')
for hive, hname in [(winreg.HKEY_LOCAL_MACHINE, 'HKLM'), (winreg.HKEY_CURRENT_USER, 'HKCU')]:
    for browser, key_path in [('Chrome', r'SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist'), ('Edge', r'SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist')]:
        try:
            key = winreg.OpenKey(hive, key_path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    print(f'  {browser} {hname}: {value}')
                    i += 1
                except OSError:
                    break
        except OSError:
            pass
"
```

## Add-ins de Office — Listado de complementos instalados

```bash
C:\WorkDRAG\python_portable\python.exe -c "
import sys, winreg
sys.path.insert(0, r'C:\WorkDRAG')

print('=== ADD-INS OFFICE SIEMPRE ACTIVOS (LoadBehavior 3 o 9) ===')
keys = [r'SOFTWARE\Microsoft\Office\Outlook\Addins', r'SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins']
for key_path in keys:
    for hive, hname in [(winreg.HKEY_LOCAL_MACHINE, 'HKLM'), (winreg.HKEY_CURRENT_USER, 'HKCU')]:
        try:
            key = winreg.OpenKey(hive, key_path)
            i = 0
            while True:
                try:
                    addin_name = winreg.EnumKey(key, i)
                    addin_key = winreg.OpenKey(key, addin_name)
                    try:
                        lb, _ = winreg.QueryValueEx(addin_key, 'LoadBehavior')
                        if lb in (3, 9):
                            try:
                                desc, _ = winreg.QueryValueEx(addin_key, 'Description')
                            except:
                                desc = ''
                            print(f'  [{hname}] {addin_name} — {desc}')
                    except OSError:
                        pass
                    i += 1
                except OSError:
                    break
        except OSError:
            pass
"
```

## Encontrar error

```bash
C:\WorkDRAG\python_portable\python.exe -c "
import ast, sys
with open(r'C:\WorkDRAG\skills\addon_audit\addon_scanner.py', 'r', encoding='utf-8') as f:
    source = f.read()
try:
    ast.parse(source)
    print('Sintaxis OK')
except SyntaxError as e:
    print(f'Error en linea {e.lineno}: {e.msg}')
    lines = source.split(chr(10))
    for i in range(max(0, e.lineno-5), min(len(lines), e.lineno+3)):
        print(f'{i+1}: {lines[i]}')
"
```
