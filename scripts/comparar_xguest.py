import sys, json, glob
sys.path.insert(0, r'C:\WorkDRAG')
from pathlib import Path

files = sorted(
    glob.glob(r'C:\WorkDRAG\exports\**\audit.json', recursive=True),
    key=lambda f: Path(f).stat().st_mtime
)

print(f"Auditorías disponibles: {len(files)}\n")

for filepath in files:
    data = json.loads(Path(filepath).read_text(encoding='utf-8'))
    fecha = data.get('generated_at', '?')[:16].replace('T', ' ')
    total = data.get('total_findings', 0)
    
    # Buscar XGuest en cualquier hallazgo
    xguest_refs = []
    for f in data.get('findings', []):
        raw = json.dumps(f.get('raw_data', {}))
        if 'XGuest' in raw or 'xguest' in raw.lower():
            xguest_refs.append(f.get('category', '?'))
    
    # Buscar Local-Admin password change
    local_admin_pwd = None
    for f in data.get('findings', []):
        raw = json.dumps(f.get('raw_data', {}))
        if 'Local-Admin' in raw and '1777' in raw:
            local_admin_pwd = 'detectado'
    
    print(f"{fecha} | {total} hallazgos | XGuest: {xguest_refs or 'no detectado'} | Local-Admin pwd: {local_admin_pwd or '-'}")