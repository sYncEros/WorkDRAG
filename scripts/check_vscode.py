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
                print(ext.name)
                print(f"  name:        {data.get('name', '?')}")
                print(f"  publisher:   {data.get('publisher', '?')}")
                print(f"  description: {str(data.get('description', '?'))[:80]}")
                print()
            except Exception as e:
                print(f"{ext.name} — error: {e}")
        else:
            print(f"{ext.name} — sin package.json")