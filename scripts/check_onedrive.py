import sys, json, glob
sys.path.insert(0, r'C:\WorkDRAG')
from pathlib import Path

files = sorted(
    glob.glob(r'C:\WorkDRAG\exports\**\audit.json', recursive=True),
    key=lambda f: Path(f).stat().st_mtime,
    reverse=True
)
data = json.loads(Path(files[0]).read_text(encoding='utf-8'))

for f in data['findings']:
    if f['category'] == 'onedrive_folder_map':
        print(f"Total: {len(f['raw_data']['redirected_folders'])} carpetas\n")
        for folder in f['raw_data']['redirected_folders']:
            print(f"  {folder['shell_name']:45} → {folder['path']}")
            print(f"  Tamaño: {folder['size_human']}\n")