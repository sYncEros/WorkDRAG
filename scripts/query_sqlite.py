import sqlite3

db_path = r'C:\WorkDRAG\evidence\audit.db'
conn = sqlite3.connect(db_path)

print('=== SESIONES EN BASE DE DATOS ===')
sessions = conn.execute('SELECT id, started_at, total_findings, max_risk FROM audit_sessions ORDER BY started_at').fetchall()
for s in sessions:
    print(f'  ID:{s[0]} | {str(s[1])[:16]} | {s[2]} hallazgos | {s[3]}')
print(f'Total: {len(sessions)}')

print('\n=== XGUEST EN BD ===')
rows = conn.execute("SELECT timestamp, title FROM findings WHERE raw_data LIKE '%XGuest%' ORDER BY timestamp").fetchall()
for r in rows:
    print(f'  {str(r[0])[:16]} | {r[1][:60]}')

print('\n=== LOCAL-ADMIN PWD EN BD ===')
rows2 = conn.execute("SELECT timestamp, title FROM findings WHERE raw_data LIKE '%Local-Admin%' AND raw_data LIKE '%1777%' ORDER BY timestamp").fetchall()
for r in rows2:
    print(f'  {str(r[0])[:16]} | {r[1][:60]}')

conn.close()
