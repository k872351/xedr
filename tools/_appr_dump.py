import sqlite3
c=sqlite3.connect(r"D:\GeRen\web\edr\reports\agents.db")
c.row_factory=sqlite3.Row
try:
  rows=c.execute("SELECT id,agent_id,action,status,requested_by,created_at,reason FROM response_approvals ORDER BY created_at DESC LIMIT 15").fetchall()
  print("approvals", len(rows))
  for r in rows: print(dict(r))
except Exception as e:
  print("err", e)
