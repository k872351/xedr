import sys, json, sqlite3
sys.path.insert(0, r"D:\GeRen\web\edr")
from backend import network_awareness as na
c=sqlite3.connect(r"D:\GeRen\web\edr\reports\agents.db")
c.row_factory=sqlite3.Row
rows=c.execute("SELECT etype, summary, detail_json FROM agent_timeline WHERE etype='http_request_etw' ORDER BY ts DESC LIMIT 5").fetchall()
print("http rows", len(rows))
for r in rows:
    d=json.loads(r["detail_json"] or "{}")
    print("---", (r["summary"] or "")[:90])
    print("keys", sorted(d.keys()))
    for k in sorted(d.keys()):
        v=d[k]
        if isinstance(v,(dict,list)):
            print(" ", k, type(v).__name__, str(v)[:180])
        else:
            print(" ", k, repr(str(v)[:180]))
r=na.analyze_network(hours=24, only_new=True, only_external=True, only_http=True, limit=15)
print("\nAPI only_http items", len(r["items"]))
print("protos", Counter:=__import__('collections').Counter(i.get('proto') for i in r['items']))
print("etypes", __import__('collections').Counter(i.get('etype') for i in r['items']))
if r["items"]:
    print("first", {k:r["items"][0].get(k) for k in ("proto","etype","method","url_path","dest_key","process_name")})
r2=na.analyze_network(hours=2, baseline_hours=1, only_new=True, only_external=True, only_http=True, limit=15)
print("hours=2 http items", len(r2["items"]), "stats", r2["stats"])
