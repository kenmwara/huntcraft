#!/usr/bin/env python3
"""HuntCraft local review page: read, edit, re-run and publish a generated draft before members see it.

    python tools/review.py            # then open http://127.0.0.1:8770

Local only (127.0.0.1). Edits save to private/_drafts/<slug>/guide.json; the deterministic leak check re-runs on every
save. "Re-run" sends one query through your own Range MCP sign-in (the generator's read-only claude -p path). Publish
needs every flag reviewed and the three checks ticked; it copies the draft into hunts/<slug>/, writes the registry
clearance record and runs build.py. Deploying stays a separate command.
"""
import argparse, json, pathlib, secrets, shutil, subprocess, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import generate as G  # noqa: E402  (one leak rule, one claude -p path)

DRAFTS, HUNTS, PRIVATE = ROOT / "private" / "_drafts", ROOT / "hunts", ROOT / "private"
TOKEN = secrets.token_urlsafe(24)   # POSTs need it in a header: a web page elsewhere can't send one to localhost
TAG_OLD = {"Not reviewed": "Confirmed"}


def rj(p, default=None):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default


def wj(p, obj):
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def entry_of(slug):
    return next((e for e in G.load_registry() if e["slug"] == slug), None)


def leaks_now(slug, guide):
    """The deterministic leak check over the current text, per flag: terms and the fields holding them."""
    solve = rj(DRAFTS / slug / "solve.json", {})
    o = solve.get("orientation") or {}
    e = entry_of(slug) or {}
    ctx = list(o.get("tables") or []) + list(o.get("hosts") or []) + [e.get("workspace"), e.get("workspace_guid")]
    out, earlier = {}, []
    for f in guide.get("flags", []):
        hits, info = G.leak_report(f, earlier, ctx)
        # info only: project what you filter (member review 1)
        out[f["flag"]] = {"terms": hits, "fields": G.leak_fields(f, hits), "info": list(info) + G.project_gaps(f)}
        earlier.append((f.get("reveal") or {}).get("answer"))
    return out


def load(slug):
    d = DRAFTS / slug
    meta = rj(d / "draft.meta.json", {})
    for v in (meta.get("flags") or {}).values():
        v["tag"] = TAG_OLD.get(v.get("tag"), v.get("tag"))
    guide = rj(d / "guide.json", {})
    e = entry_of(slug) or {}
    return {"slug": slug, "guide": guide, "meta": meta, "leaks": leaks_now(slug, guide),
            "registry": {k: e.get(k) for k in ("title", "status", "clearance")},
            "published_exists": (HUNTS / slug / "guide.json").exists(),
            "hunt_json": (HUNTS / slug / "hunt.json").exists()}


def rerun(slug, query):
    e = entry_of(slug)
    if not e:
        return {"error": "hunt not in the registry"}
    G.ARGS = SimpleNamespace(range_config=None, model=None, call_timeout=300)
    G.MODE = "deferred"
    _, trace = G.run_claude(
        f"Workspace GUID: {e['workspace_guid']}\nRun this query once with la_query exactly as written (timespan "
        f"\"all\", max_rows 50). Do not change it and do not analyse. Then reply \"done\".\n\n{query}",
        G.SOLVER_SYSTEM, tools=True, max_turns=4, label="review rerun")
    runs = [t for t in trace if t["tool"] == "la_query"]
    if not runs:
        return {"error": "the query was not run (is the Range MCP signed in?)"}
    t = runs[-1]
    return {"status": t.get("status"), "rows": t.get("rows_returned"), "sample": t.get("sample"),
            "error": t.get("error"), "at": time.strftime("%H:%M")}


def publish(slug, body):
    e = entry_of(slug)
    meta = rj(DRAFTS / slug / "draft.meta.json", {})
    guide = rj(DRAFTS / slug / "guide.json", {})
    if not e:
        return 400, {"error": "Add this hunt to hunts/registry.json first."}
    if e["status"] == "live":
        return 400, {"error": "This is the live hunt. It can't be published until it closes."}
    names = [f["flag"] for f in guide.get("flags", [])]
    unrev = [n for n in names if not (meta.get("flags", {}).get(n) or {}).get("reviewed")]
    if unrev:
        return 400, {"error": f"Review every flag first. Still open: {', '.join(unrev)}"}
    if not all(body.get("checks") or [False]) or len(body.get("checks") or []) != 3:
        return 400, {"error": "Tick all three checks before publishing."}
    leaks = {k: v for k, v in leaks_now(slug, guide).items() if v["terms"]}
    leaks.update({n: 1 for n, m in (meta.get("flags") or {}).items()
                  if n in names and m.get("model_leak") and not m.get("model_cleared")})
    if leaks:
        return 400, {"error": f"The leak check still finds the answer in: {', '.join(leaks)}"}
    dest = HUNTS / slug
    if not (dest / "hunt.json").exists():
        return 400, {"error": f"hunts/{slug}/hunt.json is missing (title, tables, host, workspace). Add it, then publish."}
    if (dest / "guide.json").exists() and not body.get("replace"):
        return 409, {"error": "A published guide already exists for this hunt.", "confirm_replace": True}
    if (dest / "guide.json").exists():
        shutil.copy2(dest / "guide.json", dest / f"guide.replaced-{time.strftime('%Y%m%d-%H%M%S')}.json")
    out = dict(guide)
    out.pop("note", None)
    wj(dest / "guide.json", out)
    (PRIVATE / slug).mkdir(parents=True, exist_ok=True)               # the solve trail stays out of the public repo
    shutil.copy2(DRAFTS / slug / "solve.json", PRIVATE / slug / "solve.generated.json")
    reg = G.load_registry()
    for r in reg:
        if r["slug"] == slug:
            r["clearance"] = {"date": time.strftime("%Y-%m-%d"),
                              "scope": (body.get("scope") or "public instruction manual").strip()}
    wj(HUNTS / "registry.json", reg)
    b = subprocess.run([sys.executable, str(ROOT / "build.py")], capture_output=True, text=True, cwd=ROOT)
    return 200, {"ok": b.returncode == 0, "build": (b.stdout + b.stderr)[-600:],
                 "next": "npx wrangler pages deploy site --project-name huntcraft --branch main"}


STATUSES = ("new", "accepted", "declined", "done")
UUID = __import__("re").compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def d1(sql):
    """Run one statement on the live hunt_requests table through wrangler (your own Cloudflare sign-in)."""
    r = subprocess.run(f'npx wrangler d1 execute huntcraft-requests --remote --json --command "{sql}"',
                       shell=True, capture_output=True, text=True, cwd=ROOT / "worker" / "request", encoding="utf-8")
    if r.returncode:
        return {"error": (r.stderr or r.stdout)[-400:]}
    return {"rows": json.loads(r.stdout)[0].get("results", [])}


def requests_list():
    return d1("SELECT id, created_at, name, link, workspace, questions, contact, status "
              "FROM hunt_requests ORDER BY created_at DESC LIMIT 200")


def request_status(body):
    rid, st = str(body.get("id") or ""), body.get("status")
    if not UUID.match(rid) or st not in STATUSES:              # both checked, so nothing user-typed reaches the SQL
        return 400, {"error": "bad id or status"}
    out = d1(f"UPDATE hunt_requests SET status='{st}' WHERE id='{rid}'")
    return (500 if "error" in out else 200), out


class H(BaseHTTPRequestHandler):
    def send(self, code, obj, ctype="application/json"):
        data = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def slug(self, prefix):
        s = self.path[len(prefix):].split("?")[0].strip("/")
        if not s or "/" in s or "\\" in s or s.startswith(".") or not (DRAFTS / s).is_dir():
            return None
        return s

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            page = (HERE / "review.html").read_text(encoding="utf-8").replace("__TOKEN__", TOKEN)
            return self.send(200, page.encode("utf-8"), "text/html")
        if self.path == "/api/drafts":
            return self.send(200, sorted(p.name for p in DRAFTS.iterdir() if p.is_dir() and (p / "guide.json").exists())
                             if DRAFTS.exists() else [])
        if self.path == "/api/requests":
            return self.send(200, requests_list())
        if self.path.startswith("/api/draft/"):
            s = self.slug("/api/draft/")
            return self.send(200, load(s)) if s else self.send(404, {"error": "no such draft"})
        self.send(404, {"error": "not found"})

    def do_POST(self):
        if self.headers.get("X-Review-Token") != TOKEN:
            return self.send(403, {"error": "bad token"})
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if self.path == "/api/request-status":
            return self.send(*request_status(body))
        for prefix in ("/api/save/", "/api/rerun/", "/api/publish/"):
            if self.path.startswith(prefix):
                s = self.slug(prefix)
                if not s:
                    return self.send(404, {"error": "no such draft"})
                if prefix == "/api/save/":
                    d = DRAFTS / s
                    wj(d / "guide.json", body["guide"])
                    meta = rj(d / "draft.meta.json", {})
                    for name, st in (body.get("state") or {}).items():
                        m = meta.setdefault("flags", {}).setdefault(name, {})
                        m["reviewed"], m["model_cleared"] = bool(st.get("reviewed")), bool(st.get("model_cleared"))
                    wj(d / "draft.meta.json", meta)
                    return self.send(200, {"ok": True, "leaks": leaks_now(s, body["guide"]), "at": time.strftime("%H:%M:%S")})
                if prefix == "/api/rerun/":
                    return self.send(200, rerun(s, body.get("query") or ""))
                code, obj = publish(s, body)
                return self.send(code, obj)
        self.send(404, {"error": "not found"})

    def log_message(self, fmt, *a):
        pass


def selftest():
    g = {"flags": [{"flag": "A", "steps": [{"look_for": "the IP 1.2.3.4"}], "reveal": {"answer": "1.2.3.4"}},
                   {"flag": "B", "steps": [{"query": "X | where RemoteIP == \"1.2.3.4\""}], "reveal": {"answer": "x.exe"}}]}
    DRAFTS.mkdir(parents=True, exist_ok=True)
    lk = leaks_now("__none__", g)
    assert lk["A"]["fields"] == ["steps[0].look_for"] and not lk["B"]["terms"]   # an earlier flag's answer is fine
    assert request_status({"id": "x' OR 1=1 --", "status": "done"})[0] == 400
    assert request_status({"id": "9012adca-1bf5-4ea6-9dd7-9f81127f77f0", "status": "pwned"})[0] == 400
    print("review selftest ok")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8770)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); sys.exit()
    print(f"HuntCraft review: http://127.0.0.1:{a.port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()
