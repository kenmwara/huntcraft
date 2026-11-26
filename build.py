#!/usr/bin/env python3
"""Build the member site from each hunt folder. Run: python build.py

Writes site/data.js (meta allowlist + guides with no answers in them), site/reveals/<slug>/f<N>.json (answer + why,
fetched only when a member clicks Reveal or gets a Check right), site/knowledge/*.html (the knowledge .md files in
the site's own design) and site/404.html. Refuses any hunt the registry marks live or that has no clearance record.
"""
import hashlib, json, pathlib, re, shutil, subprocess, sys
import markdown

ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(ROOT / "tools"))
from generate import defender_url, is_unordered, norm, shuffle_choices  # one rule shared with the generator

HUNTS, SITE, KNOW = ROOT / "hunts", ROOT / "site", ROOT / "knowledge"
REG = {e["slug"]: e for e in json.loads((HUNTS / "registry.json").read_text(encoding="utf-8"))}
# what a member's page needs, nothing more (no internal notes, no subscription or resource group)
META_KEYS = ("slug", "title", "points", "flag_count", "host", "tables", "tenant_id", "incident_window_utc")
FREE = re.compile(r"sentence|reasoning", re.I)
# Round 8 (Ken, 26 Nov): the hunt authors' credit, worded by them. One string for every page so it can't drift.
HUNT_CREDIT = "Hunt content by SancLogic / the Cyber Range threat hunt team"
FOOTER_CREDIT = f"{HUNT_CREDIT}. Manuals by Ken Kariuki. Built on the Cyber Range MCP. Independent, not affiliated."
CREDIT_SPAN = f'<span class="credit">{FOOTER_CREDIT}</span>'
NAMES_OK = {"Ken Kariuki", "SancLogic"}   # the only names allowed after "by" anywhere in the built site


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def is_free_text(r):
    return r.get("type") != "multiple_choice" and bool(FREE.search(r.get("format") or ""))


def build_hunt(d):
    slug, entry = d.name, REG.get(d.name)
    if not entry:
        print(f"REFUSED {slug}: not in hunts/registry.json"); return None, {}
    if entry["status"] == "live":
        print(f"skipped {slug}: registry says live"); return None, {}
    if not entry.get("clearance"):
        print(f"REFUSED {slug}: no clearance record in hunts/registry.json (when publishing was cleared, and its scope)")
        return None, {}
    if not entry.get("credit"):
        print(f"REFUSED {slug}: no credit in hunts/registry.json (who made this hunt)"); return None, {}
    hj, gj = d / "hunt.json", d / "guide.json"
    if not (hj.exists() and gj.exists()):
        return None, {}
    full = json.loads(hj.read_text(encoding="utf-8"))
    meta = {k: full[k] for k in META_KEYS if k in full}
    ws = full.get("workspace") or {}
    meta["workspace"] = {"name": ws.get("name"), "guid": ws.get("guid")}
    meta["credit"] = entry["credit"]
    tid = meta.get("tenant_id")

    guide = json.loads(gj.read_text(encoding="utf-8"))
    o = guide.get("orientation") or {}
    if o.get("query"):
        o["defender_url"] = defender_url(o["query"], tid)
    reveals = {}
    for i, f in enumerate(guide.get("flags", [])):
        for st in f.get("steps", []):
            q = st.get("query") or ""
            if q.strip() and not q.strip().startswith("("):
                st["defender_url"] = defender_url(q, tid)
        r = f.get("reveal") or {}
        unord = is_unordered(r)
        shipped = {k: r[k] for k in ("type", "format") if r.get(k)}
        shipped["unordered"] = unord
        if r.get("choices"):
            shipped["choices"] = shuffle_choices(r["choices"], f"{slug}|{f['flag']}")
        if not is_free_text(r):
            salt = f"{slug}|{i}|"
            shipped["salt"] = salt
            shipped["check"] = sorted({sha(salt + norm(a, unord)) for a in [r.get("answer")] + list(r.get("accept") or [])})
        f["reveal"] = shipped
        reveals[f"f{i}.json"] = {"answer": r.get("answer"), "why": r.get("why")}
    return {"meta": meta, "guide": guide}, reveals


# ---------------------------------------------------------------- pages in the site's own design

PAGE_CSS = re.search(r"<style>(.*?)</style>", (SITE / "index.html").read_text(encoding="utf-8"), re.S).group(1)
ARTICLE_CSS = """
article{padding:0;max-width:760px}
article h1{font-size:28px;line-height:1.25;letter-spacing:-.02em;margin:18px 0 12px;text-wrap:balance}
article h2{font-size:19px;margin:30px 0 8px;letter-spacing:-.01em;text-wrap:balance}
article p,article li{max-width:72ch}
article table{border-collapse:collapse;font-size:14px;margin:10px 0 16px;display:block;overflow-x:auto}
article th,article td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
article th{background:var(--surface-2)}
article code{font-family:"JetBrains Mono",ui-monospace,monospace;font-size:.9em;background:var(--surface-2);padding:1px 5px;border-radius:4px}
article pre code{background:none;padding:0;font-size:inherit}
article blockquote{margin:12px 0;padding:8px 14px;border-left:4px solid var(--note-line);background:var(--note-bg);color:var(--note-ink);border-radius:6px}
article blockquote p{margin:0}
.back{display:inline-block;padding:10px 0;font-weight:600}
.req{display:flex;flex-direction:column;gap:16px;margin-top:8px}
.req label{display:flex;flex-direction:column;gap:4px;font-size:13px;font-weight:600;color:var(--ink)}
.req label small{font-weight:400;color:var(--muted)}
.req input[type=text],.req input[type=url],.req textarea{min-height:40px;border:1px solid var(--line);border-radius:8px;background:var(--surface);padding:8px 12px;font-size:15px;font-weight:400}
.req textarea{min-height:140px;resize:vertical}
.req .tick{flex-direction:row;align-items:center;gap:10px;font-weight:500;min-height:40px}
.req .tick input{width:20px;height:20px;flex:none}
.req .hp{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}
.req .btn.primary{align-self:flex-start}
.req .msg{margin:0;padding:10px 14px;border-radius:8px;font-size:14px}
.req .msg.no{background:var(--bad-soft);color:var(--bad)}
.sent{padding:16px;border-radius:8px;background:var(--good-soft);color:var(--good);font-size:15px}
"""
# Turnstile site key (public by design; the secret lives only in the Worker). Empty until the widget exists.
TURNSTILE_SITEKEY = "0x4AAAAAAGSyenC2xh8Dd6Uo"   # public site key (widget "HuntCraft request form"); the secret lives only in the Worker
REQUEST_BODY = f"""<h1>Request a hunt</h1>
<p>Practice or finished hunts only, never the one running now.</p>
<form class="req" id="req" novalidate>
  <label>Hunt name <input type="text" name="name" required maxlength="120" autocomplete="off"></label>
  <label>Link to the hunt post <small>Optional</small><input type="url" name="link" maxlength="500" placeholder="https://"></label>
  <label>Workspace name <small>Optional</small><input type="text" name="workspace" maxlength="120" placeholder="LAW-&hellip;" autocomplete="off"></label>
  <label>The flag questions <small>Optional. Paste them if you have them; it speeds things up.</small><textarea name="questions" maxlength="8000"></textarea></label>
  <label>How to reach you <small>Optional: email or Range handle. Only used to tell you when it is up.</small><input type="text" name="contact" maxlength="200" autocomplete="email"></label>
  <label class="hp" aria-hidden="true">Leave this empty <input type="text" name="website" tabindex="-1" autocomplete="off"></label>
  <label class="tick"><input type="checkbox" name="confirm" required> This is a practice or finished hunt, not the live one</label>
  {f'<div class="cf-turnstile" data-sitekey="{TURNSTILE_SITEKEY}"></div>' if TURNSTILE_SITEKEY else ''}
  <p class="msg no" id="req-err" role="alert" hidden></p>
  <p class="msg no" id="req-fail" role="alert" hidden>Couldn't send. Try again in a minute.</p>
  <button class="btn primary" type="submit">Send request</button>
</form>
<div class="sent" id="req-ok" role="status" hidden>Thanks. You'll see it in the Hunt list when it's ready.</div>
{'<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' if TURNSTILE_SITEKEY else ''}
<script>
(function(){{
  var f=document.getElementById('req'), err=document.getElementById('req-err'), fail=document.getElementById('req-fail');
  function show(el,text){{ err.hidden=true; fail.hidden=true; if(!el) return; if(text) el.textContent=text; el.hidden=false; }}
  f.onsubmit=function(e){{
    e.preventDefault(); show(null);
    var d={{}}; ['name','link','workspace','questions','contact','website'].forEach(function(k){{ d[k]=f.elements[k].value; }});
    d.confirm=f.elements.confirm.checked;
    var t=f.querySelector('[name="cf-turnstile-response"]'); d.token=t?t.value:'';
    if(!d.name.trim()) return show(err,'Add the hunt name.');
    if(!d.confirm) return show(err,'Tick the box to confirm this is a practice or finished hunt.');
    var b=f.querySelector('button[type=submit]'); b.disabled=true;
    fetch('/api/request',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(d)}})
      .then(function(r){{ return r.json().catch(function(){{ return {{}}; }}).then(function(j){{ return {{ok:r.ok&&j.ok,j:j}}; }}); }})
      .then(function(res){{
        if(res.ok){{ f.hidden=true; document.getElementById('req-ok').hidden=false; return; }}
        if(res.j&&res.j.error) show(err,res.j.error); else show(fail);
        if(window.turnstile) window.turnstile.reset();
      }},function(){{ show(fail); }})
      .then(function(){{ b.disabled=false; }});
  }};
}})();
</script>"""
DESC = "A threat-hunt instruction manual. Follow the reasoning, run the queries yourself, and find each flag on your own."
NAV = [("method", "The hunt method"), ("kql-cookbook", "KQL cookbook"), ("log-tables", "Log-table reference"),
       ("report-writing", "Report writing")]
PAGE_JS = """<script>
(function(){
  function store(k,v){ try{ if(v===undefined) return JSON.parse(localStorage.getItem(k)); localStorage.setItem(k,JSON.stringify(v)); }catch(e){ return null; } }
  var saved=store('hc-theme'); if(saved) document.documentElement.setAttribute('data-theme',saved);
  var t=document.getElementById('theme'); if(t) t.onclick=function(){ var r=document.documentElement, dark=r.getAttribute('data-theme')==='dark' ||
    (!r.getAttribute('data-theme') && matchMedia('(prefers-color-scheme: dark)').matches);
    var next=dark?'light':'dark'; r.setAttribute('data-theme',next); store('hc-theme',next); };
  document.querySelectorAll('[data-copy]').forEach(function(b){ b.onclick=function(){
    var txt=b.parentNode.previousElementSibling.textContent;
    if(navigator.clipboard) navigator.clipboard.writeText(txt).then(function(){ b.textContent='Copied'; setTimeout(function(){ b.textContent='Copy query'; },1500); }); }; });
})();
</script>"""


def page(title, body, current=None):
    here = ' aria-current="page"'
    nav = "".join(f'<a href="/knowledge/{k}"{here if k == current else ""}>{v}</a>' for k, v in NAV)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{title}</title>
<meta name="description" content="{DESC}">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{DESC}">
<meta property="og:type" content="website">
<meta property="og:image" content="https://huntcraft.kenmwara.com/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="https://huntcraft.kenmwara.com/og.png">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon.ico" sizes="48x48">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap">
<style>{PAGE_CSS}{ARTICLE_CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <a class="brand" href="/" style="text-decoration:none;color:inherit">
      <svg viewBox="0 0 32 32" aria-hidden="true"><circle cx="14" cy="14" r="8" fill="none" stroke="var(--accent)" stroke-width="3"/><line x1="20" y1="20" x2="28.5" y2="28.5" stroke="var(--accent)" stroke-width="3" stroke-linecap="round"/></svg>
      <b>HuntCraft</b>
    </a>
    <div class="tools"><a class="btn link" href="/" style="text-decoration:none">Back to the hunt</a><button class="btn link" id="theme" type="button" aria-label="Switch theme"><svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="2"/><path d="M10 2a8 8 0 0 1 0 16z" fill="currentColor"/></svg></button></div>
  </header>
  <main><article>{body}</article></main>
  <footer>
    <nav aria-label="Method references">{nav}<a href="/request"{here if current == "request" else ""}>Request a hunt</a></nav>
    <span class="spacer"></span>
    {CREDIT_SPAN}
  </footer>
</div>
{PAGE_JS}
</body>
</html>
"""


def render_md(text):
    html = markdown.markdown(text, extensions=["tables", "fenced_code", "attr_list", "toc"])
    # cross-references: method.html#x -> /knowledge/method#x (Pages answers *.html with a 308; skip the hop)
    html = re.sub(r'href="([a-z0-9-]+)\.html(#[^"]*)?"', r'href="/knowledge/\1\2"', html)
    # code fences get the manual's code block and Copy button
    return re.sub(r'<pre><code(?: class="[^"]*")?>(.*?)</code></pre>',
                  r'<div class="code"><pre>\1</pre></div><div class="codebar"><button class="btn small" type="button" data-copy>Copy query</button></div>',
                  html, flags=re.S)


def check_scripts(pages):
    """Every inline <script> must parse: one stray apostrophe in a string blanked the whole site (25 Nov)."""
    node = shutil.which("node")
    if not node:
        print("warning: node not found, page scripts not syntax-checked"); return
    js = ("const fs=require('fs');let bad=0;for(const f of process.argv.slice(1)){const h=fs.readFileSync(f,'utf8');"
          "for(const m of h.matchAll(/<script>([\\s\\S]*?)<\\/script>/g)){try{new Function(m[1])}catch(e){bad=1;"
          "console.log(f+': '+e.message)}}}process.exit(bad)")
    r = subprocess.run([node, "-e", js, *map(str, pages)], capture_output=True, text=True)
    if r.returncode:
        sys.exit("REFUSED: a page script does not parse\n" + r.stdout)


def main():
    hunts, all_reveals = [], {}
    for d in sorted(p for p in HUNTS.iterdir() if p.is_dir() and not p.name.startswith("_")):
        h, rv = build_hunt(d)
        if h:
            hunts.append(h); all_reveals[d.name] = rv

    blob = json.dumps(hunts, indent=1, ensure_ascii=False)
    ver = hashlib.sha1((blob + json.dumps(all_reveals, sort_keys=True)).encode("utf-8")).hexdigest()[:10]
    (SITE / "data.js").write_text(f"window.HUNTS = {blob};\nwindow.HC_VER = \"{ver}\";\n", encoding="utf-8")
    shutil.rmtree(SITE / "reveals", ignore_errors=True)
    for slug, rv in all_reveals.items():
        out = SITE / "reveals" / slug
        out.mkdir(parents=True)
        for name, obj in rv.items():
            (out / name).write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")

    # knowledge pages: .md source -> .html in the site's design; the raw .md copies are no longer served
    kd = SITE / "knowledge"
    shutil.rmtree(kd, ignore_errors=True); kd.mkdir()
    for md in sorted(KNOW.glob("*.md")):
        text = md.read_text(encoding="utf-8")
        title = re.match(r"#\s*(.+)", text).group(1).split(":")[0].strip()
        (kd / f"{md.stem}.html").write_text(page(f"{title} - HuntCraft", render_md(text), md.stem), encoding="utf-8")
    (SITE / "404.html").write_text(page("Page not found - HuntCraft",
        "<h1>That page isn't here</h1><p>The link may be old or mistyped.</p>"
        "<p><a class=\"back\" href=\"/\">Back to the hunt</a></p>"), encoding="utf-8")
    (SITE / "request.html").write_text(page("Request a hunt - HuntCraft", REQUEST_BODY, "request"), encoding="utf-8")
    # the request form replaced the mailto: no address may ship in the site
    leaked = [p.name for p in SITE.rglob("*.html") if re.search(r"mailto:|@kenmwara\.com|@gmail\.com", p.read_text(encoding="utf-8"))]
    if leaked:
        sys.exit(f"REFUSED: an email address or mailto: is in {leaked}")
    # every page carries the icons and the OG card (Ken: favicon and OG image on every page, always)
    need = ('rel="icon"', 'rel="apple-touch-icon"', 'property="og:image"', 'name="twitter:card"')
    bare = [p.name for p in SITE.rglob("*.html") if not all(n in p.read_text(encoding="utf-8") for n in need)]
    if bare or not (SITE / "apple-touch-icon.png").exists():
        sys.exit(f"REFUSED: favicon/OG tags missing in {bare or 'apple-touch-icon.png'} (run tools/make_og.py)")

    # stamp the data version into the page: the kenmwara.com zone caches .js for 4h in browsers
    idx = SITE / "index.html"
    idx.write_text(re.sub(r'src="data\.js(\?v=\w+)?"', f'src="data.js?v={ver}"', idx.read_text(encoding="utf-8")), encoding="utf-8")
    # the hand-written pages take the same footer credit
    review = ROOT / "tools" / "review.html"
    for p in (idx, review):
        p.write_text(re.sub(r'<span class="credit">.*?</span>', CREDIT_SPAN, p.read_text(encoding="utf-8")), encoding="utf-8")
    pages = [idx, SITE / "404.html", SITE / "request.html", *sorted(kd.glob("*.html")), review]
    missing = [p.name for p in pages if CREDIT_SPAN not in p.read_text(encoding="utf-8")]
    if missing:
        sys.exit(f"REFUSED: footer credit missing in {missing}")
    # names: only the allowlist may follow "by" (people's names stay off the site)
    # (code, scripts and styles are skipped: "summarize count() by DeviceName" is KQL, not a person)
    prose = lambda h: re.sub(r"<[^>]+>", " ", re.sub(r"(?s)<(script|style|pre|code)\b.*?</\1>", " ", h))
    named = {m for p in pages for m in re.findall(r"\bby ((?:[A-Z][\w-]+ ?)+)", prose(p.read_text(encoding="utf-8")))}
    bad = {n.strip() for n in named} - NAMES_OK
    if bad:
        sys.exit(f"REFUSED: names outside the allowlist: {sorted(bad)}")
    check_scripts(pages)
    print(f"wrote data.js with {len(hunts)} hunt(s), {sum(len(v) for v in all_reveals.values())} reveals, "
          f"{len(list(KNOW.glob('*.md')))} knowledge pages, version {ver}")


if __name__ == "__main__":
    main()
