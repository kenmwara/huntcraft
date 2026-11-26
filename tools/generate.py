#!/usr/bin/env python3
"""HuntCraft Phase 1 generator: solve a practice hunt through YOUR Range MCP sign-in, then author a draft manual.

    python tools/generate.py rdp-flare --questions hunts/rdp-flare/questions.md --answers private/rdp-flare/answers.json
    python tools/generate.py --selftest

Flow: registry check (live = refused) -> orient -> solve each flag -> author each flag -> re-run every authored
query -> leak check -> private/_drafts/<slug>/{guide.json, solve.json, draft.meta.json}. Nothing is published:
private/ is outside hunts/ and outside the public repo. Every model call is headless `claude -p` limited to four read-only la_* tools; any other
tool call aborts the run. Known answers (optional) are never shown to the solver, only compared afterwards.
"""
import argparse, base64, gzip, hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile, time, urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
HUNTS = ROOT / "hunts"
MCP = "mcp__claude_ai_Cyber_Range__"
READ_ONLY = [MCP + t for t in ("la_query", "la_list_tables", "la_get_table_schema", "la_list_workspaces")]
ALLOWED_NAMES = set(READ_ONLY) | {"ToolSearch"}   # ToolSearch only loads the deferred MCP schemas
MODE = "deferred"
STATS = {"calls": 0, "queries": 0, "cost_usd": 0.0, "input_tokens": 0, "output_tokens": 0,
         "cache_read_tokens": 0, "cache_write_tokens": 0}


# ---------------------------------------------------------------- inputs

def load_registry():
    return json.loads((HUNTS / "registry.json").read_text(encoding="utf-8"))


def registry_gate(slug, workspace, allow_unregistered):
    """Live hunts are refused, always. Unregistered ones need Ken's explicit go (Phase 1)."""
    for e in load_registry():
        if e["slug"] == slug or (workspace and workspace in (e.get("workspace"), e.get("workspace_guid"))):
            if e["status"] == "live":
                sys.exit(f"REFUSED: {e['title']} is the live hunt. The current hunt stays fair for everyone; "
                         "come back when it closes.")
            return e
    if not allow_unregistered:
        sys.exit(f"'{slug}' is not in hunts/registry.json. Add it (status practice/retired) or pass "
                 "--allow-unregistered with --workspace if you have checked it is not the live hunt.")
    if not workspace:
        sys.exit("--allow-unregistered needs --workspace (GUID or name).")
    return {"slug": slug, "title": slug, "workspace": workspace, "workspace_guid": workspace,
            "status": "unregistered", "table_prefix": ""}


def parse_questions(text):
    """'## section | flag | points' headers, question text, optional 'format:' and 'choices:' lines."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    flags, cur = [], None
    for line in text.splitlines():
        if line.startswith("## "):
            parts = [p.strip() for p in line[3:].split("|")]
            if len(parts) != 3 or not re.match(r"^\d+\s+\S", parts[0]) or not parts[2].isdigit():
                raise ValueError(f"bad header (want '## 1 Initial Access | Q1 - Name | 75'): {line}")
            cur = {"section": parts[0], "flag": parts[1], "points": int(parts[2]), "question": "",
                   "format": None, "choices": None}
            flags.append(cur)
        elif cur is not None:
            s = line.strip()
            if s.lower().startswith("format:"):
                cur["format"] = s[7:].strip()
            elif s.lower().startswith("choices:"):
                cur["choices"] = [c.strip() for c in s[8:].split("|") if c.strip()]
            elif s and not s.startswith("#"):
                cur["question"] = (cur["question"] + " " + s).strip()
    if not flags:
        raise ValueError("no flags found: each flag needs a '## section | flag | points' header")
    for f in flags:
        if not f["question"]:
            raise ValueError(f"flag '{f['flag']}' has no question text")
    return flags


# ---------------------------------------------------------------- answer matching + leak check

def is_unordered(reveal):
    """Comma order is ignored only for list answers: reveal.unordered, or a format that says comma separated.
    A command line or free value with a comma keeps its order. Same rule in build.py and the page."""
    r = reveal or {}
    return bool(r.get("unordered")) or bool(re.search(r"comma.?separated", r.get("format") or "", re.I))


def norm(s, unordered=False):
    """Same rule as the page's Check: case, quotes, spacing and a trailing period don't matter; comma order only
    for unordered answers."""
    s = re.sub(r"[\"'`]", "", str(s or "").lower())
    s = re.sub(r"\s+", " ", s).strip().rstrip(".")
    if not unordered:
        return s
    return ",".join(sorted(p.strip() for p in s.split(",") if p.strip()))


def items_of(answer, unordered):
    """The separate values a list answer is made of (one value otherwise)."""
    a = str(answer or "")
    return [p.strip() for p in a.split(",") if p.strip()] if unordered else [a]


def shuffle_choices(choices, seed):
    """Stable shuffle: the same order on every build and every visit, but not the source order."""
    return sorted(choices, key=lambda c: hashlib.sha256(f"{seed}|{c}".encode("utf-8")).hexdigest())


def unescape(raw):
    """Tool results arrive as JSON text: undo escaped backslashes and quotes before a substring match."""
    return raw.replace("\\\\", "\\").replace('\\"', '"')


def found_in_rows(answer, raw, unordered):
    """Every item of the answer appears in the returned rows (a bare name also matches name.exe or a full path)."""
    raw = unescape(raw).lower()
    for item in items_of(answer, unordered):
        forms = answer_forms(item) or [item.lower()]
        if not any(fm and fm in raw for fm in forms):
            return False
    return True


def defender_url(query, tenant_id):
    """Defender advanced-hunting share link: UTF-16LE text, gzip, base64, url-encoded (verified 25 Nov)."""
    b = base64.b64encode(gzip.compress(query.encode("utf-16-le"), mtime=0)).decode()
    return ("https://security.microsoft.com/v2/advanced-hunting?query=" + urllib.parse.quote(b, safe="")
            + "&timeRangeId=month" + (f"&tid={tenant_id}" if tenant_id else ""))


FILTER_COL = re.compile(r"\b([A-Z][A-Za-z]+)\s*(?:==|!=|=~|!~|>=|<=|>|<|!?has(?:_any|_all)?\b|!?in~?\s*\(|!?(?:starts|ends)with\b|!?contains\b|between\b)")


def shown_columns(query):
    """Columns a query's results show: the last project/distinct list, or a summarize's aggregates + by list."""
    cols, shown = set(), None
    for line in query.split("\n"):
        m = re.match(r"\s*\|\s*(project|distinct|summarize)\b(.*)", line)
        if m:
            body = m.group(2)
            shown = set(re.findall(r"\b([A-Z][A-Za-z]+)\s*(?:=(?!=)|,|$|\))", body.split(" by ")[0] if m.group(1) == "summarize" else body))
            if m.group(1) == "summarize" and " by " in body:
                shown |= set(re.findall(r"\b([A-Z][A-Za-z]+)\b", body.split(" by ", 1)[1]))
            if m.group(1) == "project":
                shown |= set(re.findall(r"\b([A-Z][A-Za-z]+)\b", body))
    return shown


def project_gaps(flag):
    """Member review 1: a column a step filters on and its hint talks about must show in the results.
    Returns info lines like 'steps[1]: filters on LogonType and look_for names it, but the results don't show it'."""
    out = []
    for i, st in enumerate(flag.get("steps") or []):
        q = st.get("query") or ""
        shown = shown_columns(q)
        if not q.strip() or q.strip().startswith("(") or shown is None:
            continue
        filtered = {c for line in q.split("\n") if re.match(r"\s*\|\s*where\b", line) for c in FILTER_COL.findall(line)}
        talk = " ".join(st.get(k) or "" for k in ("look_for", "observe"))
        for c in sorted(filtered - shown - {"TimeGenerated"}):
            if re.search(rf"\b{c}\b", talk):
                out.append(f"steps[{i}]: filters on {c} and the hint names it, but the results don't show it (add it to project)")
    return out


def answer_forms(answer):
    """Strings that would give the answer away if they appeared outside the reveal."""
    a = str(answer or "").strip().strip('"')
    if not a or len(a.split()) > 8:            # free-text reasoning: left to the model check
        return []
    forms = {a.lower()}
    for part in re.split(r"\s*,\s*", a):
        if len(part) >= 4:
            forms.add(part.lower())
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$", a)       # IP:port -> the IP alone
    if m:
        forms.add(m.group(1))
    for tok in re.findall(r"[\w.-]+\.(?:exe|ps1|dll|bat|zip|7z|rar|vbs|js|sh|py)\b", a, flags=re.I):
        forms.add(tok.lower())                                # file names inside paths/command lines
    for tok in re.findall(r"\b[0-9a-f]{16,}\b", a, flags=re.I):
        forms.add(tok[:8].lower())                            # hash prefix
    return sorted(forms, key=len, reverse=True)


WIDEN = ("| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal "
         "time picker cannot hide them")


def widen(q):
    """Lab logs share one TimeGenerated (the load day); Defender's 7-day default picker hides them. A TimeGenerated
    filter in the query switches the picker to 'Set in query' (verified in Defender 25 Nov)."""
    if not q or q.strip().startswith("(") or "TimeGenerated > ago" in q:
        return q
    lines = q.split("\n")
    if lines[0].lstrip().startswith("let"):
        return q
    return "\n".join([lines[0], WIDEN] + lines[1:])


def leak_report(flag, earlier=(), context=()):
    """Deterministic leak check: the answer, or any reveal.accept spelling, in any form, anywhere outside `reveal`.
    Returns (blocking, info). Values that are earlier flags' answers are fine: the member already found them (the C2
    IP reused in the exfil flag). A hit that only occurs inside given context the manual shows by design (host,
    table and workspace names: 'slflare' inside 'slflarewinsysmo') is info, not a leak."""
    r = flag.get("reveal", {})
    done = {f for a in earlier for f in answer_forms(a)} | {str(a).lower() for a in earlier if a}
    forms = sorted({f for a in [r.get("answer")] + list(r.get("accept") or []) for f in answer_forms(a)} - done,
                   key=len, reverse=True)
    body = {k: v for k, v in flag.items() if k != "reveal"}
    blob = unescape(json.dumps(body, ensure_ascii=False)).lower()
    bare = blob
    for c in sorted((str(c).lower() for c in context if c), key=len, reverse=True):
        bare = bare.replace(c, " ")
    blocking = [f for f in forms if f in bare]
    info = [f"'{f}' only inside given context" for f in forms if f in blob and f not in bare]
    ch = r.get("choices") or []
    if ch and r.get("answer") is not None and norm(ch[0]) == norm(r["answer"]):
        info.append("the correct choice is listed first (fine after the seeded shuffle; check it is not the source order)")
    return blocking, info


def leak_hits(flag, earlier=(), context=()):
    return leak_report(flag, earlier, context)[0]


def leak_fields(flag, terms):
    """Which fields hold a leaked term, e.g. ['steps[1].look_for'], so the review shows where manuals leak."""
    out = []

    def walk(v, path):
        if isinstance(v, dict):
            for k, x in v.items():
                walk(x, f"{path}.{k}" if path else k)
        elif isinstance(v, list):
            for n, x in enumerate(v):
                walk(x, f"{path}[{n}]")
        elif isinstance(v, str) and any(t in unescape(v).lower() for t in terms):
            out.append(path)
    walk({k: v for k, v in flag.items() if k != "reveal"}, "")
    return out


# ---------------------------------------------------------------- headless claude

def run_claude(prompt, system, tools=False, max_turns=4, label=""):
    """One headless call. Returns (final_text, tool_trace). Aborts on any tool outside the read-only allowlist."""
    exe = shutil.which("claude") or sys.exit("claude CLI not found on PATH")
    cmd = [exe, "-p", "--output-format", "stream-json", "--verbose", "--no-session-persistence",
           "--system-prompt", system, "--max-turns", str(max_turns)]
    # Every connected MCP server's tool definitions cost ~145K tokens per turn when loaded up front (measured
    # 25 Nov). Tool calls defer them (ToolSearch loads only what's used: ~15K/turn); tool-free calls load none (~1.3K).
    env = dict(os.environ)
    if tools and ARGS.range_config:
        # only the Range server loads at all (needs that server signed in once: `claude mcp add` + /mcp)
        cmd += ["--strict-mcp-config", "--mcp-config", ARGS.range_config, "--tools", "",
                "--allowedTools", ",".join(READ_ONLY)]
    elif tools:
        cmd += ["--tools", "ToolSearch", "--allowedTools", ",".join(READ_ONLY)]
        env["ENABLE_TOOL_SEARCH"] = "true"
    else:
        cmd += ["--tools", "", "--strict-mcp-config", "--setting-sources", "project"]
    if ARGS.model:
        cmd += ["--model", ARGS.model]
    with tempfile.TemporaryDirectory() as cwd:          # empty cwd: no project CLAUDE.md pulled in
        p = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", cwd=cwd,
                           timeout=ARGS.call_timeout, env=env)
    uses, results, final = {}, {}, None
    for line in p.stdout.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("type") == "assistant":
            for c in ev["message"].get("content", []):
                if c.get("type") == "tool_use":
                    if c["name"] not in ALLOWED_NAMES:
                        sys.exit(f"ABORT [{label}]: model tried tool {c['name']} (only read-only la_* allowed)")
                    uses[c["id"]] = c
        elif ev.get("type") == "user":
            for c in (ev.get("message") or {}).get("content", []) if isinstance((ev.get("message") or {}).get("content"), list) else []:
                if c.get("type") == "tool_result":
                    results[c["tool_use_id"]] = c.get("content")
        elif ev.get("type") == "result":
            final = ev
    if not final:
        sys.exit(f"ABORT [{label}]: no result from claude (exit {p.returncode}): {p.stderr[-800:]}")
    u = final.get("usage") or {}
    STATS["calls"] += 1
    STATS["cost_usd"] += final.get("total_cost_usd") or 0
    STATS["input_tokens"] += u.get("input_tokens", 0)
    STATS["output_tokens"] += u.get("output_tokens", 0)
    STATS["cache_read_tokens"] += u.get("cache_read_input_tokens", 0)
    STATS["cache_write_tokens"] += u.get("cache_creation_input_tokens", 0)
    trace = []
    for uid, c in uses.items():
        if c["name"] == "ToolSearch":
            continue
        raw = results.get(uid)
        if isinstance(raw, list):
            raw = "".join(x.get("text", "") for x in raw if isinstance(x, dict))
        info = {"tool": c["name"].replace(MCP, ""), "input": c.get("input", {})}
        try:
            r = json.loads(raw)
            info["status"] = r.get("status") or ("Error" if r.get("error") else None)
            info["rows_returned"] = r.get("rows_returned")
            tabs = r.get("tables") or []
            info["sample"] = (tabs[0].get("rows") or [])[:8] if tabs else None
            if r.get("error"):
                info["error"] = str(r["error"])[:400]
            info["_raw"] = raw
        except (TypeError, ValueError):
            info["status"], info["error"], info["_raw"] = "Error", str(raw)[:400], str(raw or "")
        if info["tool"] == "la_query":
            STATS["queries"] += 1
        trace.append(info)
    if final.get("is_error"):
        print(f"  ! [{label}] claude reported an error: {str(final.get('result'))[:300]}")
    return final.get("result") or "", trace


def last_json(text):
    """The last ```json block (or bare {...}) in the model's reply."""
    blocks = re.findall(r"```json\s*(.*?)```", text, flags=re.S)
    cands = blocks or re.findall(r"(\{.*\})", text, flags=re.S)
    for c in reversed(cands):
        try:
            return json.loads(c)
        except ValueError:
            continue
    raise ValueError("no JSON object in reply:\n" + text[-1200:])


# ---------------------------------------------------------------- prompts

SOLVER_SYSTEM = (
    "You are a careful threat hunter solving a PRACTICE hunt in Azure Log Analytics through read-only KQL. "
    "Use only the la_* tools. Never guess: an answer counts only when specific result rows show it. "
    "Always pass the workspace GUID you are given and timespan \"all\". Keep queries tight (project, summarize, take). "
    "End your reply with one ```json block and nothing after it."
)

AUTHOR_SYSTEM = (
    "You write HuntCraft instruction manuals for absolute beginners. A manual LEADS the reader to find the flag "
    "themselves; it never states the answer outside the reveal. No em dashes. Plain, direct sentences. "
    "Reply with one ```json block and nothing else."
)

STYLE_EXAMPLE = {
    "where_to_look": {
        "decision": "Go to the File events table (ExampleFile_CL, DeviceFileEvents in a real tenant).",
        "why_here": "A web shell is a file written into a web folder, so file-creation telemetry is where it first shows up.",
        "why_not_others": "Process events show what ran, not what was dropped. Network events show the request, not the file it left behind."
    },
    "steps": [{
        "think": "Do not search for a shell by name; you don't know it yet. Ask which files appeared in the web root at all, and let the odd one stand out.",
        "query": "ExampleFile_CL\n| where FolderPath has \"wwwroot\" and ActionType == \"FileCreated\"\n| summarize Count=count() by FileName, FolderPath\n| order by Count asc",
        "run_it": "Run it in the hunt's workspace.",
        "look_for": "Most files are site assets created in bulk. Look for a single script file with a name that sounds like an image or an error page, created once.",
        "observe": "Attackers name shells to blend in. Rare plus misleading name is the pattern to remember."
    }],
    "mitre": "T1505.003 Web Shell"
}


def orient_prompt(entry, guid):
    prefix = entry.get("table_prefix") or ""
    return f"""Hunt: {entry['title']}
Workspace GUID: {guid}
Table prefix (may be empty): {prefix}

Get your bearings before any flag:
1. List the hunt's tables (la_list_tables; if a prefix is given, keep tables starting with it).
2. For each table: row count, min/max of TimeGenerated and of Timestamp (if the column exists).
3. Find the host(s) and the account names that appear.
Report in this JSON shape:
```json
{{"tables": ["..."], "hosts": ["..."], "accounts": ["..."],
  "window": {{"start": "...", "end": "..."}},
  "time_column": "Timestamp or TimeGenerated (whichever holds the REAL event time)",
  "timegenerated_is_load_time": true,
  "orientation_query": "the single union query a beginner should run first: per table, the row count, min and max of the REAL time column (FirstEvent, LastEvent) and max(TimeGenerated) (LoadedAt), so both clocks show",
  "notes": "anything a hunter must know before starting"}}
```"""


def solve_prompt(guid, orient, flag, findings, budget):
    kind = ("Multiple choice: " + " | ".join(flag["choices"])) if flag["choices"] else f"Answer format: {flag['format'] or 'not given'}"
    return f"""Workspace GUID: {guid}
Orientation (already established):
{json.dumps(orient, indent=1)}

Findings from earlier flags (trust these):
{json.dumps(findings, indent=1) if findings else "none yet"}

FLAG {flag['section']} / {flag['flag']} ({flag['points']} pts)
Question: {flag['question']}
{kind}

Solve it with at most {budget} la_query calls: hypothesis, query, read, pivot, confirm.
If the question is answered by knowledge or by reasoning over earlier findings (not by a log row), say so and do not query.
If you cannot confirm it from rows within the budget, report status "unconfirmed". Do not guess.
```json
{{"status": "confirmed | reasoned | unconfirmed",
  "answer": "exact answer string in the requested format (or null)",
  "evidence": "which query and which row(s) show it, quoting the row values",
  "path": [{{"hypothesis": "...", "query": "...", "learned": "..."}}],
  "dead_ends": "anything tried that didn't pan out, and what it taught"}}
```"""


def author_prompt(flag, solved, orient, previous=None, verdict=None):
    reveal_type = "multiple_choice" if flag["choices"] else "input"
    redo = "" if previous is None else f"""
REWRITE. Your previous draft below was flagged by the leak check: {verdict}
Rewrite it so no field outside reveal gives the answer away. Keep the queries; change only the wording that leaks.
Previous draft: {json.dumps(previous, ensure_ascii=False)}
"""
    trace = [{k: v for k, v in t.items() if not k.startswith("_")} for t in solved.get("trace", [])]
    return f"""Write the instruction-manual entry for one flag.

The flag: {json.dumps({k: flag[k] for k in ("section", "flag", "points", "question", "format", "choices")}, ensure_ascii=False)}
The solved answer (goes ONLY in reveal.answer): {json.dumps(solved.get("answer"), ensure_ascii=False)}
How it was solved (the solver's path): {json.dumps(solved.get("path"), ensure_ascii=False)}
Evidence: {solved.get("evidence")}
Dead ends: {solved.get("dead_ends")}
The real queries that ran, with row counts and sample rows: {json.dumps(trace, ensure_ascii=False)[:12000]}
Orientation: tables {orient.get("tables")}, real time column {orient.get("time_column")}.
Practice table -> production Defender table: {json.dumps(orient.get("table_map") or "derive it from the table name (..Logon_CL is DeviceLogonEvents, ..Process_CL DeviceProcessEvents, ..Network_CL DeviceNetworkEvents, ..File_CL DeviceFileEvents)")}

Rules:
- Teach the useful path, not every dead end. A dead end that teaches something can become a `think`.
- `think` explains WHY this query and not another. `look_for` describes the pattern to spot, never the value.
- Queries must be ones that actually ran above (or trivially tidied). A query must NOT filter on the answer itself.
  Never put the answer (or a piece of it: the IP, the file name, the command) in any field except reveal.
- On the first mention of each `_CL` table in a flag, give its production Defender equivalent in brackets, for
  example "RdpFlarePracticeLogon_CL (DeviceLogonEvents in a real tenant)". Once per flag, not on every mention.
- Project what you filter: every column a step filters on in a `where` that its look_for or observe talks about must
  also appear in that step's project (or summarize by / distinct), so the reader sees the value that proves it.
- If the flag is knowledge or reasoning, use one step with query "(no query, reason it out)".
- Multiple choice: never name or describe the wrong choices in where_to_look, think, look_for or observe, and never
  rule them out one by one. Teach the property that decides it (for example "which control stops a password attempt
  before a session exists?").
- Lists of commands or files: describe what the items do only at the level the objective already gives away. Never
  write a description that maps to exactly one tool or file name.
- Reasoned or judgement flags: the objective and observe state the evidence to weigh, never the conclusion. The
  conclusion lives only in reveal.why.
- reveal.type is "{reveal_type}".{" Keep the given choices in reveal.choices." if flag["choices"] else ""}
- reveal.accept: other spellings a correct reader might type. For process and file answers include the .exe and
  bare forms, the common switches seen in the rows (for example "tasklist /svc"), and the full path if the rows show
  one. Omit if none.
{redo}
Style example (a different, fictional hunt):
{json.dumps(STYLE_EXAMPLE, indent=1)}

Reply with:
```json
{{"section": "...", "flag": "...", "points": 0, "objective": "the question restated for a beginner, no answer",
  "where_to_look": {{"decision": "...", "why_here": "...", "why_not_others": "..."}},
  "steps": [{{"think": "...", "query": "...", "run_it": "...", "look_for": "...", "observe": "..."}}],
  "reveal": {{"type": "{reveal_type}", "format": "...", "choices": [], "answer": "...", "accept": [], "why": "..."}},
  "mitre": "Txxxx Name"}}
```"""


# ---------------------------------------------------------------- pipeline

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("slug", nargs="?")
    ap.add_argument("--questions", help="flag questions file (see hunts/rdp-flare/questions.md)")
    ap.add_argument("--answers", help="optional JSON list of known answers, in flag order (verification only)")
    ap.add_argument("--workspace", help="workspace GUID (needed with --allow-unregistered)")
    ap.add_argument("--allow-unregistered", action="store_true")
    ap.add_argument("--budget", type=int, default=12, help="max la_query calls per flag (default 12)")
    ap.add_argument("--only", help="comma-separated flag numbers (1-based) to run, e.g. 1,2")
    ap.add_argument("--model", help="model for every call (default: your Claude Code default)")
    ap.add_argument("--call-timeout", type=int, default=900)
    # The Range MCP accepts sign-ins only from the claude.ai connector, not from a standalone Claude Code server
    # (checked 25 Nov: "This service doesn't accept sign-ins from Claude Code"). So the default is the connector with
    # deferred tool loading, which is what HuntCraft uses (decided 25 Nov).
    ap.add_argument("--range-config", default=None,
                    help="MCP config JSON holding ONLY a Range server you can sign in to (strict: no other connector "
                    "loads). Falls back to deferred loading if that server isn't signed in.")
    ap.add_argument("--selftest", action="store_true")
    global ARGS, MCP, READ_ONLY, ALLOWED_NAMES, MODE
    ARGS = ap.parse_args()
    if ARGS.selftest:
        return selftest()
    if not (ARGS.slug and ARGS.questions):
        ap.error("slug and --questions are required")
    MODE = "deferred"
    if ARGS.range_config and pathlib.Path(ARGS.range_config).exists():
        name = next(iter(json.loads(pathlib.Path(ARGS.range_config).read_text(encoding="utf-8"))["mcpServers"]))
        saved = MCP, READ_ONLY, ALLOWED_NAMES
        MCP = f"mcp__{name}__"
        READ_ONLY = [MCP + t for t in ("la_query", "la_list_tables", "la_get_table_schema", "la_list_workspaces")]
        ALLOWED_NAMES = set(READ_ONLY)
        # preflight: one tool-only call. Signed in -> strict loading (only this server's tools cost tokens).
        _, tr = run_claude("Call la_list_workspaces once, then reply \"ok\".", SOLVER_SYSTEM, tools=True,
                           max_turns=3, label="preflight")
        if any(x.get("status") != "Error" for x in tr):
            MODE = "strict"
        else:
            MCP, READ_ONLY, ALLOWED_NAMES = saved
            print(f"note: the '{name}' MCP server in {ARGS.range_config} is not signed in; using deferred loading. "
                  "Sign it in once: run `claude` in this folder, type /mcp, pick it, authenticate.")
    if MODE == "deferred":
        ARGS.range_config = None
    print(f"MCP loading: {MODE}")

    t0 = time.time()
    entry = registry_gate(ARGS.slug, ARGS.workspace, ARGS.allow_unregistered)
    guid = ARGS.workspace or entry["workspace_guid"]
    flags = parse_questions(pathlib.Path(ARGS.questions).read_text(encoding="utf-8"))
    known = json.loads(pathlib.Path(ARGS.answers).read_text(encoding="utf-8")) if ARGS.answers else []
    pick = {int(x) - 1 for x in ARGS.only.split(",")} if ARGS.only else set(range(len(flags)))
    out = ROOT / "private" / "_drafts" / ARGS.slug
    out.mkdir(parents=True, exist_ok=True)
    print(f"{entry['title']} ({entry['status']}), workspace {guid}, {len(flags)} flags, budget {ARGS.budget}/flag")

    # 1. orient
    print("[orient] ...", flush=True)
    text, otrace = run_claude(orient_prompt(entry, guid), SOLVER_SYSTEM, tools=True, max_turns=14, label="orient")
    orient = last_json(text)
    hj = HUNTS / ARGS.slug / "hunt.json"       # one source for the practice -> Defender names (orientation + author)
    if hj.exists() and json.loads(hj.read_text(encoding="utf-8")).get("table_map"):
        orient["table_map"] = {k: v["defender"] for k, v in json.loads(hj.read_text(encoding="utf-8"))["table_map"].items()}
    print(f"[orient] tables {orient.get('tables')}, hosts {orient.get('hosts')}, time column {orient.get('time_column')}")

    # 2. solve
    solved, findings = [], []
    for i, f in enumerate(flags):
        if i not in pick:
            solved.append({"status": "skipped"}); continue
        print(f"[solve {i+1}/{len(flags)}] {f['flag']} ...", flush=True)
        text, trace = run_claude(solve_prompt(guid, orient, f, findings, ARGS.budget), SOLVER_SYSTEM, tools=True,
                                 max_turns=ARGS.budget * 2 + 4, label=f"solve {i+1}")
        try:
            s = last_json(text)
        except ValueError as e:
            s = {"status": "unconfirmed", "answer": None, "evidence": f"no parseable result: {e}"[:400]}
        s["trace"] = trace
        # an answer counts as confirmed only if its value really appears in rows the solver got back
        unord = is_unordered({"format": f["format"]})
        if s.get("status") == "confirmed":
            raw = " ".join(t.get("_raw", "") for t in trace)
            if not found_in_rows(s.get("answer"), raw, unord):
                s["status"], s["note"] = "unconfirmed", "answer not found in any returned rows"
        ks = known[i] if i < len(known) and isinstance(known[i], list) else [known[i]] if i < len(known) else []
        ks = [k for k in ks if k is not None and len(str(k).split()) <= 8]     # free text: no string compare
        if ks:                                                                   # a list = every accepted spelling
            s["matches_known"] = bool(s.get("answer")) and any(norm(s["answer"], unord) == norm(k, unord) for k in ks)
            if s["status"] != "unconfirmed" and not s["matches_known"]:
                s["status"], s["note"] = "unconfirmed", "does not match the known answer"
        if s["status"] in ("confirmed", "reasoned") and s.get("answer"):
            findings.append({"flag": f["flag"], "answer": s["answer"], "evidence": s.get("evidence")})
        print(f"   -> {s['status']}: {s.get('answer')!r} ({sum(t['tool']=='la_query' for t in trace)} queries)"
              + (f" [{s.get('note')}]" if s.get("note") else ""))
        solved.append(s)

    # 3. author
    def author_one(i, f, s, previous=None, verdict=None):
        lab = f"author {i+1}" + (" rewrite" if previous else "")
        text, _ = run_claude(author_prompt(f, s, orient, previous, verdict), AUTHOR_SYSTEM, tools=False,
                             max_turns=2, label=lab)
        try:
            g = last_json(text)
        except ValueError as e:
            if previous:
                return previous                                     # a failed rewrite keeps the first draft
            g = {"section": f["section"], "flag": f["flag"], "points": f["points"], "objective": f["question"],
                 "where_to_look": {}, "steps": [], "reveal": {"type": "input", "answer": s.get("answer")},
                 "mitre": "", "_author_error": str(e)[:300]}
        g["section"], g["flag"], g["points"] = f["section"], f["flag"], f["points"]
        g.setdefault("reveal", {})["answer"] = s.get("answer")      # the solver's answer, never the author's
        if f["choices"]:
            g["reveal"]["type"] = "multiple_choice"
            g["reveal"]["choices"] = shuffle_choices(f["choices"], f"{ARGS.slug}|{f['flag']}")  # same seed as build.py
        for st in g.get("steps", []):
            st["query"] = widen(st.get("query"))
        return g

    authored = {}
    for i, (f, s) in enumerate(zip(flags, solved)):
        if s.get("status") == "skipped":
            continue
        print(f"[author {i+1}] {f['flag']} ...", flush=True)
        authored[i] = author_one(i, f, s)

    # 4. leak check (deterministic, then one model pass for paraphrase), then ONE rewrite of each leaky flag
    context = list(orient.get("tables") or []) + list(orient.get("hosts") or []) + [entry.get("workspace"), guid]

    def model_leak_pass(items, label):
        if not items:
            return {}
        payload = [{"n": i, "answer": g["reveal"].get("answer"), "accept": g["reveal"].get("accept") or [],
                    "choices": g["reveal"].get("choices") or [],
                    "manual_without_reveal": {k: v for k, v in g.items() if k != "reveal"}} for i, g in items]
        text, _ = run_claude(
            "For each flag, does any text outside the reveal state or all-but-state the answer (paraphrase, a "
            "giveaway filter, an exact value, a description that maps to exactly one tool or file, wrong choices "
            "ruled out by name, the conclusion of a judgement flag)? Leading hints about WHERE to look are fine. "
            "List the leaking fields as paths like objective, where_to_look.why_here, steps[1].look_for. Reply:\n"
            '```json\n{"leaks": [{"n": 0, "leak": false, "fields": [], "where": ""}]}\n```\n\n'
            + json.dumps(payload, ensure_ascii=False), AUTHOR_SYSTEM, tools=False, max_turns=2, label=label)
        try:
            return {x["n"]: x for x in last_json(text).get("leaks", []) if x.get("leak")}
        except ValueError:
            return {}

    def leaks_of(i, g, model):
        hits, info = leak_report(g, [solved[k].get("answer") for k in range(i)], context)
        m = model.get(i) or {}
        return {"terms": hits, "info": info, "model": m.get("where") or None,
                "fields": sorted(set(leak_fields(g, hits)) | set(m.get("fields") or []))}

    print("[leak-check] ...", flush=True)
    model = model_leak_pass(sorted(authored.items()), "leak-check")
    leaks = {i: leaks_of(i, g, model) for i, g in authored.items()}
    first_leaks = {i: lk for i, lk in leaks.items() if lk["terms"] or lk["model"]}
    for i, lk in sorted(first_leaks.items()):
        print(f"[rewrite {i+1}] {flags[i]['flag']}: {lk['fields'] or lk['terms']}", flush=True)
        verdict = "; ".join(filter(None, [f"exact terms {lk['terms']}" if lk["terms"] else "", lk["model"],
                                          f"fields {lk['fields']}" if lk["fields"] else ""]))
        authored[i] = author_one(i, flags[i], solved[i], authored[i], verdict)
    if first_leaks:
        model2 = model_leak_pass([(i, authored[i]) for i in sorted(first_leaks)], "leak-recheck")
        for i in first_leaks:
            leaks[i] = leaks_of(i, authored[i], model2)

    # 5. validate: re-run every authored query exactly as written (after any rewrite)
    queries = sorted({st["query"] for g in authored.values() for st in g.get("steps", [])
                      if st.get("query") and not st["query"].strip().startswith("(")})
    print(f"[validate] re-running {len(queries)} authored queries ...", flush=True)
    rerun = {}
    if queries:
        listing = "\n\n".join(f"QUERY {n+1}:\n{q}" for n, q in enumerate(queries))
        _, rtrace = run_claude(
            f"Workspace GUID: {guid}\nRun each query below with la_query exactly as written (timespan \"all\", "
            f"max_rows 50), one call per query, in order. Do not change them and do not analyse. Then reply \"done\".\n\n{listing}",
            SOLVER_SYSTEM, tools=True, max_turns=len(queries) * 2 + 4, label="validate")
        for t in rtrace:
            q = (t.get("input") or {}).get("query", "")
            rerun[q.strip()] = {"status": t.get("status"), "rows": t.get("rows_returned"), "error": t.get("error")}

    flag_status, guide_flags = {}, []
    for i, g in sorted(authored.items()):
        st = solved[i]["status"]
        lk = leaks[i]
        hits = lk["terms"]
        runs = []
        for step in g.get("steps", []):
            q = (step.get("query") or "").strip()
            if q and not q.startswith("("):
                r = rerun.get(q, {"status": "not re-run"})
                runs.append({"query": q[:80], **r})
        bad_runs = [r for r in runs if r.get("status") != "Success"]
        # Reasoned: no row can hold the answer (knowledge or judgement); a human checks the reasoning in review
        tag = "Leak" if (hits or lk["model"]) else ("Unconfirmed" if st == "unconfirmed" else
              ("Query failed" if bad_runs else ("Reasoned" if st == "reasoned" else "Confirmed")))
        fl = first_leaks.get(i)
        flag_status[g["flag"]] = {"tag": tag, "solve_status": st, "leak_terms": hits, "leak_info": lk["info"],
                                  "model_leak": lk["model"], "leak_fields": lk["fields"],
                                  "rewritten": bool(fl), "first_leak": fl and {k: fl[k] for k in ("terms", "model", "fields")},
                                  "reruns": runs, "matches_known": solved[i].get("matches_known"),
                                  "note": solved[i].get("note")}
        guide_flags.append(g)

    o_query = orient.get("orientation_query") or ""
    guide = {
        "hunt": ARGS.slug, "title": entry["title"], "mode": "instruction-manual",
        "note": "Generated draft. Review every flag before publishing.",
        "workspace": f"{entry.get('workspace')} ({guid})",
        "orientation": {
            "title": "Before any flag: get your bearings",
            "why": "You never start by querying for the answer. You start by learning the ground: which tables hold data, over what time window, and for which host.",
            "do": "Run this. It tells you what telemetry exists and how much.",
            "query": widen(o_query),
            "look_for": f"Tables: {', '.join(orient.get('tables') or [])}. Host(s): {', '.join(orient.get('hosts') or [])}.",
            "gotcha": (f"Every row's TimeGenerated is the time the lab loaded the logs. The real event time is in "
                       f"{orient.get('time_column')}. Sort and filter on it, never TimeGenerated.")
                      if orient.get("timegenerated_is_load_time") else (orient.get("notes") or ""),
        },
        "flags": guide_flags,
    }
    strip = lambda tr: [{k: v for k, v in t.items() if k != "_raw"} for t in tr]
    solve_out = {"hunt": ARGS.slug, "generated": True, "orientation": orient, "orient_trace": strip(otrace),
                 "flags": [{**f, **{k: v for k, v in s.items() if k != "trace"}, "trace": strip(s.get("trace", []))}
                           for f, s in zip(flags, solved)]}
    meta = {"slug": ARGS.slug, "registry_status": entry["status"], "created_by": "ken (local CLI)",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "model": ARGS.model or "default",
            "budget_per_flag": ARGS.budget, "mcp_loading": MODE, "flags": flag_status,
            "job": {**STATS, "cost_usd": round(STATS["cost_usd"], 4), "duration_s": round(time.time() - t0)}}
    for name, obj in (("guide.json", guide), ("solve.json", solve_out), ("draft.meta.json", meta)):
        (out / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("\n== Draft written to", out.relative_to(ROOT))
    for name, fs in flag_status.items():
        extra = (" (rewritten once)" if fs["rewritten"] else "") +                 (f" leak[{', '.join(fs['leak_fields'])}]:{fs['leak_terms'] or fs['model_leak']}" if fs["tag"] == "Leak" else "") + \
                (f" info:{fs['leak_info']}" if fs.get("leak_info") else "") + \
                (f" known:{'ok' if fs['matches_known'] else 'MISMATCH'}" if fs["matches_known"] is not None else "")
        print(f"  {fs['tag']:<13} {fs['solve_status']:<11} {name}{extra}")
    j = meta["job"]
    print(f"\nTotals: {j['calls']} model calls, {j['queries']} la_query calls, "
          f"{j['input_tokens'] + j['cache_read_tokens'] + j['cache_write_tokens']:,} input tokens "
          f"({j['cache_read_tokens']:,} cached), {j['output_tokens']:,} output tokens, "
          f"${j['cost_usd']:.2f}, {j['duration_s']}s")


def selftest():
    qs = parse_questions("## 1 Initial Access | Q1 - X | 75\nWhich IP?\nformat: IP:Port\n\n## 8 Judgement | Q1 - Y | 100\n"
                         "Why?\nchoices: A | B\n")
    assert len(qs) == 2 and qs[0]["format"] == "IP:Port" and qs[1]["choices"] == ["A", "B"]
    try:
        parse_questions("## nope\nq"); raise AssertionError("bad header accepted")
    except ValueError:
        pass
    assert norm("Tasklist , SYSTEMINFO", True) == norm("systeminfo, tasklist", True)
    assert norm("b.exe, a.exe") != norm("a.exe, b.exe")                      # ordered unless the flag says list
    assert is_unordered({"format": "two commands, comma separated"}) and not is_unordered({"format": "the full command line"})
    assert is_unordered({"unordered": True})
    assert norm('"MSUpdate.exe"') == norm("msupdate.exe")
    rows = '{"rows":[{"FileName":"systeminfo.exe"},{"ProcessCommandLine":"C:\\\\Windows\\\\system32\\\\tasklist.exe /svc"}]}'
    assert found_in_rows("systeminfo, tasklist", rows, True)                 # each item, .exe and path prefixes ok
    assert not found_in_rows("systeminfo, whoami", rows, True)
    assert found_in_rows('"x.exe" -File C:\\Users\\Public\\a.ps1', '{"c":"\\"x.exe\\" -File C:\\\\Users\\\\Public\\\\a.ps1"}', False)
    ch = ["Network Level Authentication", "Account Lockout Policy", "Windows Firewall rule", "BitLocker"]
    assert shuffle_choices(ch, "s|f") == shuffle_choices(list(reversed(ch)), "s|f") and sorted(shuffle_choices(ch, "s|f")) == sorted(ch)
    ctx = {"steps": [{"look_for": "host slflarewinsysmo"}], "reveal": {"answer": "slflare"}}
    assert leak_hits(ctx) and not leak_hits(ctx, context=["slflarewinsysmo"]) and leak_report(ctx, context=["slflarewinsysmo"])[1]
    acc = {"steps": [{"look_for": "look for MSUpdateSvc"}], "reveal": {"answer": "MSUpdateService", "accept": ["MSUpdateSvc"]}}
    assert leak_hits(acc)                                                       # accept spellings count as answers
    first = {"steps": [], "reveal": {"answer": "A", "choices": ["A", "B"]}}
    assert leak_report(first)[1] and not leak_report(first)[0]
    import base64 as b64, gzip as gz, urllib.parse as up
    u = defender_url("T_CL\n| take 1", "tid1")
    q = up.parse_qs(up.urlparse(u).query)
    assert gz.decompress(b64.b64decode(q["query"][0])).decode("utf-16-le") == "T_CL\n| take 1" and q["tid"] == ["tid1"]
    assert "185.92.220.87" in answer_forms("185.92.220.87:8081")
    assert "msupdate.exe" in answer_forms('"msupdate.exe" -ExecutionPolicy Bypass -File C:\\Users\\Public\\update_check.ps1')
    assert answer_forms("One host serves both C2 and exfil on different ports, so the attacker runs one server") == []
    leaky = {"steps": [{"query": 'X | where RemoteIP == "159.26.106.84"'}], "reveal": {"answer": "159.26.106.84"}}
    clean = {"steps": [{"query": "X | summarize count() by RemoteIP"}], "reveal": {"answer": "159.26.106.84"}}
    assert leak_hits(leaky) and not leak_hits(clean)
    assert leak_fields(leaky, leak_hits(leaky)) == ["steps[0].query"] and leak_fields(clean, []) == []
    path = {"steps": [{"look_for": "the file C:\\Users\\Public\\update_check.ps1"}], "reveal": {"answer": '"a.exe" -File C:\\Users\\Public\\update_check.ps1'}}
    assert leak_hits(path)
    reuse = {"steps": [{"query": 'X | where RemoteIP == "185.92.220.87"'}], "reveal": {"answer": "185.92.220.87:8081"}}
    assert leak_hits(reuse) and not leak_hits(reuse, ["185.92.220.87"])
    gap = {"steps": [{"query": 'T_CL\n| where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"\n| project Timestamp, RemoteIP',
                      "look_for": "each row has ActionType LogonSuccess"}]}
    assert len(project_gaps(gap)) == 1 and "ActionType" in project_gaps(gap)[0]       # LogonType isn't in the hint
    gap["steps"][0]["query"] = gap["steps"][0]["query"].replace("RemoteIP", "RemoteIP, ActionType")
    assert project_gaps(gap) == []
    assert widen("T_CL\n| count").split("\n")[1].startswith("| where TimeGenerated > ago(365d)")
    assert widen("let x = 1;\nT_CL") == "let x = 1;\nT_CL" and widen("(no query, reason it out)").startswith("(")
    # the hand-written RDP-Flare manual must pass the same leak check the generator applies
    g = json.loads((HUNTS / "rdp-flare" / "guide.json").read_text(encoding="utf-8"))
    hj = json.loads((HUNTS / "rdp-flare" / "hunt.json").read_text(encoding="utf-8"))
    ctx = hj["tables"] + [hj["host"], hj["workspace"]["name"]]
    for n, fl in enumerate(g["flags"]):
        hits = leak_hits(fl, [x["reveal"]["answer"] for x in g["flags"][:n]], ctx)
        assert not hits, f"hand-written {fl['flag']} leaks {hits}"
        assert not project_gaps(fl), f"hand-written {fl['flag']}: {project_gaps(fl)}"
    reg = [e for e in load_registry() if e["status"] not in ("practice", "retired", "live")]
    assert not reg, f"registry status must be practice|retired|live: {reg}"
    print("selftest ok")


if __name__ == "__main__":
    main()
