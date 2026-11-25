# HuntCraft: Phased Solution Plan

Cairn stages per phase: Charter · Approve · Implement · Rehearse · Notch. Updated 25 Nov 2026.

| Phase | What | State |
|---|---|---|
| 0 Charter | Scope, design, scaffold, name | Done (`SolutionDesign.md`) |
| 1 Knowledge base | Method, KQL cookbook, log tables, report writing; rendered in the site's design | Done |
| 2 First worked hunt | RDP-Flare (practice, 11 flags) solved live through the MCP; manual in `hunts/rdp-flare/guide.json`; publishing cleared 25 Nov | Done |
| 3 Member site | Two-pane instruction manual, Defender links, UTC setup, hashed checks, lock-first free text, 404, OG image, favicon | Done, live |
| 4 Generator + review | `tools/generate.py` (solve, author, leak check, one rewrite, re-run) and `tools/review.py` (local review and publish) | Done (uses the Range MCP as it is: the claude.ai connector, deferred tool loading) |
| 5 Deploy + repo + launch | Pages deploy; public repo `kenmwara/huntcraft` (code, site, manuals); private `kenmwara/huntcraft-solutions` (solve trails, reports, answer files, drafts, Chat handovers); Skool launch post (drafted for Ken to send) | Repos done; post open |
| 6 Hosted generator | The "add a hunt" box for members (design brief in the private repo) | Parked: the Range MCP is used as it is (each member's own claude.ai connector), so generation stays local for now |

## How a draft reaches the library
Drafts carry their answers (the reveal, the solve trail), so they never travel through the public repo.

| Step | Who | Detail |
|---|---|---|
| Propose | member | A pull request on the public repo with `hunts/<slug>/questions.md` and a registry entry (no answers) |
| Generate | member or Ken | `python tools/generate.py <slug> --questions ...` on their own Claude account and Range sign-in; writes `private/_drafts/<slug>/` (git-ignored) |
| Hand over | member | The draft folder goes to Ken privately (not a PR); Ken commits it to the private solutions repo |
| Review | Ken | `python tools/review.py`, http://127.0.0.1:8770: tags, leaks by field, re-run, edit, mark reviewed |
| Publish | Ken | Publish on the review page: writes `hunts/<slug>/guide.json` and the registry `clearance`, keeps the solve trail in `private/`, runs `build.py` |
| Deploy | Ken | `npx wrangler pages deploy site --project-name huntcraft --branch main` |

## Two repos, one working folder
- `C:\Workspaces\huntcraft` is the public repo. `private/` inside it is a separate clone of the private repo and is
  git-ignored by the public one. `build.py` never reads `private/`.
- Public: code, site, knowledge, `hunts/<slug>/{guide.json, hunt.json, questions.md}`, registry. The guide's reveal
  answers are already public on the site (the reveal files), so they add nothing new.
- Private: `private/<slug>/{solve.json, report.md, answers.json, hunt.private.json}`, `private/_drafts/`, `private/docs/`.

## Open items
- Skool launch post (drafted for Ken to send).
- Decided 25 Nov: use the Range MCP as it is. It accepts sign-ins only from the claude.ai connector, so the
  generator runs on that connector with deferred tool loading; no change is asked of the Range.
