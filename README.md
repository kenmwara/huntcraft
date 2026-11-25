# HuntCraft

A step-by-step threat-hunting instruction manual for Cyber Range members: https://huntcraft.kenmwara.com

For each flag of a practice hunt, HuntCraft explains where to look and why, gives one query at a time with the
reasoning behind it, and says what pattern to look for. Members run every query in Microsoft Defender and find the
flag themselves. It is never an answer key: answers stay hidden behind a hashed check or a reveal.

Built on the Cyber Range MCP (read-only KQL over each hunt's Log Analytics workspace). Practice and retired hunts
only, never the live one.

**About the answers in this repo:** each flag's answer can be revealed on the site, so the reveal files
(`site/reveals/`) are public by design, the same as clicking Reveal. The solve trail and reports that produced them
live in a separate private repository.

Members can request a hunt at https://huntcraft.kenmwara.com/request (backend: `worker/request`, a Cloudflare Worker
with Turnstile, a rate limit, D1 storage and an email notice).

| | |
|---|---|
| Design | [`docs/SolutionDesign.md`](docs/SolutionDesign.md) |
| Plan | [`docs/PhasedSolutionPlan.md`](docs/PhasedSolutionPlan.md) |
| Build the site | `python build.py` |
| Deploy | `npx wrangler pages deploy site --project-name huntcraft --branch main` |
| Deploy the request Worker | `cd worker/request && npx wrangler deploy` |
| Generate a draft | `python tools/generate.py <slug> --questions hunts/<slug>/questions.md` |
| Review and publish | `python tools/review.py`, then open http://127.0.0.1:8770 |
| Checks | `python tools/generate.py --selftest` and `python tools/review.py --selftest` |
