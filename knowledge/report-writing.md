# Report writing: how to turn a solved hunt into a report that scores

Solving the hunt is half the work. The report is what gets marked, and it is what a reader learns from. This
is the method behind a good one, built on the Range's marking rubric and the lessons from a past hunt's debrief.

## The reader and the bottom line
A reviewer reads the first paragraph and decides what they think of the whole report. So **lead with the
bottom line**: in three or four sentences, what happened, how far it got, and the impact. Everything after is
the evidence for that paragraph. Never make the reader assemble the story themselves.

Then a **timeline of timed bullets** (UTC), entry to objective, each line a real event with its timestamp.
Then the findings, ordered by confidence. Then detections and gaps.

## The six marking categories: write a section to each
| Category | What a top answer contains |
|---|---|
| **Evidence** | Every claim has a row behind it. The exact query and its result, not a paraphrase. |
| **Kill chain** | The attacker's steps in order: initial access → execution → persistence → privilege escalation → collection → exfil. Map each to a technique. |
| **Scope** | Everything touched: every host, account, file, and connection. "What else did they do?" answered, not just the first flag. |
| **Detection** | At least one authored detection rule (a KQL query that would catch this next time) **and an honest false-positive discussion** of what benign activity it would also flag. |
| **Gaps** | What the telemetry could not show, and for each gap **the specific change that closes it** (enable command-line auditing, add a SACL, forward DNS). |
| **Craft** | Clear prose, confidence labels, reproducible queries, consistent terminology. |

## Three lessons from a hunt debrief: bake these into every report
1. **A confidence label on every inference.** Confirmed / Probable / Possible. "The account was created by the
   attacker (Confirmed: 4720 under the compromised session)" vs "likely used for persistence (Probable)."
   Guessing dressed as certainty is the fastest way to lose Evidence and Craft marks.
2. **Authored detections with their false positives.** Don't just say "monitor for new admins." Give the
   query, then say plainly what legitimate activity it would also catch and how you'd tune it. A detection
   with no FP discussion reads as untested.
3. **Each gap paired with its fix.** A gap is only useful if you say how to close it. "No command-line
   auditing, so we could not see script arguments → enable Audit Process Creation with command line, GPO X."

## Findings, ordered by confidence
List findings strongest-evidence first. Each finding is: the claim, the confidence, the evidence (query +
result), and what it means for the kill chain. One claim per finding; if a row supports two claims, make two
findings.

## Writing rules (house style)
- Write the bottom-line summary **once**, and make every later retelling match it. Don't let the abstract and
  the conclusion disagree.
- Plain language. State mechanisms directly; no filler, no drama.
- One wording for anything you can't prove ("consistent with", "probable"), used consistently.
- Name monitoring gaps explicitly; a gap you flag is a point you earn, a gap you hide is a point you lose.
- No placement or scoring claims in a public writeup until the hunt's results are posted. (HuntCraft only
  publishes solved/closed hunts, so this is already satisfied, but keep the habit.)

## Build the report from your own capture trail
Keep a record as you hunt: for each flag, the question, the exact query, the rows that answered it and what they
told you. That record already is your Evidence and Kill-chain content. The report then adds the bottom line, the
timeline, the authored detections with their false positives, and the gaps with their fixes. Because the
evidence is the real data you queried, the report and your results can never disagree.
