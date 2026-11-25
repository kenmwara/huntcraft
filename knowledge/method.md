# The hunt method

The repeatable loop HuntCraft follows on every hunt. A beginner can read this and run the same steps by hand.
Nothing here is hunt-specific.

## The shape of a hunt
A hunt gives you a **scenario brief** (a story: "a web server was breached, find how far it got") and a set of
**flags** (specific questions: "what was the attacker's IP?", "what account did they create?"). Your job is to
answer each flag from the **telemetry** (the logs the environment recorded). You are not guessing; the answer
is in the data, and your task is to ask the data the right question.

## The loop {#the-loop}
For the hunt as a whole, and again for each flag:

1. **Orient.** Before any flag, learn the ground.
   - Which log tables exist and have data? (`union withsource=T * | summarize count() by T`)
   - What is the time window of the incident? (`<Table> | summarize min(Timestamp), max(Timestamp)`; in a lab
     `TimeGenerated` is only the load time, see [two clocks](kql-cookbook.html#two-clocks))
   - Which hosts and accounts are in play? (`summarize by DeviceName`, `by AccountName`)
   See the [KQL cookbook: Orientation](kql-cookbook.html#orientation).

2. **Turn the flag into a question.** A flag is a question in disguise. "Identify the persistence mechanism"
   becomes "what account, service, task, or run-key was created during the incident window?" Write the
   plain-English question first; the query comes from it.

3. **Form a hypothesis.** Based on the kill chain, guess where the answer lives. "If they got a shell, the
   first PowerShell under the web-service account is the entry." A hypothesis tells you which **table** and
   which **column** to look at. A wrong hypothesis is fine; the data corrects you.

4. **Query.** Write the smallest KQL that tests the hypothesis. Filter by the incident window and the host.
   Project only the columns that matter so you can read the result.

5. **Read the result.** Look at what came back, not what you hoped. Is it one clean row, or noise? If noise,
   add a filter (a time slice, an account, exclude a known-good process). If empty, your hypothesis or your
   table was wrong; go back to step 3.

6. **Pivot.** Most flags are a chain. A process gives you a PID and a parent; the parent gives you the entry;
   the process's network events give you the C2 IP. Each result carries the key for the next query. Follow it.

7. **Confirm the flag.** State the answer and the single query + result that proves it. If you can't point to
   a row that shows it, you haven't solved it, you've guessed it.

8. **Record.** Capture the tuple: the question, the hypothesis, the exact KQL, the real result, what it told
   you, and the pivot it enabled. This record IS the teaching material and the report evidence.

## Evidence discipline (carried from a hunt debrief)
- **Label every inference with a confidence.** "The attacker used account X" (confirmed, 4720 shows creation)
  vs "the attacker likely pivoted via RDP" (probable, logon type 10 but no screen capture). Say which.
- **One query, one claim.** Don't let a result imply three things. If you claim it, show the row.
- **Name what you could not see.** A gap in the telemetry (no DNS logs, no command-line auditing) is itself a
  finding. Record it.

## Framing the work: the six marking categories
Hunts are marked on six axes (the Range's rubric). Hunt *with them in mind* so the report writes itself:
| Axis | What it asks of your hunting |
|---|---|
| Evidence | Every claim backed by a real row |
| Kill chain | The steps in order, entry → actions → objective |
| Scope | Everything the attacker touched, not just the first thing |
| Detection | A rule that would catch this next time + its false positives |
| Gaps | What the telemetry missed and the specific fix |
| Craft | Clear writing, confidence labels, reproducible queries |

See [Report writing](report-writing.html) for how the capture trail becomes the report.
