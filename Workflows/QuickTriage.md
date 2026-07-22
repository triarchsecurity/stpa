# Workflow: QuickTriage — bounded STPA on one change or one subsystem

The full method costs hours. Most security questions arrive attached to a pull request or a single feature and deserve minutes. QuickTriage keeps the method's shape — control actions, four types, contexts, constraints — and cuts everything that only pays off at system scale.

## Scope bound (this is the whole point)

**Hard limits, enforced by refusal rather than by effort:**

- **≤5 control actions.** More than five means this is not a triage; run `FullAnalysis.md`.
- **≤3 hazards**, inherited from an existing scope artifact if one exists, otherwise stated in one line each.
- **No full control-structure model.** One paragraph and, at most, a five-node diagram.
- **No parallel delegation.** Single pass.
- **Target ≤20 minutes.**

If the target exceeds the bound, say so and escalate rather than doing a bad full analysis. A triage that quietly becomes a half-finished system analysis is worse than either.

## Inputs

- A diff, a PR, a single feature, or one subsystem.
- Optionally an existing `01-scope.md` — reuse its losses and hazards rather than re-deriving them.

## Outputs

- A short markdown block: control actions, the UCA table, and constraints with probes.
- **`REPORT.html`** whenever a `grid.json` was produced — the default output format for this toolkit. Triage that stays in chat is triage nobody can hand to anyone:
  ```bash
  stpa report .stpa --title "PR #123 triage"
  ```
  Skip it only for a genuinely inline answer where no grid file was written; say so if you skip it.
- Optionally appended to the project's spec or test suite as negative assertions.

## Steps

1. **State what could go wrong at stakeholder level, in one line.** Reuse existing losses if a scope artifact exists. If not: *"the loss we care about here is ___."* One line, not a list.

2. **Name the control actions this change introduces or modifies.** Look for: a new entry point; a new authority decision; a new write path to existing state; a new external effect; a change to who or what can invoke an existing action. Cap at five.

3. **Run the four types against each action.** In your head or in a table — but all four, every action. Type 4 (too long / stopped too soon) is the one that gets skipped and the one most likely to yield something here, because changes commonly alter lifetimes: a new cache, a new token, a new retry, a new lock, a new background job.

4. **For each candidate, write the five-part sentence.** If you cannot name a specific context, there is no finding — say so and move on. Resist the urge to record a vague concern; vague concerns are what make people stop reading threat models.

5. **Check the process-model question explicitly.** One question, highest yield per second in the whole method: *does this change introduce a new belief the code holds about system state, and where does that belief come from?* A new cache, a new claim in a token, a new header trusted, a new default, a new denormalized copy — each is a process model that can go stale or be poisoned.

   Use the answer to *find* candidates, then write the finding correctly: the UCA context states the true state ("…when the record belongs to another tenant"), and the belief goes in the scenario ("…because tenant identity comes from a request header"). Beliefs in a UCA context is the Handbook error this method most often makes in software.

6. **Emit constraints with probes.** Same form as `SecurityConstraints.md`: a `MUST NOT` assertion plus a runnable probe. Two or three is a good triage; ten means you should have run the full analysis.

7. **State the bound you worked under.** *"Triage scope: the 3 control actions this PR adds. The surrounding control structure was not modeled."* This is what makes a triage honest rather than a full analysis that quietly fell short.

## When to escalate to FullAnalysis

- The change adds a controller, not just a control action.
- The change crosses a trust boundary that was not previously crossed.
- The change gives an existing controller authority it did not have.
- You find a UCA whose context is "always" — that is a design defect, and design defects need the control structure to fix properly.
