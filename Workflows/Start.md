# Workflow: Start — interactive intake, then run the whole assessment

Runs on a **bare invocation** (no target), or on *"how does this work"*, *"walk me through it"*, *"where do I start"*.

**This is the front door. It must ask, then do.** Never answer a bare invocation with "send me a task" — that makes the user do the orientation and they cannot know there are several workflows, that they supply the losses and process models, or whether this costs twenty minutes or a day.

**You have `AskUserQuestion` here** — the skill deliberately does not set `context: fork`, precisely so this workflow can ask. Use it.

## Steps

### 1. Open with the banner, then say what this is

Print the banner verbatim. It exists because a wall of prose on invocation reads as setup cost, and a framed header reads as a tool starting up.

```
  ╭──────────────────────────────────────────────────────────────╮
  │   ▲  T R I A R C H   ·   S T P A                             │
  │      Control-theoretic threat modeling                       │
  ╰──────────────────────────────────────────────────────────────╯
```

Then, in this shape — short, concrete, no theory lecture, no Leveson unless asked:

```
I find the security problems that exist when every component works
exactly as designed.

  What this finds     broken authorization, tenant leaks, TOCTOU,
                      stale permissions, bypass paths — the class where
                      nothing is broken and the composition is unsafe
  What it will not    CVEs, injection, dependency audit. Use SAST for those.
  How it works        map who has authority over what → ask four questions
                      about every authority-bearing action → hand you a
                      ranked backlog with file:line and a check per item
  What you supply     the losses that matter, and corrections to my draft
                      of what each component believes
  Cost                20 min for a PR · a few hours for a full service

Four questions, then the repo link, then I run the whole thing.
```

**This intake is a short facilitated conversation, not a form.** STPA's power is the system owner's knowledge — deployment topology, what would actually hurt, what is really deployed — which a scan cannot see; facilitated threat-modeling sessions catch the design-level threats automated scans miss ([UK Gov Secure-by-Design](https://www.security.gov.uk/policy-and-guidance/secure-by-design/activities/performing-threat-modelling/); Fowler, *Agile Threat Modelling*). Three rules follow: **(a)** ask the minimum to start and draw the rest out as you go — do not interrogate; **(b)** always offer a **"proceed with sensible defaults"** escape for a user who just wants a result (infer scope/depth, note what you assumed, run); **(c)** for a user new to this, **prefer a focused, timeboxed first pass over full-surface** — frequency over scale beats one exhaustive run. Full-surface is the right call for a deliberate audit, not a first look.

### 2. Round one — four questions, one `AskUserQuestion` call

**The exact four. Do not re-derive them.**

| # | Header | Question | multiSelect |
|---|---|---|---|
| 1 | `Inputs` | What am I working from? — *A codebase* / *A design document* | **yes** |
| 2 | `Scope` | How much of the system should I cover? | no |
| 3 | `Depth` | How deep should the code scan go? | no |
| 4 | `Losses` | What would actually hurt? — in **business** terms | **yes** |

**Do not ask for the org, and do not enumerate repos.** An earlier design asked org → repo → branch as selectable options and failed three times in a row, each differently, always with the repo question disappearing. **The link carries the org, the repo and often the branch in one string the user can paste from their address bar.** That is faster to answer than any list, works for orgs and hosts you cannot enumerate, and cannot lose a question between rounds.

Say plainly under `Scope` that **full surface is a contract**: `ScopeGate` fails the run on under-delivery and rejects "didn't get to it" as a deferral reason. Ask `Losses` in business terms — losses are a business judgment, and security vocabulary produces security-shaped answers.

**Never hand-write a "Type it" / "Other" option.** `AskUserQuestion` appends its own free-text escape automatically. A hand-made one returns its own label as the answer — you learn nothing and the flow stalls into prose. Every option must be a real value.

### 3. Ask for the link — plainly, in one line

Immediately after round one returns, ask in text. No tool call, no list:

```
Paste the repo link (or a local path):
```

For a design document, ask for its URL or path in the same message. Accept anything: an HTTPS URL, an SSH remote, `org/repo`, or a bare path. Parse the org, repo and ref from it and **echo back what you resolved** so a wrong paste is caught in one line rather than after the scan:

```
→ triarchsecurity/darksouls @ main (4e3e660) · 53 routes · cloning shallow
```

If the link has no ref, ask which branch — one line, not a question round. Never assume `main`, and never assume whatever is checked out locally. If a local checkout exists, use a **worktree**; never switch their branch.

### 3a. Per-input locators for anything that is not a codebase

| They also selected | Ask for | Then |
|---|---|---|
| A design document | file path **or** URL | Fetch or read it before proceeding. Say which you got. |

**If a design document is in the inputs, offer the STRIDE pre-pass — one line, right here.** A design doc is exactly what STRIDE-per-element wants, and its trust-boundary / data-flow / asset output *seeds* the STPA control structure (the trust-boundary layer is the one whose absence most often mis-rates findings). Ask plainly: *"Want me to run a STRIDE pass first and feed it in? — recommended when a design doc exists; it seeds the trust zones and cross-checks coverage."* If yes, run `SeedWithStride.md` before Step 2. If code-only (no design doc), skip it or offer to run it against a short architecture summary you extract.

For a git URL: look for a local checkout first, otherwise clone shallow. **Never switch their checked-out branch — use a worktree.**

### 3b. Record what you actually consulted

Write every resolved input into `model.json` as you confirm it:

```json
"scope": {
  "sources": [
    { "type": "codebase", "locator": "triarchsecurity/darksouls", "ref": "main @4e3e660", "note": "shallow clone" },
    { "type": "design-doc", "locator": "docs/architecture.md", "ref": "read 2026-07-22" }
  ]
}
```

This is provenance, and it is the difference between "we threat modeled it" and a statement someone can check. It also stops the commonest quiet failure in the combined case: a design document that was *offered* and never actually read, while the report implies both were consulted.

### 3d. Record the scope contract — FIRST WRITE, before any analysis

Their Q2 answer is a **contract**, not a preference. Write it into `model.json` immediately:

```json
"scope": {
  "requested": "full",                 // or "focused:authz" | "focused:external" | "triage"
  "candidateControlActions": 0,        // fill from the real inventory, not from what you plan to do
  "selectionCriteria": "",
  "deferred": []
}
```

**Why this is a separate step and not a footnote.** Surface coverage is `modeled / candidateControlActions`, and the analyst sets both numbers. Left unrecorded, the intake answer lives only in conversation, and the only party who can grade the result is the party who decided how much to do. This has already happened once: a full-surface request was delivered at 60% with six deferrals reading "not read this pass", and nothing caught it. `stpa scope` now does — but only if the contract is on disk.

**Under `requested: "full"`, these rules bind you:**
- Every candidate control action must be modeled. Unmodeled ≠ deferred.
- **"not read" is not a deferral reason.** A valid deferral says why the thing does not need analysing — exercises no authority, outside the declared boundary, static content with no tenant dimension. "Nobody got to it" means outstanding, not deferred.
- **Narrowing scope is the requester's decision, not yours.** If it is taking longer than expected, say so and ask — do not quietly deliver less and write the shortfall up as a boundary.

### 3e. Ask the deployment & trust context — one round, and it is not optional

**This is the round that was missing, and its absence produced a real mislocated finding.** Reachability and blast radius — which set every finding's severity — are properties of the *deployment*, not the code, and only the owner reliably knows them. Asking costs one round; not asking means the analysis rates internal, one-tenant, foothold-required paths as if they were external, cross-tenant, zero-foothold ones (and misses the central plane where cross-tenant risk actually lives). Fire one `AskUserQuestion`:

| # | Header | Question | multiSelect |
|---|---|---|---|
| 1 | `Tenancy` | How is it deployed? — *single-tenant per customer (each in their own environment)* / *multi-tenant shared* / *per-customer + a central control plane* / *not sure* | no |
| 2 | `Who reaches what` | Which surfaces are internet-facing vs internal-only, and who can authenticate — customers, staff, both? | **yes** |
| 3 | `Non-code controls` | What enforces boundaries *outside the code* — IAM, network isolation/private subnets, a WAF, broker ACLs? | **yes** |

Always include the honest escape: **"not sure — infer from the infra and mark the dependent findings provisional."** If they pick that, gather what you can from terraform/IaC, network config and IAM yourself, and tag every band that rides on an unconfirmed fact as provisional (see the reachability gotcha). Record the answers into `model.json` `scope.trustZones` and the assumptions log — they gate the bands.

### 4. State what you need from them, then start

```
Three things only you can supply. I'll draft each and you correct me:
  1. Losses      — from your Q4 answers
  2. Hazards     — system states that lead to them (NOT attacker actions)
  3. Process models — what each component BELIEVES, where the belief comes
                      from, how stale it can be   ← most findings come from here

The tools do arithmetic. The judgment is yours.
```

Then **run it**. Do not stop and ask for permission to begin — they already answered four questions.

### 5. Run the assessment, announcing progress

A full run is long. Announce each step so nobody wonders whether it hung:

```
[1/6] Losses and hazards    [2/6] Control structure   [3/6] Unsafe control actions
[4/6] Loss scenarios        [5/6] Constraints         [6/6] Plan + report
```

Follow `FullAnalysis.md` (or `QuickTriage.md` for a PR). Their Q2 answer becomes the scan `--focus`; Q3 becomes `--depth`; Q4 becomes the loss list in `01-scope.md`.

**If you fan out to parallel agents, the delivery contract is non-negotiable** — write a `manifest.json` first, have delegates `Write` to `.stpa/planes/<name>.json`, and gate with `stpa merge --expect`. Delegates that return payloads as messages fail silently; see the SKILL.md gotcha.

### 6. Finish on a complete artifact, or say why not

**`stpa run` gates the scope contract first**, then prioritises, then renders. It exits non-zero if the delivered scope does not honour the requested one, or if a required section is missing. Run the gate directly any time you want to check yourself mid-analysis:

```bash
stpa scope .stpa --inventory <route count>
```

**Do not report success on a non-zero exit.** The report will carry a banner saying the scope was not delivered as requested, or that a required section is missing, and it will be right.

End with:

```
→ .stpa/REPORT.html    open in any browser (self-contained, works offline)
→ Wave 1 is where to start: N items
→ Every item has a file:line and a command that fails now and passes after the fix
→ Coverage: X% of the grid, Y% of the system
```

Always give **both** coverage numbers. One without the other is how "100%" becomes a false assurance.

## Anti-patterns

- **Asking one question at a time.** Four sequential round trips for information you could gather in one is a worse interface than a form.
- **Asking then stopping.** The intake exists to start the work, not to produce a plan for the work.
- **Lecturing.** Credibility comes from the findings. `METHOD.md` is there for anyone who wants the theory.
