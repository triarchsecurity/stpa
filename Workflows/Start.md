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
| 1 | `Method` | Which analysis? — *STPA + STRIDE (recommended)* / *STPA only* / *STRIDE only* | no |
| 2 | `Inputs` | What am I working from? — *A codebase* / *A design document* | **yes** |
| 3 | `Scope` | How much of the system should I cover? | no |
| 4 | `Losses` | What would actually hurt? — in **business** terms | **yes** |

**Depth is no longer a question.** It was one, and the answer never changed the analysis — every
respondent picks the deepest option, and the shallow ones exist only to look balanced. Discovery depth
is now a *gate* (`stpa discover`), not a preference: the sweep runs at full depth always, and the
analyst must account for every entry-point modality it finds. Asking someone to opt into thoroughness
is how thoroughness becomes optional. If a run must be time-boxed, that belongs under `Scope`, where
it is recorded as a contract instead of hidden as a dial.

**Q1 phrasing, and why the recommendation is not neutral.** Offer three real options, and say what each
costs in one clause:

- **STPA + STRIDE — recommended.** STRIDE enumerates per-element attacker technique; STPA finds the
  composition/authorization class STRIDE structurally cannot. Together they cross-check each other's
  coverage, and STRIDE's trust-boundary output seeds the layer whose absence is the top cause of
  mis-rated findings. Adds roughly 20 minutes to a multi-hour run.
- **STPA only.** Correct when the target is an authorization architecture, or when a STRIDE model
  already exists from a previous cycle. You lose the per-element sweep and the two-way coverage check.
- **STRIDE only.** Available, and say plainly that it is the weakest of the three: it is a per-element
  technique list, so it will not find broken object-level authorization, tenant bleed at a shared
  plane, confused-deputy, TOCTOU, or bypass paths — the classes this toolkit exists for. Take it when
  the ask is a fast design-review checklist against a document, or when someone needs STRIDE output in
  a specific format for a compliance artifact. **Never silently upgrade it to STPA** — if they picked
  STRIDE only, deliver STRIDE only, and note in one line what the choice does not cover.

Say plainly under `Scope` that **full surface is a contract**: `ScopeGate` fails the run on
under-delivery and rejects "didn't get to it" as a deferral reason. Ask `Losses` in business terms —
losses are a business judgment, and security vocabulary produces security-shaped answers.

**Do not ask for the org, and do not enumerate repos.** An earlier design asked org → repo → branch as selectable options and failed three times in a row, each differently, always with the repo question disappearing. **The link carries the org, the repo and often the branch in one string the user can paste from their address bar.** That is faster to answer than any list, works for orgs and hosts you cannot enumerate, and cannot lose a question between rounds.

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

Their `Scope` answer is a **contract**, not a preference. Write it into `model.json` immediately
(along with their `Method` answer, so the report states which methods were run):

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
  1. Losses      — from your `Losses` answers
  2. Hazards     — system states that lead to them (NOT attacker actions)
  3. Process models — what each component BELIEVES, where the belief comes
                      from, how stale it can be   ← most findings come from here

The tools do arithmetic. The judgment is yours.
```

Then **run it**. Do not stop and ask for permission to begin — they already answered four questions.

### 5. Run the assessment, announcing progress

A full run is long. Announce each step so nobody wonders whether it hung:

```
[1/9] Losses and hazards      [2/9] Control structure + topology
[3/9] Discovery gate           [4/9] STRIDE seed (if selected)
[5/9] Unsafe control actions   [6/9] Loss scenarios (Part A + Part B)
[7/9] Composition              [8/9] Adversarial review
[9/9] Plan + report
```

Follow `FullAnalysis.md` (or `QuickTriage.md` for a PR). Their `Scope` answer becomes the scan
`--focus`; `Losses` becomes the loss list in `01-scope.md`.

**Three steps are new, and each exists because a real run failed without it. None is skippable.**

- **`[3/9]` Discovery gate — runs BEFORE `stpa init`, and this ordering is the whole point.**
  ```bash
  stpa discover <repo> .stpa --check
  ```
  A grid cannot be initialized against an inventory that was never audited, because coverage is
  computed over the inventory: build it from one search shape and the report earns a truthful,
  meaningless 100%. The gate sweeps ten entry-point modalities and fails (exit 7) on any modality with
  hits that is neither mapped to a control action nor ruled out with a reason. **Three of the ten are
  marked FORGOTTEN** — non-HTTP entry points, in-process command registries, and dynamic-execution
  primitives — because those are the shapes a route sweep structurally cannot see, and in a real run
  they hid an interactive PTY and an `eval` command that a *previous* run of the same target had found.
  If a modality is genuinely outstanding, leave it unmapped and let the gate stay red: a red gate that
  names the hole beats a green one that hides it.

- **`[7/9]` Composition.**
  ```bash
  stpa compose .stpa --check
  ```
  Reachability is not a property of a finding; it is a property of a finding *given what the other
  findings hand the attacker*. Declare `grants` and `requires` on every band-1/2 finding and let the
  tool recompute. It exists because two independent runs each rated a PTY-over-WebSocket at R3
  ("needs a staff identity") while separately rating token forgery at R0 — and neither noticed that
  one finding *is* the prerequisite for the other. Exit 6 means a recorded band is softer than the
  composed one; fix the band or record the control that breaks the chain.

- **`[8/9]` Adversarial review — `AdversarialReview.md`, with a different model.** Not a courtesy.
  `stpa verify` refuses to certify and the report carries a NOT-PEER-REVIEWED banner without it.

**Produce the final artifact with `stpa run` and nothing else.** Calling `RenderReport.ts` (or
`stpa report`) directly renders a report while silently bypassing the scope, plan, composition and
peer-review gates — which is exactly how a run once presented an ungated report as final. `stpa run`
chains all four, prints the banner when one fails, and exits non-zero. If you find yourself reaching
for the individual tool to "just see the output", that is the moment the gates were for.

**If you fan out to parallel agents, the delivery contract is non-negotiable** — write a `manifest.json` first, have delegates `Write` to `.stpa/planes/<name>.json`, and gate with `stpa merge --expect`. Delegates that return payloads as messages fail silently; see the SKILL.md gotcha.

### 6. Finish on a complete artifact, or say why not

**`stpa run` gates the scope contract first**, then prioritises, then renders. It exits non-zero if the delivered scope does not honour the requested one, or if a required section is missing. Run the gate directly any time you want to check yourself mid-analysis:

```bash
stpa scope .stpa --inventory <route count>
```

**Do not report success on a non-zero exit.** The report will carry a banner saying the scope was not delivered as requested, or that a required section is missing, and it will be right.

End with a **clickable link**, as the first thing in the closing block. `stpa run` calls
`stpa link` and prints this itself — quote its output verbatim rather than re-deriving a path by hand:

```
══════════════════════════════════════════════════════════════════════════
  REPORT   /abs/path/to/.stpa/REPORT.html
  OPEN     file:///abs/path/to/.stpa/REPORT.html
══════════════════════════════════════════════════════════════════════════

→ Wave 1 is where to start: N items
→ Every item has a file:line and a command that fails now and passes after the fix
→ Coverage: X% of the grid, Y% of the system, Z of 10 discovery modalities accounted for
→ Composition: N findings re-rated · Review: independent / NOT REVIEWED
```

**A bare path is not a link.** Terminals hyperlink `file://` URLs and do not hyperlink bare paths, so
the `OPEN` line is what turns "go find this" into one click. That is the whole fix for the common case,
which is a run on the user's own machine.

**Three failure modes this step has actually produced, each now handled by the tool:**

1. **A relative path.** A finished analysis ended in `.stpa/REPORT.html` and the first question back
   was *"where is the file?"* **A user asking that after a completed run is a defect here, not a
   question.**
2. **A sandbox path presented as a real one.** The follow-up was *"where is that relative to my hard
   drive?"* — the run was in a VM and `/work/...` did not exist on the reader's machine. When the
   report sits on a host share (`virtiofs`, `9p`, gRPC-FUSE), the host path is **not knowable from
   inside**, and `stpa link` says so rather than guessing: a confidently wrong path is worse than an
   honest unresolved one. It also prints the one `find` command that resolves it, and the
   `STPA_HOST_MAP="/container=/host"` export that makes every later run clickable. If you are running
   sandboxed, pass that on — do not paste the inside path as though it were the user's.
3. **A correct path into a hidden directory.** `.stpa` begins with a dot, so **Finder and most file
   pickers hide it by default** — a right path that looks missing. `stpa link` flags this and
   `--copy-to <dir>` drops a visible `STPA-REPORT.html` somewhere obvious. Offer that when the reader
   is not comfortable in a terminal.

Always give **both** coverage numbers, plus the modality count. Grid coverage without surface coverage
is how "100%" becomes false assurance — and both of those without the modality count is how a
single-modality inventory passes for a full one.

## Anti-patterns

- **Asking one question at a time.** Four sequential round trips for information you could gather in one is a worse interface than a form.
- **Asking then stopping.** The intake exists to start the work, not to produce a plan for the work.
- **Lecturing.** Credibility comes from the findings. `METHOD.md` is there for anyone who wants the theory.
