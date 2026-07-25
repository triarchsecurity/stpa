---
name: triarch-stpa
description: "Control-theoretic threat modeling of any codebase or system design document, using STPA (System-Theoretic Process Analysis — Leveson & Thomas) and its security adaptation STPA-Sec (Young & Leveson). Four steps as workflows: ScopeAndLosses (losses → hazards as system states → system-level constraints), ModelControlStructure (controllers, control actions, feedback, process models — from code OR from a design doc), IdentifyUCAs (every control action × four unsafe-control-action types, as a countable grid), LossScenarios (why the UCA occurs; why correct control fails to land). Terminates in SecurityConstraints — every finding becomes a MUST-NOT assertion with a runnable probe, so the threat model gates the build instead of rotting in a wiki. Core axiom: losses come from inadequate CONTROL, not only component failure — every component can meet its spec and the composition still be unsafe. Finds the class checklists structurally miss: broken authorization, tenant-isolation breaks, IDOR, TOCTOU, stale-permission windows, confused deputy, bypass paths, workflow-state abuse. Self-contained `stpa` CLI (scan/new/init/status/grid/plan/report/run), fully offline. Prioritize.ts turns findings into a ranked backlog — root causes by leverage, waves, effort, file locations, runnable probes. RenderReport.ts emits a self-contained HTML report that opens with the engineering plan. USE WHEN threat model, threat modeling, STPA, STAMP, STPA-Sec, security design review, architecture security review, security analysis of this repo, attack surface analysis, unsafe control action, hazard analysis, what could go wrong with this design, review this design doc for security, abuse cases, trust boundary analysis, security requirements from a design, authorization design review, is this architecture safe. NOT FOR live or offensive testing against a running target, LLM prompt-injection assessment, attacking an argument or a plan rather than a system, or retrospective incident analysis (STPA's sibling for incidents is CAST, which this toolkit does not implement)."
effort: high
---

<!--
  NO `context: fork`. Deliberate.

  Forking runs the skill in a subagent, and subagents have no AskUserQuestion —
  which makes an interactive intake impossible and forces the skill to answer a
  bare invocation with "send me a task". Running inline keeps the question tool,
  the full tool surface, and the conversation context the analyst is already in.
-->

## Customization

Optional. If you keep local overrides for skills, put them alongside this directory and
read them before executing — nothing in the toolkit requires them, and the gates behave
identically without.

## What It Does

Applies STPA — a hazard-analysis method from systems safety engineering — as active threat modeling against software. You give it a repository, a system design document, or both. It produces a hierarchical control structure, a countable grid of unsafe control actions, causal scenarios explaining how each one actually happens, and a set of security constraints expressed as ISA anti-criteria with named probes.

The method's payload is a change of question. Checklist threat modeling asks *"what can an attacker do to this component?"* STPA asks *"in what context does this system's own legitimate control action produce a loss, and can an adversary reach that context?"*

## Invoked with no target

**Run `Workflows/Start.md`. Never reply "send me a task."** It opens with the banner, explains what this is and is not in six lines, asks **four questions in one round** — **models** (which model authors the analysis and which independent model attacks it, chosen as a PAIRING so the same model cannot land in both slots), inputs, scope, losses — then asks for **the repo link in plain text**, and runs the whole assessment.

**Ask for a link. Do not enumerate repos, and do not ask for the org separately.** An earlier design asked org → repo → branch as selectable options and failed three times in a row, each in a different way, and always with the repo question disappearing — collapsed into branch, absorbed into org, or deferred to a round the user could not see. **The link carries org, repo and often the ref in one string the user pastes from their address bar.** It is faster than any list, works for hosts and orgs you cannot enumerate, and there is no question left to lose. Echo back the resolved `org/repo @ ref` so a wrong paste is caught immediately.

**This skill does not set `context: fork`, and that is load-bearing.** Forking runs a skill in a subagent, and subagents have no `AskUserQuestion` — which is why a forked version answered a bare invocation with "send me the actual task". Running inline keeps the question tool, the full tool surface, and the conversation the analyst is already in. Do not re-add it.

**Engagement, throughout — not just at the start.** Announce `[1/6]`…`[6/6]` as each step begins so a long run never looks hung. Surface findings as you hit them rather than saving everything for the report. Say what you are about to do before a step that takes minutes. End on the artifact path, the wave-1 count, and both coverage numbers.

## The Problem

STRIDE, attack trees, and their descendants are **component-and-technique enumeration**: decompose the system, walk a list of attacker techniques against each part. That works for the failure mode it was designed for — a component doing something it should not.

It structurally cannot find the dominant modern vulnerability class: **systems where every component behaves exactly as specified and the composition is still unsafe.** Broken object-level authorization, tenant-isolation failures, TOCTOU, stale-permission windows, confused-deputy, mass assignment, workflow-state abuse, double-spend races, bypass paths through admin tooling — in every one of these, no component is broken. The authorization middleware correctly authorizes what it was asked about. The database correctly returns the row it was asked for. The loss emerges from the *control relationships between* correct components.

There is a second failure, less discussed. Checklist threat models age against the checklist. A technique that did not exist when the list was written is not on the list. STPA's finding set changes only when the *design* changes, because it enumerates hazardous contexts rather than techniques.

## How It Works

Four steps, each a workflow, plus a fifth that converts output into build gates.

1. **Losses and hazards.** Name the stakeholder-level losses. Derive hazards — **system states**, never attacker actions — that lead to them. Invert into system-level constraints.
2. **Control structure.** Model controllers (including humans, pipelines, and third parties), control actions, feedback paths, and — the highest-value element — each controller's **process model**: what it believes, where the belief came from, how stale it can be.
3. **Unsafe control actions.** Every control action against all four UCA types: not provided, provided, wrong timing/order, applied too long or stopped too soon. This is a grid of exactly `4 × N` cells, and `UcaGrid.ts` counts your coverage.
4. **Loss scenarios.** Why would each UCA actually occur (wrong process model, inadequate algorithm, missing/forged feedback), and why might a *correct* control action fail to land (compromised control path, unresponsive process, or the process modified by something else entirely — the bypass class).
5. **Security constraints.** Each finding inverts into a constraint — a `MUST NOT` assertion with a runnable probe, so the threat model gates the build. If you keep a spec format with negative criteria, they map onto it directly; same object, different container.

## Core Concept

**Two claims carry the whole method.**

**Losses come from inadequate control, not only from component failure** (Leveson's STAMP). Safety and security are control problems, not reliability problems. A system of perfectly reliable components can be unsafe.

**Process-model inconsistency is the general form of the authorization bug.** A controller acts on what it *believes* about system state. When belief and reality diverge and it acts anyway, you get a vulnerability. IDOR, tenant leakage, stale permissions, confused deputy, JWT confusion, webhook spoofing, and TOCTOU are all the same bug wearing different clothes — and asking *"what does this controller believe, and who can influence that belief?"* finds them faster than any technique list. See `SoftwareMapping.md`.

**And the adversary is a context selector, not a new actor.** Attackers do not add control actions; they choose the context in which an existing legitimate action becomes hazardous. That is what makes this active rather than academic. See `AdversarialContext.md`.

## Use / Win

- **Design review before it is built** — the cheapest point to find a control-structure defect is before the control structure exists in code.
- **A system you inherited** — the control structure is the fastest way to understand what actually has authority over what.
- **Authorization architecture** — this is the method's home ground.
- **A design document with no code yet** — Modality B works purely from prose, and its assumptions log is often the deliverable that matters most.
- **A PR or single feature** — `QuickTriage.md`, twenty minutes, same shape.
- **Producing security requirements** — the output is requirements by construction, not as an afterthought.
- **Handing work to a team** — `Prioritize.ts` turns findings into a sequenced backlog with cost, file locations, and a runnable check per item.

## Workflow Routing

| Verb / Intent | Workflow | File |
|---------------|----------|------|
| **bare invocation (no target)**, "how does this work", "walk me through it", "where do I start", "what do you need from me" | **Start** | `Workflows/Start.md` |
| "threat model this", "full analysis", "security review of this system" | **FullAnalysis** | `Workflows/FullAnalysis.md` |
| "what could go wrong", "define losses", "scope the analysis", "what are the hazards" | **ScopeAndLosses** | `Workflows/ScopeAndLosses.md` |
| "model the control structure", "map controllers", "what has authority here" | **ModelControlStructure** | `Workflows/ModelControlStructure.md` |
| "find unsafe control actions", "UCAs", "run the grid" | **IdentifyUCAs** | `Workflows/IdentifyUCAs.md` |
| "why would that happen", "causal scenarios", "how would this be exploited" | **LossScenarios** | `Workflows/LossScenarios.md` |
| "turn this into requirements", "security constraints", "make these testable" | **SecurityConstraints** | `Workflows/SecurityConstraints.md` |
| "quick check", "review this PR", "triage this change" | **QuickTriage** | `Workflows/QuickTriage.md` |
| "run STRIDE first", "seed with STRIDE", "feed STRIDE into STPA", "cross-check with STRIDE", "combine STRIDE and STPA" | **SeedWithStride** | `Workflows/SeedWithStride.md` |

## Quick Reference

**Reference files** (read as needed, not upfront):

| File | Contents |
|------|----------|
| `METHOD.md` | STAMP/STPA theory, Handbook definitions, the four steps, STPA-Sec, honest limitations, sources |
| `SoftwareMapping.md` | STPA vocabulary → software; UCA-type → vulnerability-class tables; loss and hazard catalogues; entry-point recipes per stack; design-doc extraction |
| `AdversarialContext.md` | Adversary-as-context-selector; reachability ratings R0–R4; 12 context patterns; the four scenario surfaces read as attack surfaces; the prioritisation heuristic |

**Tools:**

```bash
S=~/.claude/skills/triarch-stpa

# Candidate control-structure elements from a repo (candidates, not findings)
bun $S/Tools/ControlStructureScan.ts <repo> --json > candidates.json

# GATE — prove the inventory was multi-modal, BEFORE the grid exists. Ten entry-point
# modalities; exit 7 on any that has hits and is neither mapped nor ruled out. Three are
# marked FORGOTTEN (non-HTTP entry, command registries, dynamic exec) because a route
# sweep cannot see them and they hid band-1 findings in a real run.
bun $S/Tools/DiscoveryGate.ts <repo> .stpa --check

# GATE — rate findings as a system. Declare grants/requires; the tool recomputes
# reachability transitively. Exit 6 when a recorded band is softer than the composed one.
bun $S/Tools/ComposeChains.ts .stpa --check

# GATE — the scan already found the control you say is missing. Cross-checks every
# absence claim against the `guards` category of candidates.json. Nothing to fill in by
# hand; exit 8 when a finding calls a file unguarded and the scan flagged a guard there.
bun $S/Tools/ControlInventory.ts .stpa

# GATE — provenance + arithmetic. Every process-model belief must name a trustRoot
# (database | iam | network | human | attacker-input | unverified), and no count the
# tools compute may be typed into prose. Exit 9. --fix-numbers rewrites stale counts.
bun $S/Tools/EvidenceGate.ts .stpa [--fix-numbers]

# The grid — 4 x |control actions| cells, and the coverage ratio
bun $S/Tools/UcaGrid.ts init model.json -o grid.json
bun $S/Tools/UcaGrid.ts status grid.json
bun $S/Tools/UcaGrid.ts markdown grid.json -o 03-ucas.md

# Re-analysis after the control structure changes: carry resolved cells
# forward, list only the genuinely new ones
bun $S/Tools/UcaGrid.ts init model-v2.json --merge grid.json -o grid-v2.json

# Findings -> engineering backlog: bands, root-cause leverage, waves, metrics
bun $S/Tools/Prioritize.ts .stpa
bun $S/Tools/Prioritize.ts .stpa --check   # exit 1 if any finding has no plan

# THE DEFAULT OUTPUT — self-contained HTML report, always the final step
bun $S/Tools/RenderReport.ts .stpa

# Where it is, as a CLICKABLE file:// link. Handles the sandbox case honestly and
# warns that .stpa is hidden from Finder. `stpa run` calls this automatically.
bun $S/Tools/ReportLink.ts .stpa [--copy-to ~/Desktop]
```

**The report reads as a narrative, top to bottom, and the engineering plan comes LAST.** It opens with a **plain-language STPA primer and glossary** (§0 "Reading this report") that defines every term *before* it is used — loss, hazard, controller, control action, process model, UCA and its four types, loss scenario, constraint, trust zone, blast radius, band, plus the security terms the findings use (IDOR, confused deputy, TOCTOU, prompt injection) — and states plainly that STPA finds the emergent/interaction class STRIDE structurally misses while *complementing* STRIDE, not replacing it. It also names how the report's three groupings relate so they don't read as disconnected: the **four UCA types** are the *mechanism*, the **hazards** are the dangerous *states* they produce, the **root causes** are the shared *fixes*. A threat-model report that uses "UCA", "hazard", or "IDOR" before defining them has failed the reader — the primer is not optional. `RenderReport.ts` slices `01-scope.md` into its parts (so nothing is duplicated) and lays the report out as a story a non-engineer can follow: **1 · What the system is** (the target's own purpose statement) → **2 · How it's built — systems & subsystems** (a **generated, self-contained SVG control-loop diagram** built from the model: actors → the app's subsystems → the shared resources they act on, with control arrows down and dashed feedback up, and cross-account/bus edges flagged as crown-jewel paths; the full control-structure text folds underneath) → **3 · Boundary & seams** (the trust boundary + assumptions) → **4 · What's at stake** (stakeholder losses in business terms, and hazards as unsafe system *states* ranked by how many findings reach each) → **5 · Where to focus** (a prioritization view for when the finding count is overwhelming — the top root causes by leverage, the cumulative share of findings they close, and the band-1 count, so the reader fixes the few things that resolve most findings) → **6 · How it goes wrong (loss scenarios)** and **7 · What must hold (security constraints)** — the reader's payload, placed in the prime middle rather than buried before the plan: the causal stories of how each hazard is actually reached, and the MUST-NOT that *prevents* the hazard (or *bounds* it — blast radius, attribution — where prevention is not possible), each with a runnable check → **8 · Unsafe control actions** (the full UCA grid — the exhaustive enumeration *behind* the scenarios, grouped into per-plane collapsible groups whose summaries carry finding / ruled-out / band-1 / action counts) → **9 · What each part believes** (the process-model & feedback table — kept at the end as reference because it is the densest section) → **10 · Engineering plan** (root causes by leverage, highest-leverage move, waves, six plan-quality metrics). The "what kind of thing goes wrong" bars in the header encode count as **fill length** proportional to the largest category (no full-width rail — a short bar must read as few, not as "same width as the rest"). Every section is collapsible via native `<details>` — the four narrative anchors (§1 What it is, §2 How it's built, §4 What's at stake, §5 Where to focus) default open and the rest collapsed, but all can be minimized. **No JavaScript, so the page stays self-contained and offline**; print/PDF export forces every section open so nothing is lost. `md()` folds soft-wrapped source lines into single paragraphs (a hard-wrapped scope file must not render as one `<p>` per line), and each collapsible section drops its own leading heading since the summary already labels it. The per-plane grouping keys off each cell's `plane` field and falls back to one auto-opened group when absent.

**HTML is the default deliverable.** Every analysis ends with `RenderReport.ts` writing `REPORT.html` — self-contained (no CDN, no scripts, no external fonts; opens from `file://` with no network), light/dark aware, print-clean. It reads `grid.json` plus whatever `0*.md` artifacts exist, so partial analyses still render. Never hand-author the HTML: the coverage figure, counts, and concentration qualifier are derived from grid arithmetic, and hand-narrating them is how the report drifts from the grid.

**Read `README.md` first** — install, the tactical run-one loop, and the strategic case for where this sits in an SDLC. `METHOD.md` is the theory and the honest limitations.

**Worked example:** `Examples/pulse-analysis/` — a complete real run (4 control actions, 16 cells, 100% coverage, 8 findings, 8 reasoned tombstones, 2 candidate findings refuted by reading the code). Read it before your first analysis.

**The four UCA types**, memorized: *not provided · provided · wrong timing or order · applied too long or stopped too soon.*

**The five-part UCA sentence:** `[controller]` provides/does not provide `[control action]` `[type qualifier]` when `[context]`, leading to `[hazard]`.

## Integration

- **This repository IS the skill.** `git pull` updates it in place; a change here is a
  change to the deployed behaviour. Before editing, pull; after a substantive change,
  open a PR so the reasoning lands with the code (`FIELD-NOTES.md` records why each gate
  exists — read it before deciding a gate is not worth its friction).
- **Portable by design.** No vendor or agent-framework terminology anywhere in `Tools/`,
  `Workflows/` or the `stpa` CLI. Everything runs offline with no API keys and no
  telemetry, so the directory can be lifted into a standalone repo and driven from a
  shell.
- **SAST and dependency audit are complements, not competitors.** This finds the
  emergent/authorization class they structurally miss; they find the injection and
  known-CVE classes STPA structurally misses. Run both and say which you ran.
- **Live and offensive testing** happens against a deployed target. This is analytical
  and works before deployment — its output makes an excellent target list for the
  people who do run against production.
- **Property-based testing** is the strongest probe form wherever a constraint is a
  property over pure logic rather than a single assertion.
- **Incident retrospectives** are a different method. STPA's sibling for accidents
  already happened is CAST, which this toolkit does not implement.

## Examples

**Repo, full analysis.** *"Threat model the security-portal repo."* → FullAnalysis: scope from the repo's purpose and its customer contract; `ControlStructureScan.ts` for candidates; hand-add the operator, the CI pipeline, and the support impersonation tool; ~14 control actions → 56 grid cells; parallel fan-out one agent per controller; scenarios; constraints appended to the repo's ISA.

**Design document, no code.** *"Review this RFC for security before we build it."* → Modality B: sequence diagrams give the control actions, "the gateway validates and forwards the tenant id" gives the process model, and the assumptions log becomes the question list for the RFC's author.

**PR triage.** *"Does this PR introduce anything scary?"* → QuickTriage: three control actions, the four types on each, and one question that earns its keep — *does this change introduce a new belief the code holds about system state?*

## Best Practices

- **Do Step 1 with the system's owner if one is reachable.** Losses are a business judgment. Inferring them is possible; asking is better and takes ten minutes.
- **No report reaches a human without passing `stpa verify` — adversarial peer review is a gate, not a courtesy.** Every finding must be attacked by an *independent* model (cross-vendor where possible; ≥2 reviewers for band-1/2) before delivery — a model rationalises the inflation a different model catches (this is exactly how the latent-rated-as-live error shipped). The reviewer refutes reachability, trust-zone placement, live-vs-latent, STPA-validity, and evidence, writing a verdict to `reviews.json`; `VerifyGate.ts` refuses to certify (and stamps a **NOT-PEER-REVIEWED** banner on the report) if the review is missing, self-authored, incomplete, or leaves a confirmed-live finding with no deployed reachability path. The **"How much to trust this analysis"** scorecard the renderer shows is computed from that record, never self-narrated — objective self-assessment is required and mechanical. Full stage: `Workflows/AdversarialReview.md`.
- **Model choice is a first-class analysis input — record it, and do not assume one fixed model is automatically right.** The findings come from the *reasoning* of the model behind each agent, so output quality tracks model capability directly; a run's quality claim should state the analysis model the way it states coverage (put it in `scope.sources`). A single fixed strong model is the safe default and gives consistent depth across planes — but it leaves both quality and cost on the table. The higher-leverage shape is to route by cognitive demand: the **UCA analysis, the Part-B loss scenarios, and the topology-aware rating** are where model capability most changes the answer (and where the RC-1-class mislocation happens) — give those the strongest tier; recon and mechanical passes can go cheaper; the CLI/render tools are deterministic and use no model. The single highest-value addition is an **adversarial verification pass with a *different* model** (cross-vendor where possible) that attacks each finding's reachability and trust-zone placement — a same-model author rationalizes the inflation a different-model skeptic catches. Fixed-model is fine to start; tiered-plus-adversarial is how you harden it.
- **Ask the deployment topology at intake, and bring assumption-dependent bands back to the owner before you finalize them.** The owner is the only reliable source for the environment facts that set reachability — tenancy model, what's internet-facing vs internal, who authenticates where, which boundaries IAM/network enforce. `Start.md` now asks these in a dedicated round; do not skip it, and do not run silently to a rated report on inferred topology. When a finding's band rides on an assumption you could not confirm, mark it provisional and *surface it back to the owner as a question* — "these N findings are P0 if the platform is multi-tenant and P3 if it is single-tenant-per-customer; which is it?" A buried caveat is how a mislocated finding ships; an explicit question is how it gets resolved. This is a two-way loop, not a one-shot intake — the assessment engages the owner at the start (topology) and again before the bands harden.
- **Spend your time on process models.** Per minute invested, the `believes / sourced from / staleness` table finds more real issues than any other part of the method.
- **Write down absent feedback.** A control loop that does not close is invisible unless you record the absence.
- **Work type 4 even when it feels unproductive.** Too-long/stopped-too-soon is the type analysts skip and the type that yields findings nobody else has.
- **Tombstone loudly.** "No hazard because X" is a result. Silence is not.
- **State your coverage as a number.** "84% of the grid, here is the 16% we did not reach" beats "we did a threat model" in every way that matters.
- **Slice large systems by trust boundary**, giving each slice its own boundary statement. A platform-wide grid is not a stopping rule; it is a way to never finish.

## Gotchas

- **A CONTROL FAILURE IS A CLAIM ABOUT CODE. GO READ THE CODE. NEVER INFER AN ABSENCE — learned the hard way, and it produced the worst error this method has yet shipped.** Every one of these is a claim requiring evidence, not reasoning: *"there is no timeout"*, *"nothing verifies the signature"*, *"this route has no auth guard"*, *"the check never runs"*, *"F-n is absent"*, *"no audit event is emitted"*. In one full-surface run the author made four such claims and **all four were false**, each caught by an independent reviewer who simply opened the file:
  - *"no signature verified at deploy or update time"* → `cloudformation/auto-update/verify.js` implements 2-of-N EdDSA JWS verification, anti-rollback and repo-pinning.
  - *"no idle timeout, sessions persist unbounded"* → `TerminalService.ts:18` — `IDLE_TIMEOUT = 30 * 60 * 1000`, with a wired sweep.
  - *"the MCP surface is mounted with no guard"* → `app.use('/mcp', mcpAuthMiddleware, route)` 130 lines below the handler that was read; it 401s a tokenless request.
  - *"`claimRequired` is unset so the check never rejects"* → `websocket.ts:46` initialises it to `true` and `:56` reads `config.claimRequired ?? true`, so unset means **enabled**. This one was rated **band 1, R0, "unauthenticated internet-facing WebSocket"** and written into the assumptions log as **CONFIRMED**. It was refuted outright.

  The mechanism is always the same: read the *use* of a flag or the *handler*, infer the default or the middleware, and never read the declaration or the mount. **The absence of a control in the part of the file you opened is not evidence of absence in the file.** So:
  1. **Before writing any absence claim, grep for the thing you say is missing** — `grep -n "timeout\|Timeout"`, `grep -rn "verify\|signature"`, `grep -n "app.use('/mcp'"` — and read every hit. A claim of absence needs a *negative search over the whole surface*, not a positive reading of one function.
  2. **Read declarations and defaults, not just uses.** `x ?? true` inverts the meaning of "not passed". A field initialiser can make an optional config non-optional in practice.
  3. **Follow the mount, not the handler.** Express guards are commonly applied at `app.use(prefix, guard, router)`, far from the `route.post('/')` that appears unguarded.
  4. **Cite the file:line you read to establish the absence**, and if you cannot cite one, write *"not verified"* and rate it provisional — never confirmed.
  5. **Absence claims are the reviewer's first target.** `AdversarialReview.md` dimension 5 exists for exactly this, and in the run above it was the single highest-yield dimension.

  This bias runs one way and that is why it matters: inferring an absence always makes the finding *worse*, so the error inflates severity, survives self-review comfortably, and reaches the owner as a false band-1. **When in doubt, revert to the code. There is no acceptable substitute.**
- **The scan's `guards` category is evidence, and for a long time nothing consumed it.** `ControlStructureScan.ts` emits every place the code appears to make an authority decision — in one run **2,508 candidates, of which the analysis used zero**. Two of the four false absence claims in that same run pointed at files where the scan had already flagged a guard, including `WWW-Authenticate` *inside* the middleware the finding said did not exist. `stpa controls` now does that comparison. It cannot prove an absence; it proves you did not look, which is the actual failure mode.
- **A belief is only as good as the root it bottoms out in — make `sourcedFrom` terminate.** A run credited *"roles are re-read from the database on every request"* as a working control. True for `loginRequired`; false for `identityHasRole()` and `hasClaim()`, which decrypt the role out of the caller's own token. Six remediations saying "gate this on an operator role" were therefore placebos, and two models missed it because `sourcedFrom` named a hop ("the session") rather than an origin. `stpa evidence` requires `trustRoot` ∈ `database | iam | network | human | attacker-input | unverified`. **"the token" is not a root** — expand it to what verifies it, under which key, and whether the adversary can get that key.
- **Never type a number the tools compute.** A scope document said "44 tombstones" while the grid held 66, because a correction pass changed the grid and nobody re-typed the sentence. One checkable-and-wrong number discredits every number beside it. `stpa evidence` recomputes the canonical counts and fails on any hand-written disagreement (`--fix-numbers` to rewrite). The corollary: put retractions in `corrections.json`, which the report renders as one section, instead of letting them accumulate as prose across five documents — a corrected analysis that has become unreadable is a worse deliverable than the uncorrected one.
- **A review briefed only to refute is one-directional, and its silence is not evidence.** In one run **0 of 96 verdicts were upgrades**; a third model then found two unmodelled RPC bridges, a systemic authority defect, and a seeded super-admin — none of it mis-rated, all of it *absent*. Brief every reviewer with dimension 7 of `AdversarialReview.md`: `upgrade` as a verdict, and `inventoryGap` for authority nobody modelled. `stpa verify` warns when upgrades are zero.
- **Applying a verdict means changing the artifact, not filing it.** A reviewer caught two unmodelled RPC bridges and the apply step reverted the correction, so the report kept asserting the opposite while the scorecard claimed the finding had been reviewed. `stpa verify` exits 7 unless every refutation is tombstoned and every downgrade/provisional is stamped. Re-merging reviews *after* the apply step has run is the specific way this happens — it happened again while building the gate that catches it.
- **An inventory built from ONE search shape cannot be audited by a ratio — learned the hard way, 2026-07-25, and this is now the most important gotcha here.** A full-surface run of a large TS monorepo swept `app.get|post|put|delete`, found 408 registrations, collapsed them to 25 control actions, and `ScopeGate` certified *"full surface delivered — 100%"*. It was arithmetically true and badly misleading. The run missed an interactive PTY (`pty.spawn($SHELL, {env:{...process.env}})`) reachable over a **WebSocket upgrade**, and an in-process `.eval` command backed by `new Function()` — both band-1-class, both **found by an earlier run of the same repository**, and neither ever a *candidate*: they were not rejected, they were never seen. Coverage is computed over the inventory, so **the analyst who builds the inventory decides what 100% means.** `stpa discover` now gates this before `stpa init`, and the three modalities marked FORGOTTEN in it — non-HTTP entry points, in-process command registries, dynamic-execution primitives — are exactly the shapes a route grep structurally cannot find. Run it, and leave a genuinely outstanding modality unmapped so the gate stays red: a red gate that names the hole beats a green one that hides it.
- **Reachability is not a property of a finding — rate the SET, or ship an R0 as an R3.** Two independent runs of the same target both rated an interactive PTY at R3 because it is gated on a staff email domain, while separately rating token forgery at R0 — and neither noticed that the forged token's email field is attacker-controlled, so the R0 finding *is* the R3 finding's prerequisite. The composition is an unauthenticated remote shell holding the workload's cloud credentials; no single finding said so, because every rating question in the method is asked about one finding at a time. `stpa compose` closes this: declare `grants`/`requires` per finding and it recomputes transitively. Treat a chain that *fails* to close as a question too — if a finding requires a capability nothing grants, either name the control that denies it or suspect the granting finding was never found.
- **Never produce the final artifact with `RenderReport.ts` or `stpa report` — always `stpa run`.** The individual tools render happily while bypassing the scope, plan, composition and peer-review gates, and a run did exactly that: it called the renderer directly, got a clean-looking report, and presented an ungated analysis as final. The gates only bind if the path that produces the deliverable is the path that runs them. Reaching for the single tool "just to see the output" is the moment the gates existed for.
- **Link the report; do not describe where it is.** Three separate handoff failures, all on the same analysis: a relative `.stpa/REPORT.html` ("where is the file?"), then an absolute path that was a *sandbox* path ("where is that relative to my hard drive?"), then the discovery that `.stpa` is a **dot-directory Finder hides by default** — a correct path that reads as missing. `stpa run` now calls `stpa link`, which emits a `file://` URL (terminals hyperlink those; they do not hyperlink bare paths), warns about the hidden directory, and offers `--copy-to` for a visible copy. **Quote its output; never hand-derive a path.** And when the report sits on a host share (`virtiofs`, `9p`, gRPC-FUSE) the host path is *not knowable from inside* — the tool says so and prints the `find` command plus the `STPA_HOST_MAP` export that makes later runs clickable, because a confidently wrong path is worse than an honest unresolved one. Note that container detection by `/.dockerenv` or pid-1 cgroup **does not work** in a VM sandbox; key off the filesystem type of the path's mount instead, which is what the tool does.
- **Depth is a gate, not a question.** The intake used to ask how deep the scan should go. Everyone picks the deepest option, so the question only ever offered a way to opt out of thoroughness — and its shallow answers existed to make the form look balanced. Discovery now always runs at full depth and the analyst must account for what it finds. Time-boxing belongs under `Scope`, where it is recorded as a contract instead of hidden as a dial.
- **Step 4 is the step that gets skipped, and Part B is what you lose — learned the hard way, 2026-07-22.** Two full analyses jumped from UCA straight to constraint, folding a sentence of causation into each cluster summary instead of writing `04-scenarios.md`. Nothing blocked it because the renderer graded that section `supporting`. It is now `core` and the render exits 5 without it. The cost is specific: **Part B (why a *correct* control action fails to land) has no substitute anywhere else in the method** — it is where the bypass class lives, and Step 3 structurally cannot find it because no unsafe control action occurred.
- **A hazard is a system state, not an attacker action.** `An attacker steals a token` is not a hazard; `the system accepts a token that no longer reflects the holder's entitlements` is. This one error, made in Step 1, degrades the entire analysis into a STRIDE list with extra ceremony — and it is the single most common way STPA is done wrong.
- **A hazard is also not a cause.** `Redis is down` is a cause. If it is something you would put in a postmortem timeline, it belongs in Step 4, not Step 1.
- **Model control actions, not endpoints.** Three routes and a worker that all create an order are one control action with four invocation paths. Modeling endpoints inflates the grid and hides the fact that the paths may not share controls — which is exactly the finding you wanted.
- **The controllers that matter most leave no code trace.** Human operators, on-call engineers with prod database access, the CI/CD pipeline, third parties processing your data, the package registry. `ControlStructureScan.ts` cannot see any of them. If your control structure contains only services, you have modeled the org chart of your code, not the authority structure of your system.
- **Shipped operator tooling + ambient credentials are their own controller class, and the bypass they enable defeats the entire application authorization model — learned the hard way from a real incident.** A web shell, CLI console, or debug page that ships inside a deployed (or customer-side) artifact inherits the runtime's *own* identity: its process environment carries the cloud instance/task-role credentials and a reachable metadata/credential endpoint. Anyone who reaches that shell can lift **portable** credentials and use them off-box — from a laptop — under the workload's identity, on everything that identity can reach. The guarded API path is never touched; downstream logs show the operator's own network identity (or a shared service identity), not the system, so the action is effectively unattributable. Model the shell as a **controller**, the ambient credentials as a **controlled process**, and *"my authority is confined to this process/host"* + *"privileged actions are attributable to a named human"* as process-model beliefs that are FALSE by construction. The scanner barely sees this — a PTY spawn and a metadata fetch don't look authority-bearing — so it is a mandatory **hand-added** element in Step 2, not something the grep will surface. It is also the archetypal Step-4 Part-B bypass: the finding is not any single unsafe control action, it is that a correct, guarded control action is irrelevant because the credential simply leaves the box. (Incident: an operator lifted task-role credentials from a container shell and used them from their own machine to change a customer's infrastructure; the customer saw an unfamiliar IP, and it was misreported as an automated update.)
- **Reachability and blast radius are properties of the DEPLOYMENT, not the code — pin the topology before you rate, or you will systematically mis-band findings (learned the hard way, and it is the most insidious failure this method has).** The code tells you a check is missing; it does *not* tell you who can reach the unchecked path or who is harmed when it fires. Both are environment facts: the **deployment topology** (single-tenant-per-customer vs multi-tenant vs a central control plane), the **network position** of each entry point (internet-facing vs an internal private-DNS service), the **trust zones** and where their boundaries are, and the **non-code controls** that enforce them (IAM, network policy, broker ACLs, WAF). An analysis that derives R0–R4 from code presence alone will over-rate internal, foothold-required, within-one-tenant paths as if they were external, zero-foothold, cross-tenant ones — and *simultaneously* under-model the shared/central plane where the real cross-tenant surface actually lives. Concretely, from a real run: `no org WHERE` was rated as a live cross-tenant read when the product is deployed **single-tenant-per-customer** (so it is *latent* in-deployment, and the live cross-tenant surface was a *central archive* query route nobody had modeled as its own zone); and a zero-auth message bus was rated "any publisher, R0" when it runs on a **per-deployment private-DNS network** (R3 — an adversary needs a foothold in that customer's deployment first). Six rules this forces:
  1. **Model deployment topology and trust zones as an explicit layer** — per-tenant deployment, central control plane, the customer's cloud account, the vendor's cloud account, staff vs customer — and **locate every finding in a zone.** The control structure must be layered by *trust boundary*, not only by code module.
  2. **Rate reachability from the deployed path.** Name the concrete route an adversary *in a given zone* takes. If that depends on an unconfirmed environment fact — is this route internet-facing? is the archive populated on this instance? does prod override this default key? — the band is **provisional** and the finding is tagged with the assumption it rides on.
  3. **State the blast radius on every finding** — one tenant / all tenants / one deployment / the fleet / one cloud account / all accounts. Topology, not code, decides it, and it is what separates a P0 from a P3.
  4. **Credit *and* check non-code controls.** An environmental control (IAM on a bucket, a private network segment, a broker ACL) can *close* a finding — tombstone it with that control named as the reason — or can be *assumed-but-unverified*, in which case the band is provisional. Model IAM/network/ACLs as controllers; they are part of the control structure.
  5. **Worst-case is for EXISTENCE, not for reachability.** STPA's worst-case licence means you never *omit* a finding because "there's a mitigation" — it does **not** license assuming maximal reachability. Tombstone conservatively; **rate honestly.** Conflating the two is exactly how "a missing check" inflates into "cross-tenant read is the default."
  6. **The same missing check is live in one zone and latent in another.** A defect inside a single-tenant deployment is a *within-tenant* total-compromise story (any foothold → that customer's whole environment + cloud account, non-attributably); the identical defect on a central/shared plane is *cross-tenant*. Ask of every root cause: *is this in the right zone, and could the same defect be latent here but LIVE on a shared plane I didn't model?* The scanner cannot see any of this — topology lives in terraform/IaC, network config and IAM, never in the application code — so gathering it is a mandatory hand-done step **alongside** the code read, and it must happen *before* bands are assigned.
- **`ControlStructureScan.ts` output is candidates, never findings.** It matches text. It cannot tell you what a controller believes, and a clean scan means the stack's idioms are unrecognized at least as often as it means the pattern is absent.
- **A UCA context states the actual true state, never the controller's belief, and never the result.** The Handbook is explicit: ✗ *"grants access when it incorrectly believes the caller owns the record"* — that is a **cause**, and causes are Step 4. ✓ *"grants access when the record belongs to a different tenant."* In software this is the easiest rule to break, because "the code believed the wrong thing" is exactly how we naturally describe an authorization bug. Break it and Step 3 degrades into implementation guesswork.
- **An existing safeguard does not excuse a UCA.** STPA is a worst-case method; "there's a mitigation for that" is not grounds to omit the finding, because in the worst case the mitigation does not operate as intended.
- **A UCA whose context is "always" is a design defect, not a UCA.** Record it as such and fix the control structure — do not dilute it into a context-qualified finding it is not.
- **Never hand-write a "Type it" / "Other" option in `AskUserQuestion`.** The tool appends its own free-text escape automatically. A hand-made one returns its own label as the answer — you learn nothing, and the flow stalls into prose. Every option must be a real value. Burned a live run: `Type the repo name` came back as the literal string.
- **Fire the next question round as a tool call, not after a paragraph.** Ending a turn with prose between rounds looks, from the user's side, exactly like the intake dying. If a round returns answers and more are needed, the next action is the next `AskUserQuestion` call.
- **Ask the org in round ONE, not as a follow-on.** It is part of *what we are working on*, and it is the answer that makes the repo list possible. Asking org and branch together in a single follow-on round is how the repo question fell through the gap between them — the single most important question in the intake, silently skipped.
- **Inputs are multi-select, and a repo PLUS its design docs is the strongest pairing.** The document states intent, the code states reality, and every divergence is either a documentation defect or a security finding — you cannot tell which without asking, and that question list is often worth more than the findings. A single-choice intake hides this pairing entirely, which is why Q1 is `multiSelect`.
- **Never assume the hosting account or org.** The credential that happens to be logged in locally is not necessarily the owner of the target, and defaulting to it is the same error as defaulting to `main` — a convenient assumption standing in for an answer. Enumerate with `gh org list` plus the personal account, offer them as options, and keep an **Other** escape for a URL, an SSH remote, a non-GitHub host, or a local path with no remote. If `gh` is unauthenticated, say so and ask for a path rather than guessing.
- **Every selected input needs a locator, asked as a follow-on, and recorded as provenance.** A codebase needs a path or URL **and a ref** — an analysis of "the repo" is not reproducible and not comparable to the next one, because branches diverge and a finding true on a feature branch may not exist on main. A design doc needs a path or URL that actually resolved. `scope.sources` records what was consulted; `ScopeGate.ts` fails on missing sources, on a source without a type or locator, and on an unpinned codebase. This closes the quiet failure of a multi-input run: a design doc offered at intake, never read, and silently implied in the result.
- **Record the scope contract at intake, or nothing can grade the result — learned the hard way, 2026-07-22.** A user selected "Full surface". The analysis modeled 12 of 20 control actions, declared 8 "deferred" (six with reasons amounting to *"not read this pass"*), and reported 60% surface coverage as though it were a considered boundary. Nothing caught it, because **surface coverage is `modeled / candidates` and the analyst sets both numbers** — writing `candidates: 12` would have printed a clean 100%. A ratio whose denominator the reporter chooses is not a control. `scope.requested` is now written at intake and `ScopeGate.ts` compares delivered against requested; `stpa run` gates on it before rendering.
- **Under a full-scope contract, "not read" is not a deferral reason.** It describes the analyst's progress, not the system's risk. A valid deferral says why the thing does not need analysing — no authority exercised, outside the declared boundary, static content with no tenant dimension. If the only reason is that nobody got to it, it is outstanding work. `ScopeGate.ts` pattern-matches this class of reason and fails on it.
- **Narrowing scope is the requester's decision.** If a full analysis is running long, say so and ask. Quietly delivering less and writing the shortfall up as a boundary is worse than an honest "this is taking longer than I said" — it converts an unfinished analysis into a document that looks finished.
- **Delegates must write FILES, never return large payloads as messages — learned the hard way, 2026-07-22.** A full-scope run fanned out six plane agents briefed to return findings as their final message. All six reported "idle / available". All six returned nothing. Re-briefed to `Write` to `.stpa/planes/<name>.json`, three delivered 112 cells immediately — the analysis had been done, the channel had eaten it. **"Finished" and "produced nothing" are the same signal unless you check.** That is an unsafe control structure — a control action with no feedback channel — in this toolkit's own workflow, which is precisely why `MergePlanes.ts` now refuses to merge past a plane that delivered nothing.
- **Never merge parallel results without an expected set.** Coverage is computed over cells PRESENT, not cells EXPECTED, so merging "whatever arrived" produces a healthy-looking number over a fraction of the system. Write `manifest.json` before dispatch and run `MergePlanes.ts --expect` after; it exits 4 on any undeclared gap. In the incident above the gate reported `112 of 264 cells, 3 of 6 planes` — without it, the report would have shown 100% coverage of the planes that happened to return.
- **When delegation keeps failing, stop delegating.** Two rounds of chasing a broken channel costs more than doing the work sequentially. Go plane by plane yourself, writing each to disk, and say in the report that you did.
- **Do not partition parallel UCA work by type.** Partition by controller. An agent that only ever asks "what if it's too late?" loses the cross-type comparison that makes type-4 findings visible, and type 4 is the one you were going to miss anyway.
- **Give every parallel agent the *whole* control structure, not just its slice.** The best findings are cross-controller — a bypass path exists because controller B writes what controller A guards. An agent that only sees its own controller cannot find them.
- **The checklist regression is guarded mechanically, not by exhortation — and that was a deliberate fix.** If a finding would survive deleting the control structure ("check for XSS", "consider SQL injection"), it is not an STPA finding. Telling you that is not enough: a coverage ratio that counts any string would make the fastest route to 100% a paste of generic vulnerability classes into all 4N cells — STRIDE wearing STPA vocabulary, *certified complete by a number*. So `UcaGrid.ts` counts a finding only when its `bindsTo` references a process-model variable or feedback channel declared for **this** system. Generic findings bind to nothing and score nothing. Verified: 16 generic findings filling every cell of a 16-cell grid scores **0.0%**.
- **Consequently, a thin Step 2 makes a high score impossible.** That is intended. If you cannot bind a finding to a modeled belief, either the finding is generic or the control structure is incomplete — and the second is the more common and more useful answer.
- **Binding to the same element on every cell is the second-order version of the same cheat.** Citing `PM-1` on all 4N cells passes set-membership and still produces boilerplate. `status` reports binding spread and flags when one element carries ≥80% of findings — **and the flag rides on the coverage line itself** (`100.0% ** CONCENTRATED — NOT A CLEAN 100 **`), with a matching blockquote in the markdown report, because a caveat printed *underneath* a number gets dropped the moment someone quotes the number. `status` also exits **3** on concentration, so no wrapping automation can read it as a clean pass. Not a hard block — a small system legitimately has few elements and a real single-cause defect legitimately recurs — but you cannot quote the percentage without the caveat travelling with it. If the concentration is genuine, say so explicitly in the report.
- **The concentration guard has a documented blind spot — know it before you trust it.** The heuristic is arithmetic (`distinct ≤ 1` or one element carrying ≥80%). Identical boilerplate alternated across *two* declared IDs at 50/50 passes clean. Closing that needs semantic judgment of the statement text, which arithmetic cannot do and the tool does not pretend to. **The tool catches lazy gaming, not determined gaming — the backstop is a human reading the statements.** This is written down rather than glossed over because a guard with an undocumented blind spot is worse than no guard: it manufactures confidence it hasn't earned.
- **The scanner's coverage is narrowest exactly where STPA was invented.** Shell/ops scripts, C/C++ firmware, and mobile sources are now scanned, but pattern quality is best on web/service stacks. In embedded, ops, or an unfamiliar stack, treat a clean scan as *no signal*, not as *no control structure*, and model by hand.
- **A truncated scan says so.** The walk stops at 20,000 files; when it does, both the report and the JSON carry an explicit incomplete-scan warning. Absence of candidates after truncation means unknown, never absent.
- **STPA has no native stopping rule and no likelihood ranking.** Both are real limitations, not oversights. `UcaGrid.ts` supplies the stopping rule as arithmetic; the loss-severity × reachability heuristic in `AdversarialContext.md` supplies ordering. **Both are LifeOS extensions** — do not present either as STPA doctrine, and never present the heuristic as a probability or a CVSS-comparable score.
- **The analysis is only as good as the boundary.** An unstated boundary means the analysis quietly expands until it is abandoned. State inside, environment, and excluded — with reasons — before anything else.
- **The method costs real hours.** That is the documented criticism and it is fair. `QuickTriage.md` exists because a bounded twenty-minute analysis that happens beats a thorough one that does not.

## Execution Log

Analyses write to `<target>/.stpa/` by default: `01-scope.md`, `02-control-structure.md`, `model.json`, `grid.json`, `03-ucas.md`, `04-scenarios.md`, `05-constraints.md`, and **`REPORT.html`** — the default deliverable, rendered by `Tools/RenderReport.ts` as the final step of every run. Re-run `IdentifyUCAs` when the control structure changes — new controller, new entry point, new integration, new operator role. The grid makes deltas cheap: only new control actions add cells.
