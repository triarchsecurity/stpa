# Workflow: FullAnalysis — orchestrated end-to-end STPA

Runs Steps 1–4 plus constraint emission against a target. Use when the target is a whole system and the analysis is worth hours, not minutes. For a single subsystem or a PR, use `QuickTriage.md` instead.

## Inputs

- A target: repository path, design document path, or both (a repo *and* its design docs is the strongest input — the design document states intent, the code states reality, and the delta between them is a finding generator).
- An output directory, defaulting to `<target>/.stpa/`.

## Outputs

| File | Content |
|------|---------|
| `01-scope.md` | boundary, losses, hazards, system-level constraints |
| `02-control-structure.md` | Mermaid diagram, controllers, control actions, feedback, process models, assumptions |
| `model.json` | machine-readable control structure |
| `grid.json` | the resolved UCA grid |
| `03-ucas.md` | UCA table with coverage ratio |
| `04-scenarios.md` | loss scenarios with mitigation directions |
| `05-constraints.md` | controller constraints + spec-ready negative assertions + Test Strategy rows |
| `remediation.json` | analyst input: severity, reachability, effort, location, fix, probe per finding |
| `06-remediation.md` / `.json` | the engineering plan — root causes by leverage, waves, metrics |
| **`REPORT.html`** | **the default deliverable** — plan first, then the analysis. Self-contained, no network |

## Steps

0. **Optional STRIDE pre-pass — run `SeedWithStride.md` first when a design document exists.** It runs the Fabric `create_stride_threat_model` pattern and folds the result into the STPA inputs: its **trust boundaries** seed the trust-zone layer (the layer whose absence is the top rating error), its **data flows** seed control actions, its **assets** seed controlled processes and cross-check the losses, and its **threat table** enriches the Step-4 scenarios. STRIDE and STPA are complementary — the pre-pass covers the component/technique class STPA under-enumerates while STPA still supplies the emergent/authorization class STRIDE misses. Skip it on a pure code target with no design doc, or run it against a hand-written architecture summary.

1. **Run `ScopeAndLosses.md`.** Do not delegate this — the boundary and loss list are the judgment calls the whole analysis rests on, and they need the full context of the conversation with whoever owns the system. If the system's owner is available, this step is a conversation, not an inference.

2. **Run `ModelControlStructure.md`.** Start with `stpa scan`, then do the human work of step 2 (invisible controllers) and step 6 (process models). Modality A, B, or both.

2b. **Gate the inventory BEFORE the grid exists. Do not skip to `init`.**
   ```bash
   stpa discover <repo> .stpa --check      # exit 7 = a modality has hits and no owner
   ```
   Coverage is computed over the inventory, so an inventory built from one search shape produces a
   truthful, meaningless 100%. This gate sweeps ten entry-point modalities and refuses to pass while
   any of them has hits but is neither mapped to a control action nor ruled out with a reason. The
   three marked **FORGOTTEN** — non-HTTP entry points, in-process command registries, dynamic
   execution — are the ones a route sweep cannot see; in a real run they concealed a PTY-over-WebSocket
   and an `eval` command that a previous run of the same repo had already found. Add the missing
   control actions to `model.json` now, while adding them is cheap.

   If the user selected **STPA + STRIDE**, run `SeedWithStride.md` here too (its `2b`): the trust
   boundaries it produces become the trust-zone layer, and that layer is what keeps Step-3 bands from
   being mis-rated.

3. **Generate the grid, then fan out Step 3 — with a durable delivery contract.**
   ```bash
   stpa init model.json -o grid.json
   ```

   **Write the manifest BEFORE dispatching.** It is the expected set; without one there is nothing to reconcile against, and "merge whatever arrived" is how a partial analysis reports a healthy number.

   ```json
   { "planes": { "auth": { "file": "planes/auth.json",
                           "controlActions": ["CA-A1","CA-A2"] } } }
   ```

   **Delegates write FILES, never message payloads.** Brief every agent to `Write` its findings to `.stpa/planes/<name>.json` and reply with only a path and a count. This is not a style preference — see the gotcha below; a large payload returned as a final message is a delivery channel that fails silently and indistinguishably from success.

   Each agent gets: the full `01-scope.md` (it needs every hazard), the full control structure (cross-controller context is where the good findings are), only its own control actions, and an instruction to declare `"incomplete": [...]` for anything it could not reach.

   Partition **by controller or plane, never by UCA type** — an agent that only ever asks "what if it's too late" loses the cross-type comparison that makes type-4 findings visible.

4. **Reconcile before merging. This gate is not optional.**
   ```bash
   bun "$STPA"/Tools/MergePlanes.ts .stpa --expect .stpa/manifest.json
   ```
   It compares delivered cells against the expected set and **refuses to merge** (exit 4) on any plane that produced nothing or any cell gap nobody declared. Re-run the missing planes, or record them in `model.json` `scope.deferred` so surface coverage falls to match reality — but never merge past a silent hole.

   If delegation fails repeatedly, **stop fanning out and go sequential**, analyzing planes yourself and writing each to disk as you go. Slower, but with a feedback channel that works. Say so in the report.

5. **Verify coverage before proceeding.**
   ```bash
   stpa status grid.json
   ```
   Open cells are holes. Either resolve them or state the coverage number in the report. **Report per-plane completeness, never one blended number** — a single figure hides which planes actually returned.

6. **Run `LossScenarios.md`. This step is not optional and the render gate now enforces it.**

   It is the step most likely to be skipped, because after Step 3 you already have findings and the temptation is to jump straight to constraints. Doing that has a specific cost, and it is not stylistic:

   - **Part A — why the UCA occurs.** Wrong process model, inadequate algorithm, missing or forged feedback. Skip it and a finding says *what* is unsafe but not *why it happens*, so the fix is guesswork.
   - **Part B — why a CORRECT control action fails to land.** This has **no substitute anywhere else in the method.** It is where the bypass class lives: a second service writing the same table, an admin console skipping the API, a job holding more authority than any user. Step 3 cannot find these, because no unsafe control action occurred — the guarded path is fine and the *other* path is the finding.

   Parallelizable per UCA, but scenarios benefit from cross-UCA visibility — the bypass class is usually found by noticing that two different UCAs share a controlled process. **Batch by controlled process, not by UCA**, and for each one ask explicitly: *what else writes this?*

   Write `04-scenarios.md`. `RenderReport.ts` treats it as a required section and exits 5 without it.

6b. **Compose. Rate the finding set, not the findings.**
   ```bash
   stpa compose .stpa --check              # exit 6 = a recorded band is softer than the composed one
   ```
   Declare `grants` and `requires` on every band-1/2 finding — what capability it hands an attacker,
   and what it assumes they already hold — and let the tool propagate reachability transitively. This
   step exists because two separate runs each rated a shell-over-WebSocket at R3 ("needs a staff
   identity") while separately rating identity forgery at R0, and neither composed them. A chain that
   *fails* to close is also information: if nothing grants a capability some finding requires, either
   name the control that denies it or go back to `stpa discover`, because the granting finding may
   simply not have been found.

7. **Run `SecurityConstraints.md`.** Emit `MUST NOT` assertions with probes, and land them wherever your build already looks — a test file is the durable home.

8. **Turn findings into a plan. An analysis without cost, location and a fix cannot be scheduled, and does not get done.**

   Write `remediation.json`, keyed on grid cell ids — for each finding: `severity`, `reachability` (R0–R4), `effort` (S/M/L), a `cluster` id, a `location` (`file:line`), a concrete `fix`, and a runnable `probe`. Group findings that share a cause into `clusters`, each with the one change that closes them all.

   ```bash
   stpa plan .stpa
   stpa plan .stpa --check   # exit 1 if any finding has no plan
   ```

   Three fields carry the weight, and each is one an analyst is tempted to skip:

   - **`effort`** — severity alone cannot rank work. Severity × reachability × effort is the minimum triple, and effort is the one that needs codebase knowledge.
   - **`location`** — "the per-route guard chain" costs an engineer an hour to relocate. `src/lib/api-auth.ts:39` costs zero.
   - **`cluster`** — teams fix causes, not findings. If N findings do not collapse to noticeably fewer causes, you have probably described one problem N times.

   `Prioritize.ts` computes bands, leverage (how many findings one fix closes), waves, and the plan-quality metrics. It invents nothing — every input is an analyst judgment; the tool only does arithmetic over them.

9. **Render the report. This is the default final step of every analysis — do not skip it and do not hand-write an HTML file instead.**

   ```bash
   stpa report .stpa
   ```

   `RenderReport.ts` reads `grid.json` plus whatever `0*.md` artifacts exist and emits `REPORT.html`: self-contained (no CDN, no scripts, no external fonts — it opens from `file://` on a machine with no network), light/dark aware, print-clean, with the stats header, per-UCA-type distribution, and one card per control action.

   **Why a tool and not hand-authored HTML:** the coverage figure, finding counts, tombstone split, and the concentration qualifier are all derived from `grid.json` arithmetic. Re-narrating them by hand each run is how the number drifts from the grid — and that number's integrity is the thing the rest of this toolkit exists to protect. The renderer reuses the same concentration rule as `UcaGrid.ts`, so a concentrated grid carries its qualifier into the HTML automatically, in a banner that cannot be separated from the figure.

10. **State the analysis's own limits — in `05-constraints.md`, so the renderer picks it up.** Every report ends with what this analysis could not see: controllers not modeled, the parts of the system outside the boundary, cells left open, assumptions unvalidated. A threat model that does not state its blind spots is claiming a completeness no method has.

## Effort guidance

| Target size | Realistic scope |
|-------------|-----------------|
| Single service, <10 control actions | 1–2 hours, single-pass |
| Multi-service system, 10–40 control actions | E4 with parallel fan-out per controller |
| Whole platform, 40+ control actions | Analyze in slices by trust boundary; a platform-wide grid is not a stopping rule, it is a way to never finish |

Slicing by trust boundary preserves the method: each slice gets its own boundary statement, and the interfaces between slices become environment for one and system for the other.
