# Workflow: SeedWithStride — run STRIDE first, feed it into STPA

**Why this exists.** STRIDE and STPA are *complementary, not competing* (Khan, Madnick et al., *Extending STPA with STRIDE to identify cybersecurity loss scenarios*, Computers & Security 2020; comparative STPA-Sec/STRIDE/CORAS study, C&S 2023). STRIDE is attacker-centric, per-element threat enumeration; STPA is system-theoretic and finds the emergent/interaction class STRIDE structurally under-covers. Run as a **pre-pass**, STRIDE produces exactly the inputs STPA needs and is weakest at generating by itself — most importantly the **trust boundaries** whose absence is the single most common way an STPA rating goes wrong (see the reachability-is-a-deployment-property gotcha).

**This does not replace the control-structure modeling.** STRIDE seeds and cross-checks; STPA's power — the composition/authorization/bypass class — still comes from Steps 2–4. Never let a STRIDE threat list stand in for the control structure.

## STRIDE needs a *model*, not literally a design document

STRIDE is applied *per element* over a data-flow model — components, the flows between them, and the trust boundaries they cross. That model can come from a design document **or be extracted from the code**. You cannot run STRIDE on raw source (it has nothing to enumerate against), but you can always build the model first. Two orderings:

- **Design document exists → STRIDE first, then STPA.** The doc *is* the model; run `create_stride_threat_model` on it, then seed STPA (below).
- **Code only → build the STPA control structure first, then run STRIDE on *that*.** The STPA control structure (`ControlStructureScan.ts` + the Step-2 recon) is itself a data-flow model: controllers ≈ processes, control actions ≈ data flows, controlled processes ≈ data stores, trust zones ≈ trust boundaries. Feed `02-control-structure.md` (or a short architecture summary) to `create_stride_threat_model` as the "design," get the STRIDE threats, and fold them back into the Step-4 scenarios and the coverage cross-check.

Either way the destination is the same; the only question is whether you already have a model or must extract one from the code first.

## Settled: where STRIDE goes, and how many times each method runs

This was an open question and it is now decided, because two facts close it.

**One.** STRIDE-per-element needs a *model* — components, flows, boundaries. On a code target the only
model that exists is the STPA control structure. So STRIDE cannot precede Step 2; there is nothing for
it to enumerate against.

**Two.** STRIDE's most valuable output for STPA is the **trust-boundary layer**, and that layer is
consumed at *rating* time — Steps 3 and 4 — not at modeling time.

Therefore: **one STRIDE pass, positioned immediately after Step 2, whose output is consumed at two
points.** Not STRIDE twice, and not STRIDE first.

```
1 losses/hazards → 2 control structure + topology → 2b STRIDE over that structure
  → 3 UCA grid → 4 scenarios → 4c compose → 5 constraints
  → 6 adversarial review → 6b STRIDE reconciliation → 7 plan + report
```

`2b` seeds (boundaries → zones, flows → control actions, assets → controlled processes).
`6b` reconciles (every STRIDE threat maps to a UCA or is recorded out-of-scope; every STPA finding
STRIDE could not have produced is named, because that is the return on running STPA at all).
Same single artifact, read twice. Running the *pattern* twice buys nothing; skipping the
reconciliation loses the coverage cross-check, which is most of the value.

**And STPA does not run twice either.** The temptation to re-run STPA comes from discovering, late,
that the inventory was incomplete — which re-running the same discovery will not fix. That is what
`stpa discover` is for, and it gates *before* the grid exists. When the inventory legitimately grows
mid-run (a new modality accounted for, a controller hand-added), do not restart: `stpa init
model-v2.json --merge grid.json` carries every resolved cell forward and lists only the genuinely new
ones. Re-entry, not repetition.

**When the design doc exists, the shape is unchanged** — the doc simply gives Step 2 a running start,
and STRIDE still runs at `2b` against the control structure the doc informed. The only thing a design
doc changes is how much of Step 2 you had to derive from code.

## When to use

- **At `2b` of every run where the user selected STPA + STRIDE** (the recommended intake default).
- **At `6b` of that same run**, as the coverage reconciliation. Not optional — it is the half that
  catches misses.
- **Standalone**, when the user explicitly selected *STRIDE only* at intake. Deliver the STRIDE model
  and threat table, and state in one line what the choice does not cover (broken object-level authz,
  tenant bleed at a shared plane, confused-deputy, TOCTOU, bypass paths). Do not quietly run STPA
  anyway.
- **As a completeness cross-check on an already-finished STPA run** — the case where a report exists
  and you want to know what it missed. This is `6b` run in isolation, and it is a cheap, high-yield way
  to audit a previous cycle's output.

## Steps

1. **Generate the STRIDE model.** Run the Fabric `create_stride_threat_model` pattern (via the **Fabric** skill) on the design document — or, code-only, on an architecture summary you extract first. It returns five sections: **ASSETS**, **TRUST BOUNDARIES**, **DATA FLOWS** (with the boundary-crossing ones marked), a **THREAT MODEL** table (STRIDE-per-element, id · component · threat · mitigation), and **QUESTIONS & ASSUMPTIONS**.

   ```
   Skill("Fabric")  → ExecutePattern: create_stride_threat_model  (input: the design doc)
   ```

2. **Map the STRIDE output onto STPA inputs.** This is the whole point — each STRIDE section seeds a specific STPA element:

   | STRIDE output | Seeds STPA element | How |
   |---|---|---|
   | **TRUST BOUNDARIES** | **Trust zones (Step 2 topology layer)** | Each boundary becomes a zone edge. This is the highest-value transfer — it is the layer whose absence over-rates internal paths as external and misses the central plane. |
   | **DATA FLOWS** crossing a boundary | **Control actions + feedback** | A flow across a boundary is a controller acting on a process (control action, ↓) or learning a result (feedback, ↑). |
   | **ASSETS** | **Controlled processes + a loss cross-check** | Assets are what is acted upon; high-value assets sanity-check the loss list from Step 1. |
   | **THREAT MODEL** rows | **Loss-scenario vocabulary (Step 4)** | Map by STRIDE letter: **S**poofing → process-model corruption of *identity*; **T**ampering → control-path / feedback *integrity*; **R**epudiation → the *attribution / audit* gap (an H-8-class hazard); **I**nfo disclosure → the *confidentiality* loss; **D**oS → *availability* (usually out of STPA's confidentiality/integrity frame — tombstone with that reason); **E**levation → the *authorization / escalation* UCAs. |
   | **QUESTIONS & ASSUMPTIONS** | **The assumptions log** | Fold directly into `01-scope.md` assumptions; each becomes a rating-gating question (an unconfirmed one makes dependent bands provisional). |

3. **Model the control structure (Step 2) with the trust-zone layer pre-populated.** Proceed with `ModelControlStructure.md` — but the zones, the boundary-crossing control actions, and the controlled processes are already seeded. Hand-add the controllers STRIDE cannot see (operators, pipeline, shipped tooling) as usual.

4. **Run the STPA grid and scenarios as normal**, using the STRIDE threat rows as prompts for Step-4 causation and Part-B bypass — "STRIDE flagged tampering on this flow; is that a wrong-process-model UCA, a control-path compromise, or an independent-modification bypass?"

5. **Completeness cross-check (both directions).** Two lists, reconciled:
   - **STRIDE → STPA:** every STRIDE threat maps to a UCA/scenario, or is recorded as *out of STPA scope* (a component-reliability failure) with a reason. An unmapped high-impact STRIDE threat is a gap in the control structure — go back to Step 2.
   - **STPA → STRIDE:** the emergent findings STPA produced that STRIDE did **not** (broken object-level authz, tenant bleed at a shared plane, confused-deputy, bypass paths) — call these out explicitly. They are the return on running STPA at all, and naming them is how you show the two methods are covering different ground.

## Output

A short `00-stride-seed.md` recording the STRIDE model, the mapping table, and the two-way cross-check — plus a pre-seeded trust-zone layer and control-action/asset list carried into `model.json`. The STPA run proceeds from there.

## Caveats

- STRIDE-per-element wants a **design document**; on a code-only target, extract an architecture summary first (the `ControlStructureScan.ts` candidates plus a hand-written topology) and feed that.
- STRIDE ranks by likelihood × impact; STPA does **not** use likelihood. Keep STRIDE's ranking as *input signal*, not as the STPA band — the band is severity × reachability, rated against the confirmed deployment.
- DoS / availability threats from STRIDE are usually outside STPA-Sec's confidentiality/integrity frame — tombstone them with that reason rather than forcing them into the grid.
