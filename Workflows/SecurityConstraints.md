# Workflow: SecurityConstraints — from findings to build gates

The step that decides whether the threat model survives contact with a sprint. A finding in a document is advice. A finding expressed as a negative assertion with a named probe is a gate.

**The move:** an STPA controller constraint and a test assertion are the same object. Both say *"this must not happen"*, both are stated about a specific controller in a specific context, and both are only real if you can name the check that would catch a violation. So the output does not get filed in a wiki — it becomes assertions your build already runs.

## Inputs

- UCAs from Step 3 and scenarios from Step 4.
- Wherever your project keeps executable expectations: a test suite, a CI policy file, a requirements or acceptance document.

## Outputs

- **Controller constraints** — `CC-N`, one per UCA, in requirement form.
- **Negative assertions** — one per constraint, each with a runnable probe.
- A probe table: `id | type | check | threshold | command`.
- `<output>/05-constraints.md`.

## Steps

1. **Invert each UCA into a controller constraint.** Mechanical, and it should feel mechanical — that is the sign Step 3 was done properly.

   | UCA type | Constraint form |
   |----------|-----------------|
   | Not provided | `<Controller> MUST provide <action> when <context>.` |
   | Provided | `<Controller> MUST NOT provide <action> when <context>.` |
   | Timing / order | `<Controller> MUST provide <action> only after <precondition> and within <bound>.` |
   | Duration | `<Controller> MUST sustain / terminate <action> within <bound> of <event>.` |

   Example: UCA *"the authorization middleware provides grant-access when the requested record belongs to another tenant"* → `CC-3: The authorization middleware MUST derive tenant identity exclusively from server-side session state, never from request-controlled input.`

2. **Add scenario-derived constraints.** Step 4 scenarios often imply constraints no single UCA does — especially in Part B, where the bypass class lives. *"No process may write to the tenant table except through the data-access layer that applies tenant scoping"* comes from a scenario, not from a UCA.

3. **Convert each constraint into a negative assertion with a probe.** This is the gate: **if you cannot name the probe, the constraint is not finished.** Rewrite it until you can.

   ```
   SEC-41  MUST NOT: any code path reaches the tenant table without passing tenant-scope enforcement
   ```

   | id | type | check | threshold | command |
   |----|------|-------|-----------|---------|
   | SEC-41 | grep | enumerate query sites against the tenant table; each must route through `withTenantScope` | 0 direct sites | `rg -n "from\(.tenants?.\)" src \| rg -v withTenantScope` |

4. **Prefer universal (∀) form over example form.** `∀ routes under /api/tenant/*: the handler applies tenant scoping` is one quantifier stronger than `the /api/tenant/orders route applies tenant scoping`, and it is the form that survives someone adding a route next month. Where the property is over pure logic, a property-based test (fast-check, Hypothesis, QuickCheck) beats an example test.

5. **Choose the probe type honestly.** Unit or property tests for logic; `grep`/`glob` enumeration for structural invariants like "no bypass path exists" — these are often the strongest available, because they assert over the whole codebase rather than one call; HTTP requests for API behavior; a query for data invariants; `manual` only when nothing else is possible — and a `manual` probe on a load-bearing constraint is itself a finding.

6. **Land the assertions where your build already looks.** Three good homes, in descending order of durability:
   - **A test file** — `security-invariants.test.ts` (or your equivalent) holding the grep-style structural assertions. They run on every commit, and they fail loudly when someone adds the 309th route without a guard.
   - **A CI policy step** — the same probes as a shell script that gates the pipeline.
   - **A requirements or acceptance document** — weakest, because nothing executes it, but still better than a wiki page.

   From this point the threat model stops being a document that rots and becomes something the build enforces. That transition is the entire purpose of this workflow.

7. **Record what was deliberately not constrained.** Every tombstoned grid cell and every accepted risk gets a written line with its reason. Accepted risk that is written down is risk management; accepted risk that is silent is an oversight wearing a disguise.

## Handoff

The constraints are now build artifacts. Re-run Step 3 when the control structure changes — new controller, new entry point, new external integration, new operator role. Use merge mode so the delta really is cheap:

```bash
stpa init model-v2.json --merge grid.json -o grid-v2.json
```

Resolved cells carry forward, only genuinely new cells are listed for analysis, removed cells are flagged for confirmation (a disappeared control action is either a real design change or a modeling omission), and any carried finding whose bound element no longer exists is reported as no longer counting.
