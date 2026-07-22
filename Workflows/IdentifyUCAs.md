# Workflow: IdentifyUCAs — STPA Step 3

Find the contexts in which a legitimate control action becomes hazardous. This is where STPA stops resembling every other threat-modeling method: you are not enumerating attacks, you are enumerating *contexts*, and the adversary's role is to choose the worst one.

## Inputs

- `model.json` from Step 2.
- The hazard list `H-N` from Step 1.
- `../AdversarialContext.md` for the context-generation patterns.

## Outputs

- `grid.json` — every cell resolved as a finding or a reasoned tombstone.
- `<output>/03-ucas.md` — the markdown grid plus the UCA table.
- A printed coverage ratio.

## Steps

1. **Generate the grid.**
   ```bash
   stpa init model.json -o grid.json
   stpa status grid.json
   ```
   The grid has exactly `4 × |control actions|` cells. Every cell must end as a **finding** or a **tombstone with a written reason**. An open cell is a hole in the analysis, and the tool counts them so you cannot pretend otherwise. This is the stopping rule STPA does not natively provide.

2. **For each cell, work the four types.** The question is always *"is there a context in which this is hazardous?"* — never *"can an attacker do X?"*

   | Type | The question | What it catches in software |
   |------|--------------|------------------------------|
   | **Not provided** | If this action is *not* issued when needed, does a hazard result? | Missing authz check on a route; revocation that never propagates; audit event never written; rate limit not applied to a path; input validation skipped on an internal caller |
   | **Provided** | Is there a context in which issuing this action causes a hazard? | Access granted when entitlement was never established; refund issued twice; deploy executed on unreviewed code; data returned across a tenant boundary |
   | **Wrong timing / order** | Too early, too late, or out of sequence relative to another action? | TOCTOU; check-then-use races; token validated before the revocation list refreshes; deploy before migration; idempotency key checked after the write |
   | **Too long / stopped too soon** | Applied for the wrong duration? | Session that never expires; elevated privilege not dropped; lock held past the transaction; unbounded credential TTL; rate-limit window ended early; containment lifted before eradication |

   Type 4 is the one analysts skip and the one that yields the least-obvious findings. Do not skip it.

3. **Generate contexts adversarially.** For each cell, before deciding "no hazard", run the context patterns in `../AdversarialContext.md`: can an adversary make the controller's process model wrong? delay, drop, replay, or forge the feedback? reach the control path directly? change the controlled process by another route? A cell is only safe if it is safe under an adversary who *chooses* the context.

4. **Write every finding in the five-part form.** Non-negotiable — a UCA that does not fit this shape is not yet a UCA:

   > **[Source controller]** provides / does not provide **[control action]** **[type qualifier]** when **[context]**, which leads to **[hazard link]**.

   Example: *The AuthZ middleware **provides** `grant access to a tenant-scoped record` **when** the requested record belongs to a tenant other than the caller's, which leads to **H-1** (the system serves a resource to a system owner whose entitlement has not been established).*

   Note that the context is the true state of the world — *the record belongs to another tenant* — not the mechanism. "Because tenant identity comes from a request header" is the **cause**, and it belongs in Step 4.

   The `when` clause is the load-bearing part. A UCA without a specific context is a platitude — if the context is "always", you have found a design defect, not a UCA, and it should be stated as such.

   **Two context errors the Handbook explicitly forbids, and both are easy to make in software:**

   - **Do not put the result in the context.** ✗ *"…grants access, resulting in a data breach."* ✓ *"…grants access when the caller's entitlement to the resource has not been established [H-1]."* The hazard link carries the outcome; the context carries the condition.
   - **Do not put the controller's belief in the context.** The context must be the **actual, true state**, not a process-model flaw. ✗ *"…grants access when it incorrectly believes the caller owns the record."* ✓ *"…grants access when the record belongs to a different tenant."* This one bites constantly here, because "the code believed the wrong thing" is the most natural way to describe an authorization bug — and it is a **cause**, which belongs in Step 4. Keeping beliefs out of Step 3 is what stops the analysis collapsing into a list of guesses about implementation.

   Note also that **an existing safeguard does not excuse a UCA.** STPA is a worst-case method; a mitigation that might work is not a reason to omit the finding.

5. **Bind every finding to the control structure.** Each finding carries `bindsTo: ["PM-2", "F-3"]` — the process-model variables or feedback channels from Step 2 that make it true *for this system*. **`UcaGrid.ts` does not count an unbound finding toward coverage.**

   This is the anti-checklist guard, and it is mechanical rather than exhortative. A generic statement — *"the controller provides the action when input is attacker-controlled"* — reads the same against any codebase, so it binds to nothing, so it earns no coverage. A grounded one — *"…when the tenant identifier reaching the service was not derived from server-side session state"* — binds to `PM-2` (*caller tenant, sourced from request header*), because that is the modeled element that makes it true here.

   If you cannot name the model element a finding depends on, one of two things is true: the finding is generic (drop it), or Step 2 is incomplete (go back and model the belief you are implicitly relying on). Both are useful answers.

   **Bind to the element that is actually load-bearing for that cell, not to whatever ID is handy.** `status` reports binding spread and warns when one element carries ≥80% of findings, because genuine analysis spreads across the model — different control actions depend on different beliefs. Concentration can be legitimate (small system, one dominant belief); if it is, say so in the report rather than ignoring the warning.

6. **Tombstone deliberately, with reasons.** Many cells genuinely do not produce hazards. Write why: *"CA-4.not-provided — failing to deploy is an availability concern only; availability is excluded from the boundary per 01-scope."* A reasoned tombstone is a real analysis result. A silent skip is not, and the tool rejects tombstones without a `reason`.

7. **Re-run status until coverage is acceptable.**
   ```bash
   stpa status grid.json
   ```
   Target 100% resolved. If you stop below 100%, state the coverage number in the report — a threat model that says "84% of the grid was analyzed, here are the 16% we did not reach" is honest and actionable. One that says "we did a threat model" is neither.

8. **Emit the markdown grid.**
   ```bash
   stpa grid grid.json -o 03-ucas.md
   ```

## Anti-pattern guard

If your findings could have been written without reading the control structure — "the app might be vulnerable to XSS", "check for SQL injection" — you have regressed to checklist threat modeling. Every UCA must name a specific controller, a specific control action, and a specific context drawn from *this* system's model. Discard any finding that survives the deletion of the model.

## Handoff

Step 4 (`LossScenarios.md`) takes each UCA and asks *why would this actually happen?*
