# Workflow: ScopeAndLosses — STPA Step 1

Define the purpose of the analysis. This is the step people skip, and skipping it is why most threat models are unusable: without stated losses there is no way to tell an important finding from an interesting one.

## Inputs

- A target: a repository path, a system design document, or a prose description of a system.
- Optional: existing compliance obligations, an incident history, a customer contract with stated guarantees.

## Outputs

- `Losses` — numbered `L-N`, stakeholder-level things whose occurrence is unacceptable.
- `Hazards` — numbered `H-N`, **system states** that, in a worst-case environment, lead to a loss.
- `System-level constraints` — numbered `SC-N`, the inversion of each hazard into something the system must enforce.
- A written **analysis boundary**: what is inside the system, what is environment, what is deliberately excluded.
- Written to `<target>/.stpa/01-scope.md` (or the analysis output directory chosen at invocation).

## Steps

1. **State the system's purpose in one sentence.** Use the STPA-Sec form: *"a system to do {what} by means of {how} in order to contribute to {why}."* If you cannot write this, you do not yet know what you are analyzing — read more before continuing. The purpose statement is what makes losses derivable rather than invented.

2. **Declare the analysis boundary explicitly.** Three lists: **inside** (things whose design you can change), **environment** (things you must accept, including the adversary), **excluded** (things deliberately not analyzed, each with a reason). The boundary is the single biggest determinant of the result — an unstated boundary means the analysis quietly expands until it is abandoned.

3. **Enumerate losses.** A loss is stated in stakeholder terms and involves something of value to someone. It is *not* a technical event. Start from the catalogue in `../SoftwareMapping.md` § Loss Catalogue and cut what does not apply; add what is specific to this system. Aim for 4–8. More than ~10 usually means hazards have leaked into the loss list.

   - Correct: `L-1: Customer personal data is disclosed to an unauthorized party.`
   - Wrong: `L-1: SQL injection in the search endpoint.` — that is a scenario, not a loss.

4. **Enumerate hazards.** A hazard is a **system state or condition** that, together with a worst-case set of environmental conditions, will lead to a loss. Three rules, each of which catches a common error:

   - **A hazard is a system state, not an attacker action.** `An attacker steals a session token` is not a hazard. `The system accepts a session token that no longer reflects the holder's current entitlements` is.
   - **A hazard is within the system's control.** If you cannot design it away, it belongs in the environment, not the hazard list.
   - **A hazard is not a component failure or a cause.** `Redis is down` is a cause. `The system serves a response derived from authorization state it has not confirmed` is a hazard.

   Every hazard links to ≥1 loss. A hazard with no loss link is out of scope; a loss with no hazard is an unfinished analysis. Start from `../SoftwareMapping.md` § Hazard Catalogue.

5. **Invert each hazard into a system-level constraint.** Mechanical: `SC-N: The system must not <hazard>` or `SC-N: If <hazard state> occurs, the system must <mitigate> within <bound>`. These become the top of the requirement chain that Step 4 output eventually satisfies.

6. **Refine hazards into sub-hazards only where the refinement changes the analysis.** Optional. Refine when a single hazard would otherwise force every control action into the same undifferentiated bucket.

7. **Sanity gate before proceeding.** Confirm all of: every loss is stakeholder-level; every hazard is a system state; every hazard links to ≥1 loss; the boundary lists all three categories; nothing in the hazard list names an attacker technique. Any failure here compounds through Steps 2–4 — fix it now, it is ten times cheaper.

## Handoff

Step 2 (`ModelControlStructure.md`) consumes the boundary and the hazard list. The hazard IDs are referenced by every UCA in Step 3, so they must be stable — number them once and do not renumber.
