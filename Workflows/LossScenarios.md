# Workflow: LossScenarios — STPA Step 4

Explain *why* each unsafe control action would actually occur, and *why* a correct control action might fail to have its intended effect. Step 3 tells you what unsafe looks like; Step 4 tells you how the system gets there. Scenarios are what become mitigations.

## Inputs

- `grid.json` with resolved findings from Step 3.
- The process-model table and feedback map from Step 2.
- `../AdversarialContext.md`.

## Outputs

- `<output>/04-scenarios.md` — scenarios keyed to UCA IDs, each with causal factors and a mitigation direction.
- Each scenario tagged `part-a` (why the UCA occurs) or `part-b` (why execution fails).

## Steps

1. **Part A — why would this UCA occur?** For each UCA, work the controller side. The causal factors cluster into three:

   - **The controller's process model is wrong.** It believes something about system state that is not true. Sources: state supplied by an untrusted party and never validated server-side; a cache that outlives the truth; a token whose claims were correct at issue and are not now; a default assumed rather than read; a race in which the belief was true when read and false when acted on; a value correct for one tenant applied to another.
   - **The controller's algorithm is inadequate.** The decision logic itself is wrong or incomplete for the context: an allow-list that does not cover a path; a comparison that is case-sensitive when identity is not; ordering assumed but not enforced; an error path that falls through to allow; a feature flag that changes the decision without changing the code.
   - **Feedback is missing, delayed, wrong, or forged.** The controller cannot know the true state because the signal never arrives (no audit trail), arrives late (eventual consistency), arrives wrong (unauthenticated webhook, log injection), or is suppressed by the adversary (log deletion, alert flooding).

2. **Part B — why might a correct control action fail to have its effect?** Work the path and the process side. Even a correct decision can fail to land:

   - **The control path is compromised or lossy.** The instruction is intercepted, replayed, reordered, dropped, or forged in transit: an unauthenticated internal service call, a queue without message authentication, SSRF reaching an internal control plane, a retry that duplicates a non-idempotent action.
   - **The controlled process does not respond as expected.** The revocation is written but the running process holds a cached copy; the deletion is soft and the data remains readable; the config change requires a restart that never happens; the write succeeds on the primary and is lost on failover.
   - **The controlled process is changed by something else.** This is the bypass class and it is the highest-yield category in real systems: a second service writing the same table without the guard; a direct database connection held by an operator or a migration job; an admin console that skips the API; a cron job running with more authority than any user; a support tool with impersonation.

3. **Write each scenario concretely.** A scenario names the mechanism, not the category. *"Feedback could be manipulated"* is not a scenario. *"The billing webhook handler trusts the `event.type` field in the request body and the endpoint has no signature verification, so an adversary who learns the URL can assert `payment.succeeded` and cause the entitlement service to grant a paid tier"* is a scenario — and it names its own fix.

4. **Attach a mitigation direction to each scenario.** Not a full design; a direction. Prefer, in order: eliminate the hazard (change the control structure so the context cannot arise), constrain the controller (make the wrong decision impossible), improve the process model (derive the belief from an authoritative source), add feedback (make the failure detectable). *Detection is the weakest of the four and should be recorded as such* — a scenario mitigated only by an alert is a scenario that still happens.

5. **Sweep the class.** When a scenario turns out to be an instance of a class — "the tenant id comes from a header here" — enumerate every sibling instance across the codebase before closing it. One fixed instance of a class is an incomplete fix. Record the enumeration probe and the count.

6. **Rank.** Use the loss-severity × context-reachability heuristic in `../AdversarialContext.md`. State plainly that this is a toolkit extension, not STPA doctrine — STPA deliberately does not rank by likelihood.

## Handoff

`SecurityConstraints.md` converts scenarios into constraints and probes.
