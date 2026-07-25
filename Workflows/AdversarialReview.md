# Workflow: AdversarialReview — an independent model attacks every finding before a human sees it

**Why this is mandatory, not optional.** The analysis is produced by the reasoning of one model, and a model rationalises its own inflation — in a real run it rated a *latent, single-tenant, internal* path as a *live, cross-tenant* one and would have shipped it. A same-model self-check does not catch this, because it shares the blind spot. The fix is an adversarial pass by a **different** model whose job is to *refute*, and a gate (`stpa verify`) that refuses to certify a report the review did not cover. **Objective self-assessment is required and computed from the record — never self-narrated.**

## When

After the UCA grid and the plan exist, **before** `stpa report` is treated as final. `stpa run` calls `stpa verify` automatically; a report generated without a passing review carries a **NOT-PEER-REVIEWED** banner and the command exits non-zero.

## The reviewer

- **A different model from the author, cross-vendor where possible.** Record both in `reviews.json` (`authorModel`, `reviewerModel`); `stpa verify` fails (exit 4) if they match. If only one model family is available, use a different *tier* and say so — but note in the report that the review was not cross-vendor.
- **For every band-1/2 finding, use ≥2 independent reviewers and take the majority** — the highest-severity claims are the ones an inflated analysis most wants to keep.
- The reviewer gets the finding, its `bindsTo` process-model beliefs, the trust-zone/topology facts, and the code at the cited `file:line`. It does **not** get the author's confidence.

## What the reviewer attacks (per finding)

1. **Reachability — name the deployed path.** "You rated this R0/R1. What concrete path does an adversary take *in the deployed system*? Is the entry internet-facing or on an internal private network? Does the config that makes it reachable actually ship?" Code presence is not reachability.
2. **Trust zone & blast radius.** "Which zone is this in — a single-tenant per-customer deployment, the central plane, a cloud account? Is the impact cross-tenant, or total-compromise-of-one-tenant? A defect that is latent inside a single-tenant deployment is not a live cross-tenant breach."
3. **Live vs latent / assumption dependence.** "Does the band depend on an unconfirmed assumption? If yes, it is *provisional*, not confirmed."
4. **STPA validity, not STRIDE regression.** "Would this survive deleting the control structure ('check for XSS')? If yes it is a checklist item, not an STPA finding — refute it."
5. **Evidence.** "Is the `file:line` real, and does it say what the finding claims? Read it."

6. **Composition — attack the finding SET, not the finding.** This is the duty that was missing, and
   its absence shipped a real error twice. Ask of every finding rated R2–R4: *"the prerequisite this
   rating assumes an attacker must already have — does some other finding in this report hand it to
   them?"* A PTY gated on a staff identity is not R3 when another finding forges arbitrary identities
   at R0. A bus write that needs a network foothold is not R3 when another finding gives code execution
   on the box.

   Work from `07-chains.json` (`stpa compose`), and treat a *missing* chain as a question rather than an
   answer: if a finding requires a capability that nothing in the report grants, either the environment
   genuinely denies it — say which control — or **the granting finding was never found**, which sends
   you back to `stpa discover`. In the run this rule comes from, the capability nothing granted was
   host execution, and the reason was that the PTY that would have granted it was never modelled.

   The reviewer is the right owner for this because the author rated each finding as they wrote it,
   one at a time, and composition is invisible from inside that loop.

7. **UNDER-rating and inventory gaps — the duty that was missing, and its absence cost two whole control actions.**
   Every dimension above removes or softens a finding. A reviewer briefed only to refute will therefore
   only ever shrink the report, and in a real run **0 of 96 verdicts were upgrades** — after which a third
   model found two unmodelled generic RPC bridges, a systemic authority defect (roles read out of the
   token), and a seeded super-admin account in every deployment. None of that was a mis-rating; all of it
   was *absent*. So you owe two more answers:

   - *"What is UNDER-rated?"* Use verdict `upgrade` with `newBand`, on the same evidentiary standard as a
     downgrade: name the deployed path that makes it worse than recorded.
   - *"What authority-bearing action is missing from the model entirely?"* Record it as `inventoryGap` on
     any finding, or as a standalone entry. Look specifically at what a route sweep collapses: a path whose
     segment NAMES the operation (`/api/:command`) is a registry, not an endpoint, and its authority is the
     union of everything it dispatches to. `stpa verify` prints a warning when a review returns zero
     upgrades, because that is a property of the brief rather than evidence the analysis was complete.

## The verdict (write to `reviews.json`)

Each finding gets one of: **confirmed** (survives — and for a live one, `reachabilityPath` is *required*), **downgrade** (`newBand` + why — usually reachability was over-rated), **upgrade** (`newBand` + the deployed path that makes it worse), **provisional** (`assumption` id it rides on), **refuted** (`reasons` → the author must tombstone it). Also record the `zone`, and `inventoryGap` for anything authority-bearing the model omits.

**Applying a verdict means changing the artifact, and `stpa verify` now enforces that** (exit 7). A refuted finding must be tombstoned; a downgrade or provisional must be stamped in `remediation.json`. This exists because a reviewer once caught two unmodelled RPC bridges and the apply step reverted the correction, so the report went on asserting the opposite while the scorecard claimed the finding had been checked.

```json
{ "authorModel": "claude-opus-4-8", "reviewerModel": "gpt-5.5",
  "findings": {
    "CA-x.provided": { "verdict": "downgrade", "newBand": 3, "zone": "per-deployment",
      "reasons": ["private-DNS bus, not internet-facing → R3 not R0; blast radius one deployment"] }
  } }
```

## Gate & scorecard

Run `stpa verify <dir>`. It refuses (non-zero) if there is no review, if the reviewer is not independent, if any finding is unreviewed, or if a confirmed-live finding names no deployed path — and it writes `review-scorecard.json` (reviewed %, verdict split, independent-model, live-with-path %, trust-zones-modeled). The renderer surfaces that scorecard as a **"How much to trust this analysis"** panel near the top, so the human sees the objective self-assessment before the findings — and a NOT-PEER-REVIEWED banner if the gate did not pass.

## Apply the verdicts

Refuted → tombstone the cell (with the reviewer's reason). Downgraded → set the new band in `remediation.json` and re-run `stpa plan`. Provisional → tag the assumption and surface it to the owner (see the two-way engagement loop). Then re-render. A finding the review changed but the report still shows unchanged is the exact failure this stage exists to prevent.
