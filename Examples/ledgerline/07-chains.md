# 07 — Composition: how findings chain

Reachability is not a property of a finding. It is a property of a finding **given what the other findings hand the attacker.** A finding rated R3 ("needs a foothold") is not R3 if another finding in this same report *is* the foothold. This section recomputes every band with that in mind.

> **Not STPA doctrine and not a probability.** STPA has no likelihood model and no notion of chained findings. Composed bands order this analysis's own findings and nothing else.

**8 of 8 findings (100%) declare grants/requires.** Findings that declare neither cannot chain and cannot be chained to — an undeclared finding is invisible here, so a low percentage means this section is weak, not that the system is safe.


## No composed upgrades

No finding's reachability improved through another finding. That is a real result only if the declaration rate above is high — otherwise it means the inputs were not filled in.


## What to do with this

A composed upgrade is not a new finding — it is the same finding, correctly rated. Set the composed reachability in `remediation.json` and re-run `stpa plan`, or record why the chain does not hold (a control between the two links that neither finding mentions). Leaving a composed upgrade unaddressed is how a report ships an R3 that is really an R0.
