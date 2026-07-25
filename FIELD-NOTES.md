# Field notes — observed failure modes, and the gate that catches each

Every gate in this toolkit exists because an analysis shipped a specific error. This file
records those errors so the reasoning survives the person who hit them, and so nobody has
to rediscover why a check is worth its friction.

The organising principle: **a review dimension that keeps finding things should become an
analysis-time obligation.** Review should confirm, not discover.

---

## The run these notes come from

A ~3,600-file TypeScript monorepo, full-surface, three model passes:

| pass | role | result |
|---|---|---|
| 1 | author | 96 findings |
| 2 | independent adversarial review | 22 refuted · 14 downgraded — **48% corrected** |
| 3 | third-model audit | 2 unmodelled control actions · 1 systemic authority defect · 1 seeded super-admin |

Pass 2 mostly *removed* findings. Pass 3 mostly *added* them. Neither contradicted a
verified conclusion of the other — so the trajectory was convergence, not decay. What
degraded was the **artifact**: retractions accumulating as prose across five documents.

---

## 1 · Asserting a control is absent without reading the code

**Four findings claimed a control did not exist. All four were false.**

| claim | reality |
|---|---|
| no signature verification at deploy/update | a 2-of-N EdDSA JWS verifier with anti-rollback and repo-pinning |
| no idle timeout on shell sessions | `IDLE_TIMEOUT = 30 * 60 * 1000`, with a wired sweep |
| the tool surface is mounted with no auth guard | `app.use('/mcp', authMiddleware, route)` — 130 lines below the handler that was read |
| an unset config flag means the check never runs | the field defaulted to `true`; unset meant **enabled** |

The mechanism was identical every time: read the **use** of a flag or the **handler**,
infer the default or the middleware, never read the declaration or the mount.

The fourth was rated **band-1, R0** and recorded as **CONFIRMED**. An independent reviewer
refuted it by opening the file.

**Why this error is uniquely dangerous:** inferring an absence always makes the finding
*worse*. The bias runs one way, so it inflates severity, reads plausibly on self-review,
and arrives at the owner as a false band-1.

**Rules.** Grep for the thing you say is missing and read every hit. Read declarations and
defaults, not uses — `x ?? true` inverts what "not passed" means. Follow the router mount,
not the handler. Cite the line you read, or the negative search you ran.

**Gates:** `stpa controls` · the absence-evidence check in `Prioritize.ts`

## 2 · The scan already found it, and nothing consumed the evidence

`ControlStructureScan.ts` emits a `guards` category. That run produced **2,508 guard
candidates and the analysis used zero of them.** For two of the four false claims above,
the scan had already flagged a guard *in the very file the finding called unguarded* —
including a `WWW-Authenticate` header **inside** the middleware declared not to exist.

`stpa controls` does the one comparison nobody was doing. It cannot prove an absence.
It proves you did not look, which is the actual failure mode.

Design note: it needs **nothing filled in by hand**. A gate that costs busywork is a gate
that gets bypassed with `--warn-only`.

## 3 · A belief credited as a working control, because `sourcedFrom` named a hop

One process-model variable read *"roles are re-read from the database on every request"*
and was **credited as a control that works**. True for one guard; false for the two
authority helpers that resolved the role by decrypting the caller's own token.

Consequence: **six remediations saying "gate this on an operator role" were placebos**,
because the attacker writes the role.

Two models missed it. A third found it by tracing the source to its origin.

**Rule.** `sourcedFrom` must terminate in a trust root: `database` · `iam` · `network` ·
`human` · `attacker-input` · `unverified`. *"the session"*, *"the token"*, *"config"* are
hops. A token expands to what verifies it, under which key, and whether the adversary can
obtain that key. `unverified` is a legitimate answer and forces the dependent band
provisional.

**Gate:** `stpa evidence`

## 4 · A route whose path segment names the operation

`/api/orch/:command` and `/api/function/:command` forwarded an arbitrary caller-named
command with no per-command authority filter, reaching in-process `eval`, arbitrary SQL,
and a self-update taking a caller-supplied image.

They survived **two passes and an adversarial review**, because a route sweep sees them as
HTTP routes and collapses them into one REST control action. A path segment that names the
operation is a **registry**, not an endpoint, and its authority is the union of everything
it dispatches to.

**Gate:** the `dynamic-dispatch-route` discovery modality

## 5 · A review briefed only to refute is one-directional

**0 of 96 verdicts were upgrades.** That silence is a property of the brief, not evidence
of completeness — the third pass then found two whole control actions that were not
mis-rated but *absent*.

**Rule.** Brief every reviewer with the upgrade duty: `upgrade` as a verdict, and
`inventoryGap` for authority nobody modelled.

**Gate:** `stpa verify` warns at zero upgrades

## 6 · A verdict that was filed but never applied

A reviewer caught the RPC bridges of §4 and **the apply step reverted the correction**, so
the report went on asserting the opposite while the scorecard claimed the finding had been
checked. That is worse than an unreviewed finding.

The specific mechanism: **re-merging reviews after the apply step has already run.** It
recurred while building the gate that catches it, leaving 11 verdicts filed and unstamped.

**Gate:** `stpa verify` exit 7 — refutations must be tombstoned, downgrades and
provisionals stamped

## 7 · A number typed by hand

A scope document said "44 tombstones" while the grid held 66, because a correction pass
changed the grid and nobody re-typed the sentence. One checkable-and-wrong number
discredits every number beside it.

**Rules.** Never type a count the tools compute. Put retractions in `corrections.json`,
which the report renders as one section — a corrected analysis that has become unreadable
is a worse deliverable than the uncorrected one.

**Gate:** `stpa evidence` (`--fix-numbers` rewrites them)

---

## On writing gates

Three of these gates produced **false positives on first run**, and each was fixed by
running it rather than reasoning about it:

- `"443 open"` — matched a port range, because `open` was too generic a noun.
- `"closes 12 findings"` — a cluster-leverage count read as a total.
- The absence check demanded `file:line` **for an absence**, which is incoherent; and it
  then failed the shipped worked example, which is derived from a design document and has
  no lines to cite at all.

That last one is the general lesson: **the evidence standard must match what the analysis
was derived from.** A codebase analysis cites code. A design-document analysis cites the
document.

A gate that cries wolf gets disabled, so a false-positive class is not cosmetic — it is
the failure of the gate.
