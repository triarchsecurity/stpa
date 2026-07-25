# Contributing

## What this project wants most

**Worked examples.** One complete run against a system you can talk about publicly is worth more than a feature. Put it in `Examples/<name>/` with the artifacts, the rendered report, and a README that says what to look at first and why.

**Stack recipes.** `SoftwareMapping.md` has per-stack entry-point recipes — how to find the control actions in a Rails app, a Go service, a Django project, a Spring app. Every stack we do not cover is a stack where `ControlStructureScan.ts` returns a misleadingly clean result, because a clean scan means "idioms unrecognised" at least as often as it means "pattern absent."

**Refutations.** If you can make the coverage number lie, that is the most valuable issue you can file. Two guards already exist because of exactly this — the binding rule and the concentration guard — and both were added after someone demonstrated the ratio could be gamed.

## What it does not want

Findings from a real system that its owner has not agreed to publish. Sanitise or synthesise; the Ledgerline example is fictional for this reason.

## Ground rules for the method

These are not style preferences. Each one, broken, degrades the analysis into a checklist with extra ceremony.

- **A hazard is a system state, never an attacker action.** "An attacker steals a token" is out; "the system accepts a token that no longer reflects the holder's entitlements" is in.
- **A UCA context states the true state, never the controller's belief and never the result.** "grants access when it believes the caller owns the record" is a *cause* and belongs in Step 4. "grants access when the record belongs to a different tenant" is the UCA.
- **A tombstone needs a written reason.** A silent skip is not a skip. The tools enforce this.
- **Model control actions, not endpoints.** Four routes that all create an order are one control action with four invocation paths.

## Code

TypeScript, on **Node or Bun**. No runtime dependencies, and that is deliberate — the toolkit must run offline with no API keys, no network calls and no telemetry. A PR that adds a dependency needs to argue for it, and a PR that adds a Bun-specific or Node-specific API needs to argue harder: the `stpa` CLI dispatches tools to whichever runtime is running it, and that only works while the tools stay runtime-agnostic.

Keep `Tools/*.ts` executable directly — `bun Tools/X.ts` **and** `node Tools/X.ts` — as well as through the `stpa` CLI.

## Filing an issue

Say what you ran, what you expected, and what you got. If it is a method question rather than a bug, that is welcome too — open a discussion.
