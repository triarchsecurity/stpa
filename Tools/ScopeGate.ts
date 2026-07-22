#!/usr/bin/env bun
/**
 * ScopeGate.ts — holds the analysis to the scope that was ASKED FOR.
 *
 * WHY THIS EXISTS (a real failure, 2026-07-22).
 *
 * A user selected "Full surface" at intake. The analysis modeled 12 of 20 control
 * actions, declared the other 8 "deferred", and reported 60% surface coverage as
 * though that were a scoping decision. It was not. It was an unfinished analysis
 * written up as a virtue, and six of the eight deferral reasons were literally
 * "not read this pass".
 *
 * Nothing caught it, for a structural reason worth stating plainly:
 *
 *   surface coverage = modeled / candidateControlActions
 *
 * and the ANALYST SETS BOTH NUMBERS. Writing `candidateControlActions: 12` would
 * have printed a clean 100%. A ratio whose denominator the reporter chooses is not
 * a control. Worse, the intake answer lived only in conversation, so no tool could
 * compare what was delivered against what was requested.
 *
 * Three checks, in order of how much they would have caught:
 *
 *   1. CONTRACT   — `scope.requested` is recorded at intake. If it is "full" and
 *                   any control action is unmodeled, that is a BREACH, not a
 *                   deferral. Exit 6.
 *   2. REASONS    — under a full-scope contract, "not read" is not a scoping
 *                   reason. It is an unfinished item wearing one. Exit 6.
 *   3. DENOMINATOR— the candidate count is sanity-checked against the target's
 *                   actual route/entry-point inventory, so a small denominator
 *                   cannot manufacture a clean percentage.
 *
 * Usage:
 *   bun ScopeGate.ts <analysis-dir> [--inventory N] [--warn-only]
 */

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

function die(m: string, c = 1): never {
  console.error(m);
  process.exit(c);
}

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h"))
  die(
    [
      "ScopeGate.ts — hold the analysis to the scope that was requested",
      "",
      "Usage: bun ScopeGate.ts <analysis-dir> [--inventory N] [--warn-only]",
      "",
      "  --inventory N   the target's real entry-point count, to sanity-check the",
      "                  candidate denominator (e.g. number of API route files)",
      "  --warn-only     report without failing (exit 0 regardless)",
      "",
      "model.json must carry scope.requested — one of:",
      "  full            every authority-bearing control action (nothing may be unmodeled)",
      "  focused:<lens>  a named subset, e.g. focused:authz",
      "  triage          a bounded PR/feature pass",
      "Exit 6 = the delivered scope does not honour the requested scope.",
    ].join("\n"),
    2,
  );

const dir = resolve(argv.find((a) => !a.startsWith("-") && argv[argv.indexOf(a) - 1] !== "--inventory") ?? ".stpa");
const invIdx = argv.indexOf("--inventory");
const inventory = invIdx !== -1 ? Number(argv[invIdx + 1]) : null;
const warnOnly = argv.includes("--warn-only");

const modelPath = join(dir, "model.json");
if (!existsSync(modelPath)) die(`no model.json in ${dir}`);
const model = JSON.parse(readFileSync(modelPath, "utf8"));

const scope = model.scope ?? {};
const requested: string | undefined = scope.requested;
const candidates: number | undefined = scope.candidateControlActions;
const modeled: number = (model.controlActions ?? []).length;
const deferred: { name: string; reason: string }[] = scope.deferred ?? [];
const sources: { type?: string; locator?: string; ref?: string }[] = scope.sources ?? [];

let failed = false;
const fail = (m: string) => {
  console.error(m);
  failed = true;
};

console.log(`scope contract — ${dir}\n`);
console.log(`  requested:  ${requested ?? "NOT RECORDED"}`);
console.log(`  candidates: ${candidates ?? "not declared"}`);
console.log(`  modeled:    ${modeled}`);
console.log(`  deferred:   ${deferred.length}`);
if (inventory) console.log(`  inventory:  ${inventory} entry points in the target`);
console.log(`  sources:    ${sources.length ? sources.map((x) => `${x.type ?? "?"}:${x.locator ?? "?"}${x.ref ? ` @${x.ref}` : ""}`).join(", ") : "NONE RECORDED"}`);
console.log("");

// ── 1. contract recorded at all ───────────────────────────────────────────
if (!requested) {
  fail(
    [
      "NO SCOPE CONTRACT RECORDED.",
      "",
      "  model.json has no scope.requested, so nothing can check the delivered",
      "  scope against the asked-for scope. The intake answer must be written",
      "  down at intake — if it lives only in conversation, the only party who",
      "  can grade the result is the party who chose how much to do.",
      "",
      '  Add: "scope": { "requested": "full" | "focused:<lens>" | "triage", ... }',
    ].join("\n"),
  );
}

// ── 2. full means full ────────────────────────────────────────────────────
if (requested === "full") {
  if (typeof candidates === "number" && modeled < candidates) {
    fail(
      [
        `CONTRACT BREACH: full surface was requested; ${modeled} of ${candidates} control actions were modeled.`,
        "",
        `  ${candidates - modeled} unmodeled control action(s) under a full-scope contract are not a`,
        "  scoping decision — they are unfinished work. Surface coverage would report",
        `  ${((modeled / candidates) * 100).toFixed(0)}%, which reads as a considered boundary and is not one.`,
        "",
        "  Either finish them, or go back to the requester and get the scope changed",
        "  to focused:<lens>. Narrowing scope is theirs to decide, not the analyst's.",
      ].join("\n"),
    );
  }

  // "not read" is an unfinished item, not a reason
  const UNFINISHED = /\bnot (read|examined|opened|analy[sz]ed|modeled|covered)\b|\bthis pass\b|\bran out of\b|\bno time\b|\btime constraint/i;
  const bad = deferred.filter((d) => UNFINISHED.test(d.reason ?? ""));
  if (bad.length) {
    fail(
      [
        `INVALID DEFERRAL REASONS under a full-scope contract (${bad.length}):`,
        ...bad.map((d) => `    ${d.name}\n      "${d.reason}"`),
        "",
        '  "not read" describes the analyst\'s progress, not the system\'s risk. A valid',
        "  deferral says why the thing does not need analysing — no authority exercised,",
        "  outside the declared boundary, static content with no tenant dimension. If the",
        "  only reason is that nobody got to it, it is not deferred; it is outstanding.",
      ].join("\n"),
    );
  }
}

// ── 2b. provenance: what was actually consulted ───────────────────────────
// A design document that was offered at intake and never read is the quiet
// failure in a multi-input analysis: the report implies both were consulted and
// nothing says otherwise. Recording sources makes "we threat modeled it" into a
// statement someone can check.
if (!sources.length) {
  fail(
    [
      "NO SOURCES RECORDED.",
      "",
      "  model.json declares no scope.sources, so the report cannot say what was",
      "  actually consulted — which repo, which branch, which documents. In a",
      "  multi-input analysis this is how a design doc gets offered, never read,",
      "  and silently implied in the result.",
      "",
      '  Add: "sources": [{ "type": "codebase", "locator": "org/repo", "ref": "main @sha" }]',
    ].join("\n"),
  );
} else {
  const vague = sources.filter((x) => !x.locator?.trim() || !x.type?.trim());
  if (vague.length) fail(`${vague.length} source(s) missing a type or locator — provenance must name the thing, not gesture at it.`);
  const codebases = sources.filter((x) => x.type === "codebase");
  const unpinned = codebases.filter((x) => !x.ref?.trim());
  if (unpinned.length) {
    fail(
      [
        `${unpinned.length} codebase source(s) have no ref (branch/commit).`,
        "",
        "  An analysis of 'the repo' is not reproducible and not comparable to the next",
        "  one. Branches diverge — a finding true on a feature branch may not exist on",
        "  main, and vice versa. Pin the ref.",
      ].join("\n"),
    );
  }
}

// ── 3. the denominator is not the analyst's to shrink ─────────────────────
if (inventory && typeof candidates === "number") {
  // Very rough: grouping entry points into control actions legitimately compresses,
  // but an order-of-magnitude gap usually means the denominator was chosen to make
  // the percentage look good rather than derived from the surface.
  const ratio = inventory / candidates;
  if (ratio > 8) {
    fail(
      [
        `IMPLAUSIBLE DENOMINATOR: ${inventory} entry points compressed into ${candidates} candidate control actions (${ratio.toFixed(1)}:1).`,
        "",
        "  Grouping endpoints into control actions compresses legitimately — several",
        "  routes issuing one authority are one action — but a ratio this high usually",
        "  means the denominator was set small rather than derived. Surface coverage is",
        "  modeled/candidates, so shrinking candidates inflates the percentage without",
        "  analysing anything. Justify the grouping in scope.selectionCriteria or raise",
        "  the candidate count.",
      ].join("\n"),
    );
  }
}

if (!failed) {
  console.log(`scope contract honoured${requested === "full" ? " — full surface delivered" : ` — ${requested}`}.`);
  process.exit(0);
}
console.error(`\n${warnOnly ? "(--warn-only: not failing)" : "Exit 6."}`);
process.exit(warnOnly ? 0 : 6);
