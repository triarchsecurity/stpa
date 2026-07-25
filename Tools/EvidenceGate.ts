#!/usr/bin/env bun
/**
 * EvidenceGate.ts — two checks that stop the report asserting things nothing computed.
 *
 * ── 1. TRUST ROOTS ─────────────────────────────────────────────────────────────
 * Every process-model belief records `sourcedFrom`. In a real run one of them said
 * the caller role was "re-read from the database on every request", and it was
 * CREDITED as a control that works. It was half true: `loginRequired` does read the
 * database, but `identityHasRole()` and `hasClaim()` resolve the role by decrypting
 * the caller's own token — so the role was attacker-supplied data, and roughly six
 * remediations that said "gate this on an operator role" were placebos. Two models
 * missed it; a third found it by tracing the source to its origin.
 *
 * The fix is to make `sourcedFrom` terminate. A belief is only as trustworthy as the
 * root its evidence bottoms out in, so every variable must name one:
 *
 *   database        a read of authoritative state at decision time
 *   iam             a cloud/platform authorization decision
 *   network         a network position (VPC, private DNS, SG)
 *   human           an out-of-band human action
 *   attacker-input  request data, a token payload, a caller-supplied parameter
 *   unverified      not traced yet — HONEST, and forces the band to be provisional
 *
 * "the session", "the token", "config" are not roots — they are hops. A token
 * expands to: what verifies it, under which key, and can the adversary obtain that
 * key. Writing `attacker-input` where that chain ends in the caller is the single
 * most useful sentence in the model.
 *
 * ── 2. DERIVED NUMBERS ─────────────────────────────────────────────────────────
 * Counts the tools compute must never be typed into prose. In a real run the scope
 * document said "44 tombstones" when the grid held 66, because a correction pass
 * changed the grid and nobody re-typed the sentence. Any number a reader could check
 * against an artifact and find wrong destroys trust in every number beside it, so
 * this gate recomputes the canonical values and fails on any hand-written
 * disagreement.
 *
 * Usage:
 *   bun EvidenceGate.ts <analysis-dir> [--warn-only] [--fix-numbers]
 *
 * Exit: 0 pass · 2 bad input · 9 unresolved trust root or a wrong number in prose
 */

import { existsSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const ROOTS = new Set(["database", "iam", "network", "human", "attacker-input", "unverified"]);

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) {
  console.log(
    [
      "EvidenceGate.ts — trust-root provenance + derived-number consistency",
      "",
      "Usage: bun EvidenceGate.ts <analysis-dir> [--warn-only] [--fix-numbers]",
      "",
      "Every processModels[].variables[] entry needs trustRoot ∈",
      "  " + [...ROOTS].join(" | "),
      "",
      "--fix-numbers rewrites hand-written counts in 0*.md to the computed values.",
      "Exit 9 = an unresolved trust root, or prose disagreeing with the artifacts.",
    ].join("\n"),
  );
  process.exit(2);
}
const warnOnly = argv.includes("--warn-only");
const fixNumbers = argv.includes("--fix-numbers");
const dir = resolve(argv.find((a) => !a.startsWith("-")) ?? ".stpa");

function readJson(name: string, required = true): any {
  const p = join(dir, name);
  if (!existsSync(p)) {
    if (!required) return null;
    console.error(`no ${name} in ${dir}`);
    process.exit(2);
  }
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch (e) {
    console.error(`${name} is not valid JSON: ${(e as Error).message}`);
    process.exit(2);
  }
}

const model = readJson("model.json");
const grid = readJson("grid.json");
const plan = readJson("06-remediation.json", false);

let failed = false;
const fail = (m: string) => {
  console.error(m);
  failed = true;
};

// ── 1. trust roots ────────────────────────────────────────────────────────────
const missing: { id: string; controller: string; sourcedFrom: string }[] = [];
const bad: { id: string; value: string }[] = [];
const rootTally: Record<string, number> = {};
let vars = 0;
for (const g of model.processModels ?? []) {
  for (const v of g.variables ?? []) {
    vars++;
    const tr = v.trustRoot;
    if (!tr) {
      missing.push({ id: v.id, controller: g.controller ?? "?", sourcedFrom: String(v.sourcedFrom ?? "").slice(0, 70) });
      continue;
    }
    if (!ROOTS.has(tr)) bad.push({ id: v.id, value: String(tr) });
    else rootTally[tr] = (rootTally[tr] ?? 0) + 1;
  }
}

console.log(`evidence gate — ${dir}\n`);
console.log(`  process-model variables:  ${vars}`);
console.log(`  trust roots declared:     ${vars - missing.length}`);
if (Object.keys(rootTally).length)
  console.log(`  distribution:             ${Object.entries(rootTally).map(([k, n]) => `${n} ${k}`).join(" · ")}`);

if (missing.length) {
  fail(
    `\n!! ${missing.length} process-model variable(s) do not name a trust root:\n` +
      missing.map((m) => `   ${m.id}  [${m.controller}]\n     sourcedFrom: "${m.sourcedFrom}..."`).join("\n") +
      [
        "",
        "",
        "  Add `trustRoot` to each: " + [...ROOTS].join(" | "),
        "",
        '  "the session" / "the token" / "config" are HOPS, not roots. Expand the chain:',
        "  a token bottoms out in whatever verifies it and whichever key does so — if the",
        "  adversary can obtain that key, the root is `attacker-input`, and every gate built",
        "  on that belief is a placebo. That is exactly how a credited belief hid six",
        "  worthless remediations in a real run.",
        "",
        "  `unverified` is a legitimate answer and forces the dependent band to be provisional.",
        "",
      ].join("\n"),
  );
}
if (bad.length)
  fail(
    `!! ${bad.length} variable(s) name an unrecognised trust root:\n` +
      bad.map((b) => `   ${b.id}: ${JSON.stringify(b.value)}`).join("\n") +
      `\n\n  Allowed: ${[...ROOTS].join(" | ")}\n`,
  );

// ── 2. derived numbers ────────────────────────────────────────────────────────
const cells = grid.cells ?? [];
const canon: Record<string, number> = {
  findings: cells.filter((c: any) => c.state === "uca").length,
  tombstones: cells.filter((c: any) => c.state === "tombstone").length,
  cells: cells.length,
  "control actions": (model.controlActions ?? []).length,
};
// Deliberately NOT checking "open": the word collides with port ranges ("80/443 open
// to 0.0.0.0/0") and produced a false positive on the first run of this gate. A gate
// that cries wolf is a gate that gets bypassed with --warn-only, so the bar for
// including a noun is that it cannot plausibly appear next to an unrelated number.
if (plan?.clusters) canon["root causes"] = plan.clusters.length;

// "<n> findings", "<n> tombstones", "<n> control actions", "<n> root causes", ...
const NOUNS = Object.keys(canon).sort((a, b) => b.length - a.length);
const mismatches: { file: string; noun: string; wrote: number; actual: number; line: number }[] = [];
// Only HAND-AUTHORED documents. 03-ucas.md, 06-remediation.md and 07-chains*.md are
// rendered by the tools from the same artifacts this gate computes from, so checking
// them would flag the tools against themselves.
// Also excluded: 08-final-audit.md and any *-audit.md — an independent reviewer's own
// document, describing the state as they found it. Rewriting someone else's audit to
// match the artifacts you changed afterwards would falsify their record.
const GENERATED = /^(03-ucas|06-remediation|07-chains)|-audit\.md$/;
const mdFiles = readdirSync(dir).filter((f) => /^0\d.*\.md$/.test(f) && !GENERATED.test(f));
for (const f of mdFiles) {
  const p = join(dir, f);
  let text = readFileSync(p, "utf8");
  let changed = false;
  const lines = text.split("\n");
  lines.forEach((ln, i) => {
    for (const noun of NOUNS) {
      const re = new RegExp(`\\b(\\d{1,4})\\s+(?:reasoned\\s+|bound\\s+)?${noun}\\b`, "gi");
      for (const m of [...ln.matchAll(re)]) {
        const wrote = Number(m[1]);
        if (wrote === canon[noun]) continue;
        // A QUALIFIED count is not a claim about the total: "closes 12 findings",
        // "22 findings were refuted", "40 of 96 findings". Only unqualified totals
        // are checkable, so look back a short way for a partial-count cue.
        const before = ln.slice(Math.max(0, (m.index ?? 0) - 28), m.index ?? 0);
        if (/\b(closes?|of|out of|were|was|refuted|downgraded|confirmed|provisional|among|remaining|only|first|top|another)\s*$/i.test(before)) continue;
        // "N of M findings" — the number is a subset, not the total.
        const after = ln.slice((m.index ?? 0) + m[0].length, (m.index ?? 0) + m[0].length + 12);
        if (/^\s*(?:of|\/)\s*\d/.test(after)) continue;
        // Trailing cue: "22 findings were refuted" is a historical statement, not a total.
        if (/^\s*(?:were|was|remain|had been|have been)\b/i.test(after)) continue;
        mismatches.push({ file: f, noun, wrote, actual: canon[noun], line: i + 1 });
        if (fixNumbers) {
          lines[i] = lines[i].replace(m[0], m[0].replace(String(wrote), String(canon[noun])));
          changed = true;
        }
      }
    }
  });
  if (changed) writeFileSync(p, lines.join("\n"));
}

console.log(`  derived numbers checked:  ${mdFiles.length} markdown file(s) against ${NOUNS.length} computed values`);
if (mismatches.length) {
  const verb = fixNumbers ? "CORRECTED" : "WRONG";
  const msg =
    `\n!! ${mismatches.length} hand-written number(s) ${verb} in prose:\n` +
    mismatches.map((m) => `   ${m.file}:${m.line}  "${m.wrote} ${m.noun}"  ->  computed: ${m.actual}`).join("\n") +
    (fixNumbers
      ? "\n\n  Rewritten in place. Prefer not writing these by hand at all.\n"
      : [
          "",
          "",
          "  Re-run with --fix-numbers, or delete the number from the prose entirely.",
          "  A count a reader can check and find wrong discredits every number beside it,",
          "  and these drift silently the moment a correction pass touches the grid.",
          "",
        ].join("\n"));
  if (fixNumbers) console.log(msg);
  else fail(msg);
}

writeFileSync(
  join(dir, "evidence-gate.json"),
  JSON.stringify(
    {
      computedAt: null,
      processModelVariables: vars,
      trustRootsDeclared: vars - missing.length,
      trustRootDistribution: rootTally,
      unresolvedTrustRoots: missing.map((m) => m.id),
      canonicalCounts: canon,
      proseMismatches: mismatches,
      passed: !failed,
    },
    null,
    2,
  ),
);

if (failed) {
  console.error(warnOnly ? "\n(--warn-only: not failing.)" : "\nEVIDENCE GATE FAILED.");
  process.exit(warnOnly ? 0 : 9);
}
console.log("\nevidence gate clean — every belief names a trust root, every prose count matches the artifacts.");
