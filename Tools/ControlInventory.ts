#!/usr/bin/env bun
/**
 * ControlInventory.ts — the scan already found the control you say is missing.
 *
 * WHY THIS EXISTS. `ControlStructureScan.ts` emits a `guards` category: every place
 * the codebase appears to make an authority decision. In a real full-surface run it
 * produced **2,508 guard candidates and the analysis consumed none of them.** The
 * author then wrote four findings asserting that a control was ABSENT, and all four
 * were false — an image-signature verifier, a session idle timeout, an auth
 * middleware, and a config default that inverted the meaning of "not passed". One
 * was rated band-1 R0 and recorded as CONFIRMED before an independent reviewer
 * refuted it by opening the file.
 *
 * For at least two of those four, the scan had already flagged a guard candidate in
 * the very file the finding called unguarded — including `WWW-Authenticate` INSIDE
 * the middleware that was declared not to exist. The evidence was on disk the whole
 * time. Nothing looked at it.
 *
 * So this gate does the one comparison nobody was doing: for every finding whose
 * statement asserts an absence, it checks whether the scan found a guard candidate
 * in the files that finding points at, and fails when it did and the finding does
 * not account for it. That is a COLLISION check, not an acking chore — there is
 * nothing to fill in by hand, because a gate that costs busywork is a gate that gets
 * bypassed.
 *
 * It cannot prove an absence (nothing can, mechanically). It can prove you did not
 * look, which is the actual failure mode.
 *
 * Usage:
 *   bun ControlInventory.ts <analysis-dir> [--warn-only]
 *
 * Reads  candidates.json (from `stpa scan --json`), grid.json, remediation.json
 * Writes control-inventory.json
 * Exit:  0 pass · 2 bad input · 8 an absence claim collides with a found guard
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) {
  console.log(
    [
      "ControlInventory.ts — cross-check absence claims against the guards the scan found",
      "",
      "Usage: bun ControlInventory.ts <analysis-dir> [--warn-only]",
      "",
      "Requires candidates.json in the analysis dir:",
      "  stpa scan <repo> --depth deep --json > <dir>/candidates.json",
      "",
      "Exit 8 = a finding asserts a control is absent in a file where the scan found one.",
    ].join("\n"),
  );
  process.exit(2);
}
const warnOnly = argv.includes("--warn-only");
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

const gridForSources = readJson("grid.json", false) ?? readJson("model.json", false) ?? {};
const CODE_SOURCED = ((gridForSources?.scope?.sources ?? []) as any[]).some((s: any) =>
  /codebase|repo/i.test(String(s?.type ?? "")),
);

const cands = readJson("candidates.json", false);
// A Modality-B analysis works from a design document: there is no code scan, so there is
// nothing to collide with and nothing to skip past. Passing here is correct rather than
// lenient. The gate still HARD-FAILS a codebase analysis with no scan, because that is
// the case where every absence claim is unfalsifiable.
if (!cands && !CODE_SOURCED) {
  console.log(`control inventory — ${dir}\n`);
  console.log("  no codebase in scope.sources and no candidates.json — design-document");
  console.log("  analysis, so there are no guard candidates to cross-check. Skipped.");
  process.exit(0);
}
if (!cands) {
  console.error(
    [
      `no candidates.json in ${dir} — this gate has nothing to compare against.`,
      "",
      "  Run: stpa scan <repo> --depth deep --json > " + join(dir, "candidates.json"),
      "",
      "  Without it, every absence claim in the analysis is unfalsifiable, which is",
      "  exactly the state that shipped four false findings in a real run.",
    ].join("\n"),
  );
  process.exit(2);
}
const grid = readJson("grid.json");
const remed = readJson("remediation.json", false) ?? { findings: {} };

type Cand = { file: string; line: number; text: string; pattern?: string };
const guards: Cand[] = cands?.candidates?.guards ?? [];
const byFile = new Map<string, Cand[]>();
for (const g of guards) {
  if (!g?.file) continue;
  if (!byFile.has(g.file)) byFile.set(g.file, []);
  byFile.get(g.file)!.push(g);
}

// Language that asserts a control does not exist. Deliberately broad: a false
// positive here costs one line of evidence, a false negative costs a band-1 finding.
const ABSENCE =
  /\b(no|none|never|nothing|absent|without|unguarded|unbounded|lacks?|missing|fails? to|is not|does not|cannot)\b/i;
// Any path-looking token with a source extension.
const PATHISH = /[\w@./-]*[\w-]+\.(?:ts|tsx|js|jsx|mjs|cjs|py|rb|go|java|kt|cs|php|rs|tf|ya?ml)\b/gi;

interface Collision {
  finding: string;
  file: string;
  guards: Cand[];
}
const collisions: Collision[] = [];
const absenceFindings: string[] = [];

for (const c of grid.cells ?? []) {
  if (c.state !== "uca") continue;
  const stmt = String(c.statement ?? "");
  if (!ABSENCE.test(stmt)) continue;
  absenceFindings.push(c.id);

  const r: any = (remed.findings ?? {})[c.id] ?? {};
  const evidence = `${r.location ?? ""} ${r.absenceVerifiedBy ?? ""} ${r.reachabilityPath ?? ""}`;
  // Files the finding points at, from the statement and its recorded location.
  const referenced = new Set<string>();
  for (const m of `${stmt} ${r.location ?? ""}`.matchAll(PATHISH)) referenced.add(m[0]);

  for (const ref of referenced) {
    // match a scan file whose path ends with the referenced fragment
    for (const [file, hits] of byFile) {
      if (!file.endsWith(ref) && !file.includes(ref)) continue;
      if (/\.(test|spec|integration)\./.test(file)) continue;
      // If the evidence cites a LINE in this file, the author looked. Match on the
      // basename as well as the full path: citing `oauth-server.ts:50` proves the read
      // just as well as citing `src/utils/auth/oauth-server.ts:50`, and demanding the
      // long form only teaches people to paste paths they did not open.
      const base = (ref.split("/").pop() ?? ref).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const citesThisFile = new RegExp(`${base}:\\d+`).test(evidence + " " + stmt);
      if (citesThisFile) continue;
      collisions.push({ finding: c.id, file, guards: hits.slice(0, 4) });
    }
  }
}

const filesWithGuards = byFile.size;
const inventory = {
  computedAt: null as string | null,
  guardCandidates: guards.length,
  filesWithGuards,
  absenceAssertingFindings: absenceFindings.length,
  collisions: collisions.map((c) => ({
    finding: c.finding,
    file: c.file,
    guardLines: c.guards.map((g) => g.line),
  })),
  passed: collisions.length === 0,
};
writeFileSync(join(dir, "control-inventory.json"), JSON.stringify(inventory, null, 2));

console.log(`control inventory — ${dir}\n`);
console.log(`  guard candidates found by the scan:  ${guards.length}`);
console.log(`  files containing a guard candidate:  ${filesWithGuards}`);
console.log(`  findings that assert an absence:     ${absenceFindings.length}`);
console.log(`  collisions:                          ${collisions.length}`);
console.log("");

if (!collisions.length) {
  console.log(
    guards.length === 0
      ? "no guard candidates in the scan — nothing to collide with (check the scan ran at --depth deep)"
      : "no absence claim points at a file where the scan found an unaccounted-for guard.",
  );
  process.exit(0);
}

console.error(`!! ${collisions.length} ABSENCE CLAIM(S) COLLIDE WITH A GUARD THE SCAN FOUND:\n`);
for (const c of collisions) {
  console.error(`   ${c.finding}`);
  console.error(`     claims a control is absent, but the scan flagged a guard in:`);
  console.error(`       ${c.file}:${c.guards.map((g) => g.line).join(",")}`);
  for (const g of c.guards) console.error(`         ${g.line}: ${g.text.trim().slice(0, 76)}`);
  console.error("");
}
console.error(
  [
    "  Open those lines. One of three things is true:",
    "",
    "    1. The guard IS the control you said was missing  -> the finding is FALSE. Withdraw it.",
    "    2. The guard is real but does not cover this path  -> keep the finding, and cite the",
    "       file:line you read, saying why it does not apply. The gate then passes.",
    "    3. The hit is noise (a test helper, an unrelated check) -> cite it and dismiss it.",
    "",
    "  All three require you to have READ the line. That is the whole point: this gate cannot",
    "  prove an absence, but it can prove you did not look — and not looking is what shipped",
    "  four false findings, one of them band-1 and recorded as CONFIRMED.",
    "",
  ].join("\n"),
);
process.exit(warnOnly ? 0 : 8);
