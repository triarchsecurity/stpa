#!/usr/bin/env bun
/**
 * MergePlanes.ts — the reconciliation gate for parallel analysis.
 *
 * WHY THIS EXISTS (a real failure, 2026-07-22).
 *
 * A full-scope run fanned out six agents, one per plane, each briefed to return
 * its findings as its final message. All six reported "idle / available". All six
 * returned nothing. The orchestrator had:
 *
 *   - a control action .......... "agent produces findings for its plane"
 *   - no feedback channel ....... "finished" and "produced nothing" look identical
 *   - no reconciliation gate .... merge would have proceeded on whatever arrived
 *
 * That is a textbook unsafe control structure, in the toolkit's own workflow. Had
 * the merge run unchecked, the grid would have been silently short by ~200 cells
 * and coverage would still have printed a healthy number, because coverage is
 * computed over cells PRESENT, not cells EXPECTED.
 *
 * Two fixes, both structural rather than advisory:
 *
 *   1. Delegates write FILES, not messages. A file exists or it does not.
 *      A message that never arrives is indistinguishable from one never sent.
 *   2. This tool refuses to merge until every expected plane and every expected
 *      cell is accounted for — present, or explicitly declared incomplete.
 *
 * An expected-vs-present check is the whole point. Never replace it with a count
 * of what showed up.
 *
 * Usage:
 *   bun MergePlanes.ts <analysis-dir> --expect <manifest.json>   # merge + gate
 *   bun MergePlanes.ts <analysis-dir> --expect <manifest.json> --check
 *
 * manifest.json — written BEFORE dispatch, from the control-action inventory:
 *   { "planes": { "auth": { "file": "planes/auth.json",
 *                           "controlActions": ["CA-A1","CA-A2"] } } }
 */

import { existsSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const UCA_TYPES = ["not-provided", "provided", "timing-order", "duration"] as const;

/**
 * Delegates label the four types with predictable variance — "timing",
 * "wrong-timing", "too-long", "stopped-too-soon". Left unhandled, a naming
 * difference reads as MISSING ANALYSIS, which is the opposite of the truth and
 * would send someone to re-run work that was already done correctly. Canonicalize
 * on the way in, and report what was renamed so the variance stays visible.
 */
const TYPE_ALIASES: Record<string, string> = {
  "not-provided": "not-provided", "notprovided": "not-provided", "not_provided": "not-provided",
  "omitted": "not-provided", "missing": "not-provided",
  provided: "provided", "provided-unsafe": "provided", unsafe: "provided",
  "timing-order": "timing-order", timing: "timing-order", "wrong-timing": "timing-order",
  "wrong-order": "timing-order", "timing-or-order": "timing-order", order: "timing-order",
  duration: "duration", "too-long": "duration", "too-long-too-short": "duration",
  "stopped-too-soon": "duration", "applied-too-long": "duration", "duration-stopped": "duration",
};

const renamed: { from: string; to: string }[] = [];

function canonicalizeCellId(id: string): string {
  const dot = id.lastIndexOf(".");
  if (dot === -1) return id;
  const base = id.slice(0, dot);
  const suffix = id.slice(dot + 1).toLowerCase();
  const canon = TYPE_ALIASES[suffix];
  if (!canon) return id;
  const out = `${base}.${canon}`;
  if (out !== id) renamed.push({ from: id, to: out });
  return out;
}

interface PlaneSpec {
  file: string;
  controlActions: string[];
}
interface Manifest {
  planes: Record<string, PlaneSpec>;
}

function die(m: string, c = 1): never {
  console.error(m);
  process.exit(c);
}

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h"))
  die(
    [
      "MergePlanes.ts — reconciliation gate for parallel STPA analysis",
      "",
      "Usage: bun MergePlanes.ts <analysis-dir> --expect <manifest.json> [--check]",
      "",
      "Refuses to merge until every expected plane file exists and every expected",
      "cell is present or explicitly declared incomplete. Exit 4 = gap detected.",
    ].join("\n"),
    2,
  );

const dir = resolve(argv.find((a) => !a.startsWith("-") && argv[argv.indexOf(a) - 1] !== "--expect") ?? ".stpa");
const eIdx = argv.indexOf("--expect");
if (eIdx === -1) die("--expect <manifest.json> is required. Without an expected set there is nothing to reconcile against, and a merge of whatever arrived is exactly the failure this tool exists to prevent.", 2);
const manifestPath = resolve(argv[eIdx + 1] ?? "");
const checkOnly = argv.includes("--check");

if (!existsSync(manifestPath)) die(`no manifest at ${manifestPath}`);
let manifest: Manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
} catch (e) {
  die(`manifest is not valid JSON: ${(e as Error).message}`);
}

const planeNames = Object.keys(manifest.planes ?? {});
if (!planeNames.length) die("manifest declares no planes");

// ── expected cell set ─────────────────────────────────────────────────────
const expected = new Set<string>();
const expectedByPlane = new Map<string, string[]>();
for (const [name, spec] of Object.entries(manifest.planes)) {
  const ids: string[] = [];
  for (const ca of spec.controlActions) for (const t of UCA_TYPES) ids.push(`${ca}.${t}`);
  ids.forEach((i) => expected.add(i));
  expectedByPlane.set(name, ids);
}

// ── what actually arrived ─────────────────────────────────────────────────
interface PlaneReport {
  name: string;
  fileFound: string | null;
  parsed: boolean;
  cells: any[];
  declaredIncomplete: string[];
  present: Set<string>;
  missing: string[];
  unexpected: string[];
  processModels: any[];
  feedback: any[];
  refuted: any[];
}

const reports: PlaneReport[] = [];
for (const [name, spec] of Object.entries(manifest.planes)) {
  const primary = join(dir, spec.file);
  // tolerate the prose escape hatch, but never count it as structured output
  const proseAlt = primary.replace(/\.json$/, ".md");
  let fileFound: string | null = null;
  let cells: any[] = [];
  let parsed = false;
  let declaredIncomplete: string[] = [];
  let processModels: any[] = [];
  let feedback: any[] = [];
  let refuted: any[] = [];

  if (existsSync(primary)) {
    fileFound = spec.file;
    try {
      const j = JSON.parse(readFileSync(primary, "utf8"));
      cells = (Array.isArray(j.cells) ? j.cells : []).map((c: any) => ({ ...c, id: canonicalizeCellId(c.id) }));
      declaredIncomplete = Array.isArray(j.incomplete) ? j.incomplete : [];
      processModels = j.processModels ?? [];
      feedback = j.feedback ?? [];
      refuted = j.refuted ?? [];
      parsed = true;
    } catch (e) {
      console.error(`  ${name}: file present but unparseable — ${(e as Error).message}`);
    }
  } else if (existsSync(proseAlt)) {
    fileFound = spec.file.replace(/\.json$/, ".md");
  }

  const present = new Set(cells.map((c: any) => c.id));
  const exp = expectedByPlane.get(name)!;
  reports.push({
    name,
    fileFound,
    parsed,
    cells,
    declaredIncomplete,
    present,
    missing: exp.filter((i) => !present.has(i)),
    unexpected: [...present].filter((i) => !expected.has(i)),
    processModels,
    feedback,
    refuted,
  });
}

// ── report ────────────────────────────────────────────────────────────────
console.log(`reconciliation against ${manifestPath}\n`);
console.log(`plane          file      parsed  cells  expected  missing  declared-incomplete`);
console.log(`─────────────────────────────────────────────────────────────────────────────`);
let hardGap = false;
for (const r of reports) {
  const exp = expectedByPlane.get(r.name)!.length;
  // A gap is "hard" when it was neither delivered nor declared. A declared gap is
  // a scoping decision; an undeclared one is a hole nobody chose.
  const undeclared = r.missing.filter((m) => !r.declaredIncomplete.some((d) => m.startsWith(d)));
  if (undeclared.length) hardGap = true;
  console.log(
    `${r.name.padEnd(14)} ${(r.fileFound ? "yes" : "MISSING").padEnd(9)} ${(r.parsed ? "yes" : "no").padEnd(7)} ${String(r.cells.length).padEnd(6)} ${String(exp).padEnd(9)} ${String(undeclared.length).padEnd(8)} ${r.declaredIncomplete.length}`,
  );
}

const allCells = reports.flatMap((r) => r.cells);
const totalUndeclared = reports.reduce(
  (a, r) => a + r.missing.filter((m) => !r.declaredIncomplete.some((d) => m.startsWith(d))).length,
  0,
);

if (renamed.length) {
  console.log(`\ncanonicalized ${renamed.length} cell id(s) from known type aliases:`);
  const byPair = new Map<string, number>();
  for (const r of renamed) {
    const k = `${r.from.slice(r.from.lastIndexOf(".") + 1)} -> ${r.to.slice(r.to.lastIndexOf(".") + 1)}`;
    byPair.set(k, (byPair.get(k) ?? 0) + 1);
  }
  for (const [k, n] of byPair) console.log(`  ${k}  (${n})`);
  console.log(`  A label difference is not a missing analysis — canonicalized rather than reported as a gap.`);
}

console.log(`\ntotal cells delivered: ${allCells.length} of ${expected.size} expected`);
console.log(`planes delivered:      ${reports.filter((r) => r.parsed).length} of ${reports.length}`);
if (totalUndeclared) console.log(`UNDECLARED GAPS:       ${totalUndeclared} cells nobody chose to skip`);

const emptyPlanes = reports.filter((r) => !r.fileFound);
if (emptyPlanes.length) {
  console.log(`\n!! ${emptyPlanes.length} PLANE(S) PRODUCED NO OUTPUT AT ALL: ${emptyPlanes.map((r) => r.name).join(", ")}`);
  console.log(`   A delegate that finishes and delivers nothing is indistinguishable from one`);
  console.log(`   that completed successfully, unless you check. You just checked.`);
  console.log(`   Do NOT merge and report a coverage number over the planes that did return —`);
  console.log(`   that number would describe a fraction of the system while looking complete.`);
  console.log(`   Either re-run the missing planes, or record them as deferred in model.json`);
  console.log(`   scope.deferred so surface coverage falls to match reality.`);
}

if (checkOnly) process.exit(hardGap || emptyPlanes.length ? 4 : 0);

if (hardGap || emptyPlanes.length) {
  console.error(`\nrefusing to merge: ${totalUndeclared} undeclared cell gap(s), ${emptyPlanes.length} empty plane(s).`);
  console.error(`Re-run the missing planes, or declare the gaps explicitly, then merge.`);
  process.exit(4);
}

// ── merge ─────────────────────────────────────────────────────────────────
const merged = {
  mergedAt: null as string | null,
  planes: reports.map((r) => ({
    name: r.name,
    cells: r.cells.length,
    expected: expectedByPlane.get(r.name)!.length,
    declaredIncomplete: r.declaredIncomplete,
  })),
  processModels: reports.flatMap((r) => r.processModels),
  feedback: reports.flatMap((r) => r.feedback),
  cells: allCells,
  refuted: reports.flatMap((r) => r.refuted),
};
writeFileSync(join(dir, "planes-merged.json"), JSON.stringify(merged, null, 2));
console.log(`\nmerged → ${join(dir, "planes-merged.json")}`);
console.log(`Next: fold these into model.json + grid.json, then \`stpa status\`.`);
