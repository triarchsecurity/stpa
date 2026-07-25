/**
 * StrideGate.ts — hold the analysis to the METHOD contract recorded at intake.
 *
 * Why this exists, specifically.
 *
 * The intake asks which analysis to run and writes the answer into model.json as
 * `scope.methods`. Until this gate existed, NOTHING read that field — not
 * ScopeGate, not VerifyGate, not DiscoveryGate, not the renderer. A run could
 * record "STPA + STRIDE", deliver STPA only, and every gate would pass green.
 *
 * That happened. A full-surface run recorded STPA + STRIDE, never executed the
 * STRIDE pass, and instead grew a hand-written nine-row table at the end of
 * 05-constraints.md which the scope prose then described as "a STRIDE
 * per-element sweep was run". Nothing caught it because nothing was looking.
 * The requester found it by reading the report and asking where STRIDE was.
 *
 * This is the same failure the toolkit already learned once with Step 4: the
 * workflow said to do it, the workflow was not enough, and it only stopped
 * being skipped when RenderReport started exiting 5 without 04-scenarios.md.
 * A method selection that no gate checks is an unenforced promise — which is,
 * with some irony, exactly the defect class STPA exists to find: a control
 * action with no feedback channel.
 *
 * What it checks:
 *   1. CONTRACT    — `scope.methods` is recorded at all. Absent means nothing
 *                    can verify what was delivered, so the gate fails rather
 *                    than assuming STPA-only. Exit 8.
 *   2. DELIVERY    — if STRIDE was selected, 00-stride-seed.md exists and
 *                    carries the five sections SeedWithStride.md specifies.
 *   3. RECONCILE   — the two-way cross-check is present in BOTH directions.
 *                    STRIDE→STPA alone is the half people write; STPA→STRIDE is
 *                    the half that justifies having run STPA, and it is the half
 *                    that gets dropped.
 *   4. PROVENANCE  — how the pass was produced is declared. A hand-run pass is
 *                    legitimate (SeedWithStride sanctions it for code targets)
 *                    but it must not silently read as a Fabric-pattern run.
 *   5. NO UPGRADE  — if STRIDE-only was selected, a populated UCA grid means the
 *                    run quietly upgraded itself to STPA. Start.md forbids that.
 *
 * Writes stride-scorecard.json for the renderer regardless of pass/fail, so the
 * report states method coverage from computed data rather than from narration.
 *
 * Usage:
 *   bun StrideGate.ts <analysis-dir> [--warn-only]
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

function die(m: string, c = 1): never {
  console.error(m);
  process.exit(c);
}

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h"))
  die(
    [
      "StrideGate.ts — hold the analysis to the method contract recorded at intake",
      "",
      "Usage: bun StrideGate.ts <analysis-dir> [--warn-only]",
      "",
      "  --warn-only     report without failing (exit 0 regardless)",
      "",
      "model.json must carry scope.methods — either an array or a string:",
      '  "methods": ["stpa", "stride"]        preferred',
      '  "methods": "STPA + STRIDE"           tolerated (parsed case-insensitively)',
      "",
      "When STRIDE is selected, 00-stride-seed.md must exist and carry:",
      "  ASSETS · TRUST BOUNDARIES · DATA FLOWS · THREAT MODEL · QUESTIONS",
      "  plus a two-way reconciliation (STRIDE -> STPA and STPA -> STRIDE)",
      "",
      "Declare how the pass was produced via scope.strideProvenance, e.g.",
      '  "fabric:create_stride_threat_model"   the specified pattern',
      '  "hand-run-over-control-structure"     sanctioned for code-only targets',
      "",
      "Exit 8 = the delivered methods do not honour the methods requested.",
    ].join("\n"),
    2,
  );

const dir = resolve(argv.find((a) => !a.startsWith("-")) ?? ".stpa");
const warnOnly = argv.includes("--warn-only");

const modelPath = join(dir, "model.json");
if (!existsSync(modelPath)) die(`no model.json in ${dir}`);
const model = JSON.parse(readFileSync(modelPath, "utf8"));
const scope = model.scope ?? {};

const read = (f: string) => (existsSync(join(dir, f)) ? readFileSync(join(dir, f), "utf8") : null);

let failed = false;
const fail = (m: string) => {
  console.error(m);
  failed = true;
};

// ── parse the method contract ─────────────────────────────────────────────
// Tolerate both the structured array and the prose string an earlier intake
// wrote, because a gate that only accepts the new shape fails every analysis
// already on disk and teaches people to pass --warn-only.
const rawMethods: unknown = scope.methods;
const methodText = Array.isArray(rawMethods) ? rawMethods.join(" ") : typeof rawMethods === "string" ? rawMethods : "";
const recorded = methodText.trim().length > 0;
const wantsStride = /stride/i.test(methodText);
const wantsStpa = /stpa|stamp/i.test(methodText);

const seed = read("00-stride-seed.md");
const gridRaw = read("grid.json");
const gridCells: number = (() => {
  if (!gridRaw) return 0;
  try {
    return (JSON.parse(gridRaw).cells ?? []).filter((c: any) => c.state && c.state !== "open").length;
  } catch {
    return 0;
  }
})();

const provenance: string | null = typeof scope.strideProvenance === "string" ? scope.strideProvenance : null;

console.log(`method contract — ${dir}\n`);
console.log(`  methods requested:  ${recorded ? methodText : "NOT RECORDED"}`);
console.log(`  STPA:               ${wantsStpa ? "requested" : "not requested"}`);
console.log(`  STRIDE:             ${wantsStride ? "requested" : "not requested"}`);
console.log(`  00-stride-seed.md:  ${seed ? `present (${seed.split("\n").length} lines)` : "ABSENT"}`);
console.log(`  provenance:         ${provenance ?? "NOT DECLARED"}`);
console.log("");

// ── 1. contract recorded at all ───────────────────────────────────────────
if (!recorded) {
  fail(
    [
      "NO METHOD CONTRACT RECORDED.",
      "",
      "  model.json has no scope.methods, so nothing can check the methods",
      "  delivered against the methods the requester chose. This gate will not",
      "  assume STPA-only on your behalf — that assumption is how a STRIDE",
      "  selection goes missing without anyone noticing.",
      "",
      '  Add: "methods": ["stpa", "stride"]   (or ["stpa"], or ["stride"])',
      "",
    ].join("\n"),
  );
}

// ── 2/3/4. STRIDE was requested — was it actually delivered? ──────────────
const REQUIRED_SECTIONS = ["ASSETS", "TRUST BOUNDARIES", "DATA FLOWS", "THREAT MODEL", "QUESTIONS"];
let missingSections: string[] = [];
let threatCount = 0;
let mapped = 0;
let novel = 0;
let outOfScope = 0;
let bareRows: string[] = [];
let bothDirections = false;

if (wantsStride) {
  if (!seed) {
    fail(
      [
        "STRIDE WAS REQUESTED AND NOT DELIVERED.",
        "",
        "  scope.methods names STRIDE, but there is no 00-stride-seed.md in this",
        "  analysis. A STRIDE table folded into another document does not count:",
        "  the artifact is what the renderer shows and what the next cycle diffs",
        "  against, and prose in 01-scope.md claiming a sweep was run is exactly",
        "  what this gate exists to stop.",
        "",
        "  Run Workflows/SeedWithStride.md and write 00-stride-seed.md.",
        "",
      ].join("\n"),
    );
  } else {
    const up = seed.toUpperCase();
    missingSections = REQUIRED_SECTIONS.filter((s) => !up.includes(s));
    if (missingSections.length)
      fail(
        [
          `STRIDE SEED IS INCOMPLETE — missing ${missingSections.length} of 5 required sections:`,
          ...missingSections.map((s) => `    - ${s}`),
          "",
          "  SeedWithStride.md step 1 defines these five. Each seeds a specific STPA",
          "  element; TRUST BOUNDARIES is the highest-value one, because it is the",
          "  layer whose absence over-rates internal paths as external.",
          "",
        ].join("\n"),
      );

    // Threat rows look like `| ST-1 | element | letter | threat | status |`.
    // The id must be its OWN cell (`| ST-1 |`). The reconciliation table later in the
    // document opens rows with an id followed by prose in the same cell
    // (`| ST-1 plaintext :80 forward |`); matching those too counted them as
    // dispositionless threat rows and reported four false positives.
    const rows = seed.split("\n").filter((l) => /^\s*\|\s*ST-\d+\s*\|/i.test(l));
    threatCount = rows.length;
    // Count rows that carry NO disposition, rather than comparing sums — a row can
    // legitimately be both NEW and reference a CA it compounds, and summing the
    // three buckets double-counts it, which lets a genuinely bare row hide inside
    // an arithmetic that looks balanced. Ask the question directly instead.
    const disposed = (l: string) => /CA-\d+/.test(l) || /\bNEW\b/.test(l) || /\bOUT\b/.test(l);
    mapped = rows.filter((l) => /CA-\d+/.test(l)).length;
    novel = rows.filter((l) => /\bNEW\b/.test(l)).length;
    outOfScope = rows.filter((l) => /\bOUT\b/.test(l)).length;
    bareRows = rows.filter((l) => !disposed(l)).map((l) => (l.match(/ST-\d+/i)?.[0] ?? "ST-?").toUpperCase());

    if (threatCount === 0)
      fail(
        [
          "STRIDE SEED HAS NO THREAT ROWS.",
          "",
          "  Expected a THREAT MODEL table with rows identified ST-1, ST-2, ...",
          "  Without per-threat ids there is nothing to reconcile against the grid.",
          "",
        ].join("\n"),
      );

    const s2p = /STRIDE\s*(?:→|->|to)\s*STPA/i.test(seed);
    const p2s = /STPA\s*(?:→|->|to)\s*STRIDE/i.test(seed);
    bothDirections = s2p && p2s;
    if (!bothDirections)
      fail(
        [
          "RECONCILIATION IS ONE-DIRECTIONAL.",
          `    STRIDE -> STPA: ${s2p ? "present" : "MISSING"}`,
          `    STPA -> STRIDE: ${p2s ? "present" : "MISSING"}`,
          "",
          "  Both halves are required and they answer different questions.",
          "  STRIDE->STPA asks whether every threat landed somewhere (or is recorded",
          "  out of scope with a reason). STPA->STRIDE names the emergent findings",
          "  STRIDE could not have produced — the composition, bypass and duration",
          "  classes. That second half is the return on having run STPA at all, and",
          "  it is the half that gets dropped.",
          "",
        ].join("\n"),
      );

    if (bareRows.length)
      fail(
        [
          `${bareRows.length} THREAT ROW(S) ARE UNACCOUNTED FOR: ${bareRows.join(", ")}`,
          "",
          "  Every ST-* row must either map to a control action (cite CA-n), be",
          "  marked NEW (STRIDE found what STPA did not), or be marked OUT with a",
          "  reason. An unmapped high-impact threat is a gap in the control",
          "  structure — go back to Step 2 rather than leaving the row bare.",
          "",
        ].join("\n"),
      );

    if (!provenance)
      fail(
        [
          "STRIDE PROVENANCE NOT DECLARED.",
          "",
          "  Record how the pass was produced in scope.strideProvenance. A hand-run",
          "  per-element sweep over the control structure is legitimate — it is what",
          "  SeedWithStride.md sanctions for a code-only target — but it must not",
          "  read as though the Fabric create_stride_threat_model pattern produced",
          "  it. Same reason VerifyGate records which model reviewed the findings:",
          "  the provenance of a claim is part of the claim.",
          "",
          '    "strideProvenance": "fabric:create_stride_threat_model"',
          '    "strideProvenance": "hand-run-over-control-structure"',
          "",
        ].join("\n"),
      );
  }
} else if (seed) {
  console.log("  note: 00-stride-seed.md exists but STRIDE is not in scope.methods.");
  console.log("        Not a failure — but record it in methods so the report claims it.\n");
}

// ── 5. STRIDE-only must not silently become STPA ──────────────────────────
if (wantsStride && !wantsStpa && gridCells > 0) {
  fail(
    [
      `STRIDE-ONLY WAS REQUESTED, BUT A POPULATED STPA GRID EXISTS (${gridCells} resolved cells).`,
      "",
      "  Start.md is explicit: never silently upgrade STRIDE-only to STPA. If the",
      "  requester needs STPA, ask and record the change in scope.methods. Deliver",
      "  what was chosen, and state in one line what the choice does not cover.",
      "",
    ].join("\n"),
  );
}

// ── scorecard: computed, never narrated ───────────────────────────────────
const scorecard = {
  computedAt: null as string | null,
  methodsRecorded: recorded,
  methods: recorded ? methodText : null,
  stpaRequested: wantsStpa,
  strideRequested: wantsStride,
  strideDelivered: wantsStride ? !!seed : null,
  strideProvenance: provenance,
  requiredSections: REQUIRED_SECTIONS.length,
  missingSections,
  threats: threatCount,
  mappedToUca: mapped,
  strideOnlyFindings: novel,
  outOfScope,
  unaccountedRows: bareRows,
  reconciledBothDirections: bothDirections,
  passed: !failed,
};
writeFileSync(join(dir, "stride-scorecard.json"), JSON.stringify(scorecard, null, 2));

if (wantsStride && seed && !failed) {
  console.log(
    `method contract honoured — STRIDE delivered: ${threatCount} threats · ${mapped} mapped to UCAs · ` +
      `${novel} STRIDE-only · ${outOfScope} out of scope · reconciled both directions.`,
  );
} else if (!wantsStride && recorded) {
  console.log("method contract honoured — STRIDE was not requested, nothing to deliver.");
}

if (failed) {
  console.error(
    warnOnly
      ? "\n(--warn-only: not failing, but the method contract was not honoured.)"
      : "\nMETHOD CONTRACT NOT HONOURED. Fix the above or re-run with --warn-only.",
  );
  process.exit(warnOnly ? 0 : 8);
}
