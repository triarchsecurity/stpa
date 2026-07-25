#!/usr/bin/env bun
/**
 * UcaGrid.ts — the stopping rule for STPA Step 3.
 *
 * STPA has no native stopping rule: you stop when you feel done, which means
 * you stop when you get tired. This tool replaces that with arithmetic. Every
 * control action must be considered against all four UCA types, so the analysis
 * is a grid of exactly 4 x |control actions| cells. Coverage is the ratio of
 * resolved cells (a finding OR an explicit tombstone with a reason) to total
 * cells. An unresolved cell is a hole in the analysis, and now you can count them.
 *
 * Usage:
 *   bun UcaGrid.ts init    <model.json> [-o grid.json]   # generate the empty grid
 *   bun UcaGrid.ts init    <model.json> --merge <old-grid.json> -o grid.json
 *                                                        # re-analysis: carry resolved
 *                                                        # cells forward, list only new ones
 *   bun UcaGrid.ts status  <grid.json>                   # coverage report
 *   bun UcaGrid.ts markdown <grid.json> [-o grid.md]     # analyst-facing checklist
 *
 * Input model.json shape (produced by ModelControlStructure workflow):
 *   {
 *     "system": "name",
 *     "controlActions": [
 *       { "id": "CA-1", "action": "grant access to tenant record",
 *         "controller": "API gateway", "process": "tenant-data service",
 *         "hazards": ["H-1","H-3"] }
 *     ]
 *   }
 *
 * Cell states: "open" (unresolved) | "uca" (finding recorded) | "tombstone" (reasoned skip)
 * A tombstone without a reason string is rejected — that is the whole point.
 *
 * THE BINDING RULE (the anti-checklist guard).
 *
 * Arithmetic alone would make this tool the instrument of the regression it exists
 * to prevent. If any string counts as a resolved cell, the fastest path to 100%
 * coverage is to paste a generic vulnerability-class phrase into all 4N cells —
 * which is (component x threat-type) enumeration wearing STPA vocabulary, now
 * certified complete by a coverage number. Countability would quantify theatre
 * instead of beating it.
 *
 * So: a finding counts toward coverage ONLY if its `bindsTo` references at least
 * one element ID declared in THIS system's control structure — a process-model
 * variable (PM-*) or a feedback channel (F-*). A finding that binds to nothing is
 * `unbound`: it is printed, but it does not count. Generic table-lookup findings
 * cannot bind, so they cannot manufacture coverage, so you cannot reach 100%
 * without having actually modeled the control structure.
 *
 * This also forces the analyst-confirmation step to happen: `init` refuses a model
 * with no declared process-model variables, and raw ControlStructureScan.ts output
 * has none.
 *
 * Coverage = (bound findings + reasoned tombstones) / total cells.
 */

const UCA_TYPES = [
  { key: "not-provided", label: "Not providing causes hazard" },
  { key: "provided", label: "Providing causes hazard" },
  { key: "timing-order", label: "Wrong timing or order (too early / too late / out of order)" },
  { key: "duration", label: "Applied too long or stopped too soon" },
] as const;

type UcaTypeKey = (typeof UCA_TYPES)[number]["key"];

interface ControlAction {
  id: string;
  action: string;
  controller: string;
  process?: string;
  hazards?: string[];
}

interface ProcessModelVariable {
  id: string;
  belief: string;
  sourcedFrom?: string;
  staleness?: string;
}

interface ProcessModel {
  controller: string;
  variables: ProcessModelVariable[];
}

interface Cell {
  id: string;
  controlActionId: string;
  controlAction: string;
  controller: string;
  ucaType: UcaTypeKey;
  ucaTypeLabel: string;
  state: "open" | "uca" | "tombstone";
  /** Five-part UCA sentence when state === "uca". */
  statement?: string;
  /** Hazard IDs this UCA links to. */
  linksTo?: string[];
  /**
   * Control-structure element IDs (PM-* / F-*) this finding is grounded in.
   * Required for a finding to count toward coverage — see THE BINDING RULE.
   */
  bindsTo?: string[];
  /** Required when state === "tombstone". */
  reason?: string;
}

/**
 * What was modeled versus what exists. Grid coverage answers "did we finish the
 * analysis we scoped"; scope answers "how much of the system did we scope". They
 * are different numbers and conflating them is how a 100% turns into a false
 * assurance — so this one travels with the grid and is printed next to it.
 */
interface Scope {
  candidateControlActions?: number;
  selectionCriteria?: string;
  deferred?: { name: string; reason: string }[];
}

interface Grid {
  system: string;
  generated: string;
  totalCells: number;
  scope?: Scope;
  /** Element IDs declared by the control structure; the only valid bindsTo targets. */
  declaredElements: string[];
  cells: Cell[];
}

function die(msg: string, code = 1): never {
  console.error(msg);
  process.exit(code);
}

/** Write through die() rather than letting a bad path dump a raw stack trace. */
function writeOut(path: string, content: string, note: string): void {
  try {
    require("node:fs").writeFileSync(path, content);
  } catch (e) {
    die(`cannot write ${path}: ${(e as Error).message}`);
  }
  console.error(note);
}

function usage(): never {
  die(
    [
      "UcaGrid.ts — STPA Step 3 coverage grid",
      "",
      "Usage:",
      "  bun UcaGrid.ts init     <model.json>  [--merge <old-grid.json>] [-o <grid.json>]",
      "  bun UcaGrid.ts status   <grid.json>",
      "  bun UcaGrid.ts markdown <grid.json>   [-o <grid.md>]",
      "",
      "Cell states: open | uca | tombstone (tombstone requires a `reason`).",
      "Coverage = (BOUND findings + reasoned tombstones) / totalCells.",
      "A finding is bound only if `bindsTo` names a declared PM-*/F-* element.",
    ].join("\n"),
    2,
  );
}

function readJson(path: string): unknown {
  let text: string;
  try {
    text = require("node:fs").readFileSync(path, "utf8");
  } catch {
    die(`cannot read: ${path}`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    die(`not valid JSON: ${path} — ${(e as Error).message}`);
  }
}

function collectDeclaredElements(model: {
  processModels?: ProcessModel[];
  feedback?: { id?: string }[];
}): string[] {
  const ids: string[] = [];
  for (const pm of model.processModels ?? []) {
    for (const v of pm.variables ?? []) {
      if (v.id) ids.push(v.id);
    }
  }
  for (const f of model.feedback ?? []) {
    if (f.id) ids.push(f.id);
  }
  return [...new Set(ids)];
}

function buildGrid(model: {
  system?: string;
  scope?: Scope;
  controlActions?: ControlAction[];
  processModels?: ProcessModel[];
  feedback?: { id?: string }[];
}): Grid {
  const actions = model.controlActions ?? [];
  if (!Array.isArray(actions) || actions.length === 0) {
    die("model has no `controlActions` — model the control structure first (Step 2).");
  }
  const declared = collectDeclaredElements(model);
  if (declared.length === 0) {
    die(
      [
        "model declares no process-model variables or feedback channels.",
        "",
        "This is the analyst-confirmation gate, not a formatting complaint. Raw",
        "ControlStructureScan.ts output has no process models — it cannot, because",
        "pattern matching cannot tell you what a controller believes. Findings must",
        "bind to declared control-structure elements to count toward coverage, so a",
        "model with none can only ever score 0%.",
        "",
        "Add to model.json, per controller:",
        '  "processModels": [{ "controller": "C-1", "variables": [',
        '      { "id": "PM-1", "belief": "caller tenant", "sourcedFrom": "request header",',
        '        "staleness": "wrong at source, permanently" } ] }]',
        '  "feedback": [{ "id": "F-1", "from": "P-1", "to": "C-1", "signal": "audit event" }]',
      ].join("\n"),
    );
  }
  const cells: Cell[] = [];
  for (const ca of actions) {
    if (!ca.id || !ca.action || !ca.controller) {
      die(`control action missing id/action/controller: ${JSON.stringify(ca)}`);
    }
    for (const t of UCA_TYPES) {
      cells.push({
        id: `${ca.id}.${t.key}`,
        controlActionId: ca.id,
        controlAction: ca.action,
        controller: ca.controller,
        ucaType: t.key,
        ucaTypeLabel: t.label,
        state: "open",
      });
    }
  }
  return {
    system: model.system ?? "unnamed system",
    generated: new Date().toISOString(),
    totalCells: cells.length,
    scope: model.scope,
    declaredElements: declared,
    cells,
  };
}

/** A finding counts only if it binds to ≥1 declared control-structure element. */
function isBound(c: Cell, declared: Set<string>): boolean {
  return (c.bindsTo ?? []).some((id) => declared.has(id));
}

/**
 * Binding-concentration check — the second-order gaming guard.
 *
 * Set-membership binding alone is still gameable: cite the SAME element ID on
 * every cell and you get 100% coverage with boilerplate. Genuine analysis spreads
 * across the model, because different control actions depend on different beliefs.
 * Extreme concentration is therefore a smell, and it gets surfaced rather than
 * silently accepted.
 *
 * This is a WARNING, not a hard failure — a small system legitimately has few
 * elements, and a real single-cause defect legitimately implicates one belief
 * repeatedly. Judgment stays with the analyst; the tool just refuses to be quiet.
 *
 * KNOWN LIMIT (verified by cross-vendor audit, 2026-07-22): the heuristic is
 * `distinct <= 1 || topShare >= 0.8`. Alternating identical boilerplate across TWO
 * declared IDs at 50/50 passes clean. Closing that would require semantic judgment
 * of statement content, which arithmetic cannot do and this tool does not attempt.
 * It is stated here rather than hidden because a guard whose blind spot is
 * undocumented is worse than one with no guard — it invites false confidence.
 * The backstop is human review of the statements themselves.
 */
function bindingConcentration(cells: Cell[], declared: Set<string>) {
  const findings = cells.filter((c) => c.state === "uca" && isBound(c, declared));
  const counts = new Map<string, number>();
  for (const c of findings) {
    for (const id of new Set((c.bindsTo ?? []).filter((r) => declared.has(r)))) {
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
  }
  const distinct = counts.size;
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
  const topShare = findings.length && top ? top[1] / findings.length : 0;
  const warn = findings.length >= 4 && (distinct <= 1 || topShare >= 0.8);
  return { findings: findings.length, distinct, top, topShare, warn, counts };
}

function validate(grid: Grid): string[] {
  const errs: string[] = [];
  if (grid.cells.length !== grid.totalCells) {
    errs.push(`totalCells (${grid.totalCells}) != actual cells (${grid.cells.length})`);
  }
  const declared = new Set(grid.declaredElements ?? []);
  if (declared.size === 0) {
    errs.push(
      "grid declares no control-structure elements — regenerate with `init` from a model that has processModels",
    );
  }
  const byAction = new Map<string, Set<string>>();
  for (const c of grid.cells) {
    if (c.state === "tombstone" && !c.reason?.trim()) {
      errs.push(`${c.id}: tombstoned with no reason — a reasoned skip is required, a silent one is not a skip`);
    }
    if (c.state === "uca" && !c.statement?.trim()) {
      errs.push(`${c.id}: state=uca with no statement — write the five-part UCA sentence`);
    }
    for (const ref of c.bindsTo ?? []) {
      if (!declared.has(ref)) {
        errs.push(`${c.id}: bindsTo references undeclared element "${ref}"`);
      }
    }
    if (!byAction.has(c.controlActionId)) byAction.set(c.controlActionId, new Set());
    byAction.get(c.controlActionId)!.add(c.ucaType);
  }
  for (const [id, types] of byAction) {
    if (types.size !== UCA_TYPES.length) {
      errs.push(`${id}: has ${types.size}/${UCA_TYPES.length} UCA-type cells — grid is malformed`);
    }
  }
  return errs;
}

function status(grid: Grid): number {
  const errs = validate(grid);
  const declared = new Set(grid.declaredElements ?? []);
  const open = grid.cells.filter((c) => c.state === "open");
  const uca = grid.cells.filter((c) => c.state === "uca");
  const tomb = grid.cells.filter((c) => c.state === "tombstone");
  const bound = uca.filter((c) => isBound(c, declared));
  const unbound = uca.filter((c) => !isBound(c, declared));
  const resolved = bound.length + tomb.length;
  const ratio = grid.totalCells === 0 ? 0 : resolved / grid.totalCells;
  const conc0 = bindingConcentration(grid.cells, declared);

  console.log(`system:        ${grid.system}`);
  console.log(`control acts:  ${grid.totalCells / UCA_TYPES.length}`);
  console.log(`total cells:   ${grid.totalCells}  (4 x control actions)`);
  console.log(`declared elts: ${declared.size}  (process-model variables + feedback channels)`);
  console.log(`findings:      ${uca.length}  (${bound.length} bound, ${unbound.length} UNBOUND)`);
  console.log(`tombstoned:    ${tomb.length}`);
  console.log(`open:          ${open.length}`);
  // The qualifier rides ON the coverage line, not beside it. A caveat printed
  // underneath gets dropped the moment someone quotes the number; a caveat inside
  // the number cannot be quoted away.
  const qualifier = conc0.warn ? "  ** CONCENTRATED — NOT A CLEAN 100; see warning below **" : "";
  console.log(
    `COVERAGE:      ${(ratio * 100).toFixed(1)}%  (${resolved}/${grid.totalCells})  [bound findings + reasoned tombstones]${qualifier}`,
  );

  const cand = grid.scope?.candidateControlActions;
  const modeled = grid.totalCells / UCA_TYPES.length;
  if (cand && cand > 0) {
    const surf = (modeled / cand) * 100;
    console.log(
      `SURFACE:       ${surf.toFixed(0)}%  (${modeled}/${cand} candidate control actions modeled)` +
        (surf < 100 ? `  << grid coverage is of the MODELED subset, not the system` : ""),
    );
  } else {
    console.log(`SURFACE:       unknown — model.json has no scope.candidateControlActions`);
    console.log(`               Grid coverage describes only what was modeled. Record how many`);
    console.log(`               control actions the system actually has, or the number misleads.`);
  }

  const perType = UCA_TYPES.map((t) => {
    const n = uca.filter((c) => c.ucaType === t.key).length;
    return `  ${t.key.padEnd(13)} ${n}`;
  }).join("\n");
  console.log(`findings by type:\n${perType}`);

  const conc = bindingConcentration(grid.cells, declared);
  if (conc.findings) {
    console.log(
      `binding spread: ${conc.distinct} distinct element(s) across ${conc.findings} bound findings` +
        (conc.top ? `; most-cited ${conc.top[0]} in ${conc.top[1]} (${(conc.topShare * 100).toFixed(0)}%)` : ""),
    );
  }
  if (conc.warn) {
    console.log(`\n!! BINDING CONCENTRATION WARNING`);
    console.log(`   Nearly every finding cites the same control-structure element. Real analysis`);
    console.log(`   spreads across the model, because different control actions depend on different`);
    console.log(`   beliefs. This pattern is what boilerplate-with-a-citation looks like.`);
    console.log(`   Legitimate if the system is small or one belief genuinely drives everything —`);
    console.log(`   if so, say that in the report. Otherwise the findings are not yet specific.`);
  }

  if (unbound.length) {
    console.log(`\nUNBOUND FINDINGS (do NOT count toward coverage):`);
    console.log(`  A finding that references no declared process-model variable or feedback`);
    console.log(`  channel is not grounded in this system's control structure — it is a generic`);
    console.log(`  vulnerability-class statement that would read the same against any codebase.`);
    console.log(`  Bind it to the model element that makes it true here, or drop it.`);
    for (const c of unbound.slice(0, 40)) {
      console.log(`  ${c.id}  [${c.controller}] ${(c.statement ?? "").slice(0, 100)}`);
    }
    if (unbound.length > 40) console.log(`  … and ${unbound.length - 40} more`);
  }

  if (open.length) {
    console.log(`\nOPEN CELLS (unanalyzed — these are holes, not passes):`);
    for (const c of open.slice(0, 40)) {
      console.log(`  ${c.id}  [${c.controller}] ${c.controlAction} — ${c.ucaTypeLabel}`);
    }
    if (open.length > 40) console.log(`  … and ${open.length - 40} more`);
  }
  if (errs.length) {
    console.log(`\nVALIDATION ERRORS:`);
    for (const e of errs) console.log(`  ${e}`);
    return 1;
  }
  // Exit 3 on concentration so automation and any wrapping workflow cannot treat a
  // concentrated grid as a clean pass. Distinct from 1 (validation error) so a caller
  // can tell "malformed" from "suspiciously uniform". Open cells stay exit 0 —
  // they are visibly incomplete, which is honest; concentration is invisibly shallow,
  // which is not.
  if (conc0.warn) return 3;
  return 0;
}

function markdown(grid: Grid): string {
  const lines: string[] = [];
  const declared = new Set(grid.declaredElements ?? []);
  lines.push(`# UCA Grid — ${grid.system}`);
  lines.push("");
  const resolved = grid.cells.filter(
    (c) => c.state === "tombstone" || (c.state === "uca" && isBound(c, declared)),
  ).length;
  const conc = bindingConcentration(grid.cells, declared);
  lines.push(
    `Coverage: **${((resolved / grid.totalCells) * 100).toFixed(1)}%** (${resolved}/${grid.totalCells} cells) — ${grid.totalCells / UCA_TYPES.length} control actions x ${UCA_TYPES.length} UCA types. Counted: findings bound to a declared control-structure element, plus reasoned tombstones.`,
  );
  if (conc.warn) {
    lines.push("");
    lines.push(
      `> **⚠️ THIS COVERAGE FIGURE IS NOT A CLEAN PASS.** ${conc.distinct} distinct control-structure element(s) across ${conc.findings} bound findings` +
        (conc.top ? `; \`${conc.top[0]}\` is cited by ${(conc.topShare * 100).toFixed(0)}% of them` : "") +
        `. Genuine analysis spreads across the model, because different control actions depend on different beliefs. This shape is what boilerplate-with-a-citation looks like. If the concentration is real — a small system, or one belief that genuinely drives everything — state that explicitly here. Do not quote the percentage above without this paragraph.`,
    );
  }
  lines.push("");
  const groups = new Map<string, Cell[]>();
  for (const c of grid.cells) {
    if (!groups.has(c.controlActionId)) groups.set(c.controlActionId, []);
    groups.get(c.controlActionId)!.push(c);
  }
  for (const [id, cells] of groups) {
    const first = cells[0]!;
    lines.push(`## ${id} — ${first.controller} → ${first.controlAction}`);
    lines.push("");
    lines.push(`| type | state | statement / reason | binds to | links to |`);
    lines.push(`|------|-------|--------------------|----------|----------|`);
    for (const c of cells) {
      const mark =
        c.state === "uca"
          ? isBound(c, declared)
            ? "**UCA**"
            : "**UCA (UNBOUND — uncounted)**"
          : c.state === "tombstone"
            ? "n/a"
            : "OPEN";
      const body = c.state === "uca" ? (c.statement ?? "") : c.state === "tombstone" ? (c.reason ?? "") : "—";
      lines.push(
        `| ${c.ucaType} | ${mark} | ${body.replace(/\|/g, "\\|")} | ${(c.bindsTo ?? []).join(", ")} | ${(c.linksTo ?? []).join(", ")} |`,
      );
    }
    lines.push("");
  }
  return lines.join("\n");
}

// ---- main ----
const argv = process.argv.slice(2);
if (argv.length < 2) usage();

const cmd = argv[0]!;
const input = argv[1]!;
const outIdx = argv.indexOf("-o");
const outPath = outIdx !== -1 ? argv[outIdx + 1] : undefined;

if (cmd === "init") {
  const model = readJson(input) as {
    system?: string;
    controlActions?: ControlAction[];
    processModels?: ProcessModel[];
    feedback?: { id?: string }[];
  };
  const grid = buildGrid(model);

  // --merge <old-grid.json>: carry resolved cells forward when the control
  // structure changes, so a re-analysis costs only the genuinely new cells.
  const mIdx = argv.indexOf("--merge");
  if (mIdx !== -1) {
    const oldPath = argv[mIdx + 1];
    if (!oldPath) die("--merge needs a path to the previous grid.json");
    const prev = readJson(oldPath) as Grid;
    const prevById = new Map((prev.cells ?? []).map((c) => [c.id, c]));
    let carried = 0;
    for (const c of grid.cells) {
      const p = prevById.get(c.id);
      if (p && p.state !== "open") {
        c.state = p.state;
        c.statement = p.statement;
        c.reason = p.reason;
        c.linksTo = p.linksTo;
        c.bindsTo = p.bindsTo;
        carried++;
      }
    }
    const nowIds = new Set(grid.cells.map((c) => c.id));
    const dropped = (prev.cells ?? []).filter((c) => !nowIds.has(c.id));
    const added = grid.cells.filter((c) => !prevById.has(c.id));
    console.error(`merged from ${oldPath}: ${carried} resolved cells carried forward`);
    console.error(`  NEW cells needing analysis: ${added.length}`);
    for (const c of added.slice(0, 20)) console.error(`    + ${c.id}  ${c.controlAction} — ${c.ucaTypeLabel}`);
    if (added.length > 20) console.error(`    … and ${added.length - 20} more`);
    if (dropped.length) {
      console.error(`  REMOVED cells (control action gone from the model): ${dropped.length}`);
      for (const c of dropped.slice(0, 20)) console.error(`    - ${c.id}`);
      console.error(`  Confirm each removal is a real design change, not a modeling omission.`);
    }
    // Stale bindings: a carried finding may cite an element the new model dropped.
    const declaredNow = new Set(grid.declaredElements);
    const stale = grid.cells.filter(
      (c) => c.state === "uca" && (c.bindsTo ?? []).length > 0 && !(c.bindsTo ?? []).some((r) => declaredNow.has(r)),
    );
    if (stale.length) {
      console.error(`  ${stale.length} carried finding(s) now bind to nothing declared — they no longer count toward coverage.`);
    }
  }

  const json = JSON.stringify(grid, null, 2);
  if (outPath) writeOut(outPath, json, `wrote ${grid.totalCells} cells → ${outPath}`);
  else console.log(json);
  process.exit(0);
} else if (cmd === "status") {
  const grid = readJson(input) as Grid;
  process.exit(status(grid));
} else if (cmd === "markdown") {
  const grid = readJson(input) as Grid;
  const errs = validate(grid);
  if (errs.length) {
    for (const e of errs) console.error(`ERROR ${e}`);
    process.exit(1);
  }
  const md = markdown(grid);
  if (outPath) writeOut(outPath, md, `wrote → ${outPath}`);
  else console.log(md);
  process.exit(0);
} else {
  usage();
}
