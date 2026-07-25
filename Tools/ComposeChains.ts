#!/usr/bin/env bun
/**
 * ComposeChains.ts — STPA Step 4c: rate findings as a SYSTEM, not as a list.
 *
 * WHY THIS EXISTS (learned the hard way, 2026-07-25, from two runs of the same
 * target four hours apart):
 *
 *   Run A found "token forgery — any internet caller can mint a session"  → R0.
 *   Run A found "web terminal spawns a PTY with the container's full env,
 *                gated on the caller's email domain being alertd.ai"      → R3.
 *
 *   Both findings were correct. Both were rated correctly *in isolation*. And the
 *   composition — forge a token whose email field you control, satisfy the domain
 *   check, get an interactive shell with the workload's AWS credentials — is an
 *   UNAUTHENTICATED REMOTE SHELL that neither finding states and no reviewer saw,
 *   because every rating question in the method is asked about one finding at a
 *   time. Run B (different day, revised skill) found the forgery and missed the
 *   PTY entirely, so it could not have composed them either.
 *
 * The lesson is not "reviewers should think harder." It is that reachability is
 * not a property of a finding. It is a property of a finding GIVEN what the other
 * findings hand the attacker. R3 means "needs a foothold" — and if some other
 * finding in the same report *is* the foothold, R3 is a fiction.
 *
 * So this tool asks the one question the four UCA types cannot: what does each
 * finding GRANT, what does each finding REQUIRE, and which grants satisfy which
 * requirements? Then it recomputes reachability transitively and refuses to pass
 * when a finding's recorded band is softer than its composed band.
 *
 * This is a LifeOS extension, not STPA doctrine. Leveson's method has no notion of
 * chained findings — it has no likelihood or ranking at all. Do not present the
 * composed band as STPA, and do not present it as a probability.
 *
 * Capability tokens are deliberately coarse. A taxonomy fine enough to be precise
 * is too fine to be used consistently, and an unused field is worse than a blunt one:
 *
 *   identity:any        a session as an arbitrary user of the system
 *   identity:staff      a session that passes a vendor/staff/admin test
 *   identity:tenant     a session scoped to some particular tenant
 *   credential:session  a bearer token / cookie usable elsewhere
 *   credential:cloud    cloud credentials usable OFF the box
 *   key:signing         key material that mints or verifies credentials
 *   secret:config       secrets at rest (SOPS blob, env, parameter store)
 *   foothold:network    the ability to reach an internal-only network position
 *   exec:runtime        code execution inside the application process
 *   exec:host           command execution on the host/container
 *   read:tenant         another tenant's data
 *   write:inputs        the ability to write what the system reasons over
 *   id:tenant-key       a tenant identifier used as a scoping or lookup key
 *
 * Usage:
 *   bun ComposeChains.ts [analysis-dir] [--check] [--max-depth N]
 *
 * Reads  remediation.json (+ grid.json for statements/labels)
 * Writes 07-chains.json, 07-chains.md
 * Exit:  0 pass · 1 bad input · 6 an unrated composition exists (with --check)
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

type Reach = "R0" | "R1" | "R2" | "R3" | "R4";
type Sev = "catastrophic" | "severe" | "moderate" | "minor";

const REACH_ORDER: Reach[] = ["R0", "R1", "R2", "R3", "R4"];
const reachRank = (r: Reach) => REACH_ORDER.indexOf(r);
/** Lower rank = easier to reach. Composition can only ever make a finding EASIER. */
const easier = (a: Reach, b: Reach): Reach => (reachRank(a) <= reachRank(b) ? a : b);

const BAND: Record<Sev, Record<Reach, number>> = {
  catastrophic: { R0: 1, R1: 1, R2: 2, R3: 2, R4: 3 },
  severe: { R0: 1, R1: 2, R2: 2, R3: 3, R4: 3 },
  moderate: { R0: 2, R1: 3, R2: 3, R3: 4, R4: 4 },
  minor: { R0: 3, R1: 4, R2: 4, R3: 4, R4: 4 },
};

const KNOWN_CAPS = new Set([
  "identity:any", "identity:staff", "identity:tenant",
  "credential:session", "credential:cloud", "key:signing", "secret:config",
  "foothold:network", "exec:runtime", "exec:host",
  "read:tenant", "write:inputs", "id:tenant-key",
]);

function die(msg: string, code = 1): never {
  console.error(msg);
  process.exit(code);
}

const argv = process.argv.slice(2);
const check = argv.includes("--check");
const depthArg = argv.indexOf("--max-depth");
const MAX_DEPTH = depthArg !== -1 ? Number(argv[depthArg + 1]) || 4 : 4;
// Guard on depthArg !== -1. Without --max-depth, depthArg is -1 and argv[depthArg + 1]
// is argv[0] — the positional directory itself — so it was filtered out and dir
// silently fell back to ".", which is how `stpa run` reported UNRATED COMPOSITION
// while looking at the wrong directory.
const dir = resolve(
  argv.find((a) => !a.startsWith("--") && (depthArg === -1 || a !== argv[depthArg + 1])) ?? ".",
);

const readJson = (name: string): any => {
  const p = join(dir, name);
  if (!existsSync(p)) die(`missing ${name} in ${dir} — run \`stpa plan\` first`);
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch (e) {
    die(`${name} is not valid JSON — ${(e as Error).message}`);
  }
};

const rem = readJson("remediation.json");
const grid = existsSync(join(dir, "grid.json")) ? readJson("grid.json") : { cells: [] };
const cellById = new Map<string, any>();
for (const c of grid.cells ?? []) cellById.set(c.id, c);

interface Node {
  id: string;
  severity: Sev;
  recorded: Reach;
  grants: string[];
  requires: string[];
  composed: Reach;
  via: string[];          // the chain that got us here, nearest-first
  statement: string;
}

const nodes: Node[] = [];
const unknownCaps: { id: string; cap: string }[] = [];

for (const [id, r0] of Object.entries<any>(rem.findings ?? {})) {
  const grants: string[] = Array.isArray(r0.grants) ? r0.grants : [];
  const requires: string[] = Array.isArray(r0.requires) ? r0.requires : [];
  for (const c of [...grants, ...requires]) if (!KNOWN_CAPS.has(c)) unknownCaps.push({ id, cap: c });
  nodes.push({
    id,
    severity: r0.severity,
    recorded: r0.reachability,
    grants,
    requires,
    composed: r0.reachability,
    via: [],
    statement: (cellById.get(id)?.statement ?? cellById.get(id)?.reason ?? "").slice(0, 170),
  });
}

if (!nodes.length) die("remediation.json has no findings", 1);

const declared = nodes.filter((n) => n.grants.length || n.requires.length).length;

// ── the fixed point ───────────────────────────────────────────────────────────
// A finding's composed reachability is the easiest of: its own recorded value, and
// (for each of its requirements) the composed reachability of anything that grants
// that requirement. Iterate to a fixed point so chains of length > 2 propagate.
// Bounded by MAX_DEPTH passes — a cycle just stops improving, which is correct:
// mutually-enabling findings are as reachable as their easiest entry point.
const grantors = new Map<string, Node[]>();
for (const n of nodes) for (const g of n.grants) {
  if (!grantors.has(g)) grantors.set(g, []);
  grantors.get(g)!.push(n);
}

for (let pass = 0; pass < MAX_DEPTH; pass++) {
  let changed = false;
  for (const n of nodes) {
    if (!n.requires.length) continue;
    for (const req of n.requires) {
      for (const g of grantors.get(req) ?? []) {
        if (g.id === n.id) continue;
        // Reaching n via g costs whatever it costs to reach g.
        const viaCost = g.composed;
        if (reachRank(viaCost) < reachRank(n.composed)) {
          n.composed = easier(viaCost, n.composed);
          n.via = [g.id, ...g.via];
          changed = true;
        }
      }
    }
  }
  if (!changed) break;
}

const bandOf = (s: Sev, r: Reach) => BAND[s][r];
const upgraded = nodes
  .filter((n) => reachRank(n.composed) < reachRank(n.recorded))
  .map((n) => ({
    ...n,
    recordedBand: bandOf(n.severity, n.recorded),
    composedBand: bandOf(n.severity, n.composed),
  }))
  .sort((a, b) => a.composedBand - b.composedBand || reachRank(a.composed) - reachRank(b.composed));

const bandMoved = upgraded.filter((u) => u.composedBand < u.recordedBand);

// ── chains worth reading: grant → require paths, deepest first ────────────────
const chains: { path: string[]; entry: Reach; endBand: number; caps: string[] }[] = [];
for (const n of nodes) {
  if (!n.via.length) continue;
  const path = [...[...n.via].reverse(), n.id];
  const entryNode = nodes.find((x) => x.id === path[0])!;
  const caps: string[] = [];
  for (let i = 0; i < path.length - 1; i++) {
    const a = nodes.find((x) => x.id === path[i])!;
    const b = nodes.find((x) => x.id === path[i + 1])!;
    caps.push(a.grants.find((g) => b.requires.includes(g)) ?? "?");
  }
  chains.push({
    path,
    entry: entryNode.recorded,
    endBand: bandOf(n.severity, n.composed),
    caps,
  });
}
chains.sort((a, b) => a.endBand - b.endBand || b.path.length - a.path.length);

// ── report ───────────────────────────────────────────────────────────────────
const out = {
  computedAt: null as null,
  findings: nodes.length,
  declaredCapabilities: declared,
  declaredPct: Math.round((declared / nodes.length) * 100),
  unknownCapabilityTokens: unknownCaps,
  composedUpgrades: upgraded.map((u) => ({
    id: u.id,
    severity: u.severity,
    recorded: u.recorded,
    composed: u.composed,
    recordedBand: u.recordedBand,
    composedBand: u.composedBand,
    via: u.via,
  })),
  bandMoved: bandMoved.length,
  chains: chains.slice(0, 40),
};
writeFileSync(join(dir, "07-chains.json"), JSON.stringify(out, null, 2));

const md: string[] = [];
md.push(`# 07 — Composition: how findings chain\n`);
md.push(
  `Reachability is not a property of a finding. It is a property of a finding **given what the other ` +
    `findings hand the attacker.** A finding rated R3 ("needs a foothold") is not R3 if another finding ` +
    `in this same report *is* the foothold. This section recomputes every band with that in mind.\n`,
);
md.push(
  `> **Not STPA doctrine and not a probability.** STPA has no likelihood model and no notion of chained ` +
    `findings. Composed bands order this analysis's own findings and nothing else.\n`,
);
md.push(
  `**${declared} of ${nodes.length} findings (${out.declaredPct}%) declare grants/requires.** ` +
    `Findings that declare neither cannot chain and cannot be chained to — an undeclared finding is ` +
    `invisible here, so a low percentage means this section is weak, not that the system is safe.\n`,
);

if (unknownCaps.length) {
  md.push(`\n## Unknown capability tokens\n`);
  md.push(`These do not match the declared vocabulary, so they compose with nothing:\n`);
  for (const u of unknownCaps.slice(0, 20)) md.push(`- \`${u.id}\` → \`${u.cap}\``);
  md.push("");
}

if (!bandMoved.length && !upgraded.length) {
  md.push(`\n## No composed upgrades\n`);
  md.push(
    `No finding's reachability improved through another finding. That is a real result only if the ` +
      `declaration rate above is high — otherwise it means the inputs were not filled in.\n`,
  );
} else {
  md.push(`\n## Findings whose real reachability is easier than recorded\n`);
  md.push(`| finding | severity | recorded | composed | band | reached via |`);
  md.push(`|---|---|---|---|---|---|`);
  for (const u of upgraded) {
    const move = u.composedBand < u.recordedBand ? `**${u.recordedBand} → ${u.composedBand}**` : `${u.recordedBand}`;
    md.push(`| \`${u.id}\` | ${u.severity} | ${u.recorded} | **${u.composed}** | ${move} | ${u.via.map((v) => `\`${v}\``).join(" ← ")} |`);
  }
  md.push("");
}

if (chains.length) {
  md.push(`\n## Chains, worst first\n`);
  for (const c of chains.slice(0, 15)) {
    const arrow = c.path
      .map((p, i) => (i === 0 ? `\`${p}\`` : `—[${c.caps[i - 1]}]→ \`${p}\``))
      .join(" ");
    md.push(`- **band ${c.endBand}**, entry ${c.entry}: ${arrow}`);
  }
  md.push("");
}

md.push(`\n## What to do with this\n`);
md.push(
  `A composed upgrade is not a new finding — it is the same finding, correctly rated. Set the composed ` +
    `reachability in \`remediation.json\` and re-run \`stpa plan\`, or record why the chain does not hold ` +
    `(a control between the two links that neither finding mentions). Leaving a composed upgrade ` +
    `unaddressed is how a report ships an R3 that is really an R0.\n`,
);
writeFileSync(join(dir, "07-chains.md"), md.join("\n"));

console.log(`composition analysis — ${dir}\n`);
console.log(`  findings:              ${nodes.length}`);
console.log(`  declare grants/requires: ${declared} (${out.declaredPct}%)`);
console.log(`  composed upgrades:     ${upgraded.length}`);
console.log(`  band changes:          ${bandMoved.length}`);
console.log(`  chains found:          ${chains.length}`);
if (unknownCaps.length) console.log(`  !! unknown capability tokens: ${unknownCaps.length}`);
console.log(`\nwrote 07-chains.{json,md}`);

if (out.declaredPct < 60) {
  console.error(
    `\n!! WEAK COMPOSITION INPUT — only ${out.declaredPct}% of findings declare grants/requires.\n` +
      `   This section cannot find a chain through a finding that declares nothing. Fill in\n` +
      `   grants/requires for at least every band-1 and band-2 finding before trusting it.`,
  );
}

if (bandMoved.length) {
  console.error(`\n!! ${bandMoved.length} finding(s) have a HARDER recorded band than their composed band:`);
  for (const u of bandMoved) {
    console.error(`   ${u.id}: band ${u.recordedBand} → ${u.composedBand}  (${u.recorded} → ${u.composed} via ${u.via.join(" ← ")})`);
  }
  console.error(
    `\n   Either set the composed reachability in remediation.json and re-run \`stpa plan\`, or\n` +
      `   record the control that breaks the chain. An unrated composition is the defect this\n` +
      `   tool exists to catch — a real one shipped as R3 when it was R0.`,
  );
  if (check) process.exit(6);
}
