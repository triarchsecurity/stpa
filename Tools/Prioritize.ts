#!/usr/bin/env bun
/**
 * Prioritize.ts — turns findings into an engineering backlog.
 *
 * An STPA grid tells you what is unsafe. It does not tell a team what to do on
 * Monday. The missing pieces are cost, location, and leverage:
 *
 *   - **Cost.** Severity alone cannot rank work. Severity x reachability x effort
 *     is the minimum triple, and effort is the one an analyst is most tempted to
 *     omit because it requires knowing the codebase.
 *   - **Location.** "The per-route guard chain" costs an engineer an hour to
 *     relocate. `src/lib/api-auth.ts:39` costs zero.
 *   - **Leverage.** N findings usually collapse to far fewer root causes. Teams
 *     fix causes, not findings. A plan that does not show "this one change closes
 *     six of these" hides its own best move.
 *
 * This tool computes all three from `remediation.json` + `grid.json` and emits a
 * sequenced plan. It invents nothing: severity, reachability and effort are
 * analyst inputs; bands, leverage, waves and the metrics are arithmetic over them.
 *
 * NOT A RISK SCORE. Band is severity x reachability from AdversarialContext.md —
 * a toolkit extension, explicitly not a probability and not
 * CVSS-comparable. It orders THIS analysis's findings for THIS team.
 *
 * Usage:
 *   bun Prioritize.ts [analysis-dir]        # writes 06-remediation.{json,md}
 *   bun Prioritize.ts [dir] --check         # exit 1 if any finding lacks remediation
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

type Sev = "catastrophic" | "severe" | "moderate" | "minor";
type Reach = "R0" | "R1" | "R2" | "R3" | "R4";
type Effort = "S" | "M" | "L";

interface Remediation {
  severity: Sev;
  reachability: Reach;
  effort: Effort;
  cluster?: string;
  location?: string;
  fix: string;
  probe?: string;
  note?: string;
}
interface Cluster {
  id: string;
  name: string;
  summary?: string;
  fix?: string;
  effort?: Effort;
  /**
   * Cluster-level defaults. On a large analysis, hand-writing severity and
   * reachability for every finding is the step that does not get done, and a plan
   * that does not get written is a plan that does not exist. Findings sharing a
   * root cause usually share a severity and a reachability, so set them once here
   * and override only where a specific finding genuinely differs.
   */
  severity?: Sev;
  reachability?: Reach;
  location?: string;
  probe?: string;
  members?: string[];
}
interface RemedFile {
  clusters?: Cluster[];
  findings: Record<string, Remediation>;
}

/** severity x reachability -> band. From AdversarialContext.md. Not a probability. */
const BAND: Record<Sev, Record<Reach, number>> = {
  catastrophic: { R0: 1, R1: 1, R2: 2, R3: 2, R4: 3 },
  severe: { R0: 1, R1: 2, R2: 2, R3: 3, R4: 3 },
  moderate: { R0: 2, R1: 3, R2: 3, R3: 4, R4: 4 },
  minor: { R0: 3, R1: 4, R2: 4, R3: 4, R4: 4 },
};
const BAND_LABEL: Record<number, string> = {
  1: "Fix before ship",
  2: "Fix this cycle",
  3: "Constrain and schedule",
  4: "Accept explicitly, in writing",
};
const EFFORT_LABEL: Record<Effort, string> = { S: "hours", M: "days", L: "weeks" };
const EFFORT_RANK: Record<Effort, number> = { S: 0, M: 1, L: 2 };
const REACH_LABEL: Record<Reach, string> = {
  R0: "adversary creates the context directly",
  R1: "adversary induces it through normal interaction",
  R2: "adversary waits for it to arise",
  R3: "requires a prior foothold",
  R4: "requires an insider or supply-chain compromise",
};

function die(m: string, c = 1): never {
  console.error(m);
  process.exit(c);
}

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h"))
  die("Usage: bun Prioritize.ts [analysis-dir] [--check]\n\nReads grid.json + remediation.json, writes 06-remediation.{json,md}.", 2);

const dir = resolve(argv.find((a) => !a.startsWith("-")) ?? ".stpa");
const checkOnly = argv.includes("--check");

const readJson = (f: string) => {
  const p = join(dir, f);
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch (e) {
    die(`${f} is not valid JSON: ${(e as Error).message}`);
  }
};

const grid = readJson("grid.json");
if (!grid) die(`no grid.json in ${dir} — run Steps 2–3 first.`);
const remed: RemedFile | null = readJson("remediation.json");
if (!remed) {
  die(
    [
      `no remediation.json in ${dir}.`,
      "",
      "Findings without cost, location and a fix are an analysis, not a plan.",
      "Create remediation.json keyed on grid cell ids:",
      "",
      "{",
      '  "clusters": [',
      '    { "id": "RC-1", "name": "Authorization is per-route opt-in",',
      '      "summary": "why these findings share a cause",',
      '      "fix": "the one structural change that closes them", "effort": "L" }',
      "  ],",
      '  "findings": {',
      '    "CA-1.not-provided": {',
      '      "severity": "catastrophic|severe|moderate|minor",',
      '      "reachability": "R0|R1|R2|R3|R4",',
      '      "effort": "S|M|L",',
      '      "cluster": "RC-1",',
      '      "location": "src/lib/api-auth.ts:39",',
      '      "fix": "the concrete change an engineer makes",',
      '      "probe": "a command that fails before and passes after"',
      "    }",
      "  }",
      "}",
    ].join("\n"),
  );
}

const declared = new Set<string>(grid.declaredElements ?? []);
const findings = (grid.cells as any[]).filter(
  (c) => c.state === "uca" && (c.bindsTo ?? []).some((r: string) => declared.has(r)),
);

// ── join + validate ───────────────────────────────────────────────────────
const missing: string[] = [];
// cluster membership can be declared on the cluster (members: [...]) instead of
// repeated on every finding
const memberOf = new Map<string, string>();
for (const cl of remed.clusters ?? []) for (const id of cl.members ?? []) memberOf.set(id, cl.id);
const clusterById = new Map<string, Cluster>((remed.clusters ?? []).map((c) => [c.id, c]));

const inherited: string[] = [];
const rows = findings.map((c) => {
  const explicit = remed.findings?.[c.id];
  const clId = explicit?.cluster ?? memberOf.get(c.id);
  const cl = clId ? clusterById.get(clId) : undefined;

  // Merge: explicit finding fields win; anything absent falls back to the cluster.
  const r: Remediation | undefined =
    explicit || cl
      ? ({
          severity: explicit?.severity ?? cl?.severity,
          reachability: explicit?.reachability ?? cl?.reachability,
          effort: explicit?.effort ?? cl?.effort,
          cluster: clId,
          location: explicit?.location ?? (c as any).location ?? cl?.location,
          fix: explicit?.fix ?? cl?.fix,
          probe: explicit?.probe ?? cl?.probe,
        } as Remediation)
      : undefined;
  if (!explicit && r) inherited.push(c.id);

  if (!r || !r.severity || !r.reachability || !r.effort) {
    missing.push(c.id);
    return null;
  }
  // Membership checks, not truthiness — EFFORT_RANK.S is 0 and band values are
  // never 0, but relying on that is exactly how a valid input gets rejected.
  if (!(r.severity in BAND)) die(`${c.id}: unknown severity "${r.severity}" (catastrophic|severe|moderate|minor)`);
  if (!(r.reachability in BAND[r.severity])) die(`${c.id}: unknown reachability "${r.reachability}" (R0..R4)`);
  if (!(r.effort in EFFORT_RANK)) die(`${c.id}: unknown effort "${r.effort}" (S|M|L)`);
  if (!r.fix?.trim()) die(`${c.id}: no fix — a finding without a concrete change is not actionable`);
  return { cell: c, ...r, band: BAND[r.severity][r.reachability] };
});

if (missing.length) {
  console.error(`${missing.length} bound finding(s) have no remediation entry:`);
  for (const m of missing) console.error(`  ${m}`);
  console.error(`\nEvery finding needs severity, reachability, effort and a fix, or it cannot be scheduled.`);
  if (checkOnly) process.exit(1);
}
if (inherited.length) {
  console.error(`${inherited.length} finding(s) inherited severity/effort from their cluster; ${Object.keys(remed.findings ?? {}).length} set explicitly.`);
}
if (checkOnly) {
  console.error(`all ${rows.filter(Boolean).length} bound findings have remediation entries`);
  process.exit(0);
}

const R = rows.filter(Boolean) as NonNullable<(typeof rows)[number]>[];

// ── cluster leverage: how many findings one fix closes ────────────────────
const clusterMap = new Map<string, Cluster>((remed.clusters ?? []).map((c) => [c.id, c]));
const byCluster = new Map<string, typeof R>();
for (const r of R) {
  const k = r.cluster ?? `(ungrouped:${r.cell.id})`;
  if (!byCluster.has(k)) byCluster.set(k, [] as any);
  (byCluster.get(k) as any).push(r);
}
const clusters = [...byCluster.entries()]
  .map(([id, items]) => {
    const meta = clusterMap.get(id);
    const bestBand = Math.min(...items.map((i) => i.band));
    const effort = meta?.effort ?? (items.map((i) => i.effort).sort((a, b) => EFFORT_RANK[b] - EFFORT_RANK[a])[0] as Effort);
    return {
      id,
      name: meta?.name ?? items[0]!.cell.controlAction,
      summary: meta?.summary,
      fix: meta?.fix,
      effort,
      leverage: items.length,
      bestBand,
      items: items.sort((a, b) => a.band - b.band),
      grouped: !!meta,
    };
  })
  // rank by leverage first, then by the severity of the worst thing it closes
  .sort((a, b) => b.leverage - a.leverage || a.bestBand - b.bestBand || EFFORT_RANK[a.effort] - EFFORT_RANK[b.effort]);

// ── waves ─────────────────────────────────────────────────────────────────
// Wave 1: everything band 1, plus band-2 quick wins (effort S) — the set that
// buys the most reduction for the least sequencing risk.
// Wave 2: remaining band 2.  Wave 3: band 3.  Backlog: band 4 (accept in writing).
const wave = (r: (typeof R)[number]) =>
  r.band === 1 ? 1 : r.band === 2 ? (r.effort === "S" ? 1 : 2) : r.band === 3 ? 3 : 4;
const waves = [1, 2, 3, 4].map((w) => ({ w, items: R.filter((r) => wave(r) === w).sort((a, b) => a.band - b.band || EFFORT_RANK[a.effort] - EFFORT_RANK[b.effort]) }));

// ── metrics ───────────────────────────────────────────────────────────────
const bandCount = [1, 2, 3, 4].map((b) => R.filter((r) => r.band === b).length);
const effortCount = (["S", "M", "L"] as Effort[]).map((e) => R.filter((r) => r.effort === e).length);
const quickWins = R.filter((r) => r.band <= 2 && r.effort === "S");
const urgent = R.filter((r) => r.band <= 2);
const wave1 = waves[0]!.items;
const wave1CoversUrgent = urgent.length ? wave1.filter((r) => r.band <= 2).length / urgent.length : 1;
const topCluster = clusters[0];
const withLocation = R.filter((r) => r.location?.trim()).length;
const withProbe = R.filter((r) => r.probe?.trim()).length;

const metrics = {
  findings: R.length,
  unremediated: missing.length,
  bands: { band1: bandCount[0], band2: bandCount[1], band3: bandCount[2], band4: bandCount[3] },
  effort: { S: effortCount[0], M: effortCount[1], L: effortCount[2] },
  quickWins: quickWins.length,
  rootCauses: clusters.filter((c) => c.grouped).length,
  maxLeverage: topCluster?.leverage ?? 0,
  concentration: R.length ? Number(((topCluster?.leverage ?? 0) / R.length).toFixed(2)) : 0,
  wave1Size: wave1.length,
  wave1CoversUrgentPct: Number((wave1CoversUrgent * 100).toFixed(0)),
  locatedPct: R.length ? Number(((withLocation / R.length) * 100).toFixed(0)) : 0,
  probedPct: R.length ? Number(((withProbe / R.length) * 100).toFixed(0)) : 0,
};

const out = {
  system: grid.system,
  metrics,
  clusters: clusters.map((c) => ({ id: c.id, name: c.name, summary: c.summary, fix: c.fix, effort: c.effort, leverage: c.leverage, bestBand: c.bestBand, findings: c.items.map((i) => i.cell.id) })),
  waves: waves.map((w) => ({
    wave: w.w,
    label: w.w === 1 ? "Start here" : w.w === 2 ? "This cycle" : w.w === 3 ? "Scheduled" : "Accept in writing",
    items: w.items.map((r) => ({
      id: r.cell.id, controlAction: r.cell.controlAction, controller: r.cell.controller,
      band: r.band, severity: r.severity, reachability: r.reachability, effort: r.effort,
      cluster: r.cluster ?? null, location: r.location ?? null, fix: r.fix, probe: r.probe ?? null,
      statement: r.cell.statement,
    })),
  })),
};
writeFileSync(join(dir, "06-remediation.json"), JSON.stringify(out, null, 2));

// ── markdown ──────────────────────────────────────────────────────────────
const md: string[] = [];
md.push(`# 06 — Engineering plan`);
md.push("");
md.push(
  `**${metrics.findings} findings → ${metrics.rootCauses || clusters.length} root cause${(metrics.rootCauses || clusters.length) === 1 ? "" : "s"}.** ` +
    `${metrics.bands.band1} band-1, ${metrics.bands.band2} band-2. ` +
    `${metrics.quickWins} quick win${metrics.quickWins === 1 ? "" : "s"} (band ≤2, hours of work). ` +
    `Wave 1 is ${metrics.wave1Size} item${metrics.wave1Size === 1 ? "" : "s"} and closes ${metrics.wave1CoversUrgentPct}% of everything band-2-or-worse.`,
);
md.push("");
md.push(`> Band is severity × reachability, a toolkit extension — **not a probability, not CVSS-comparable.** It orders this analysis's findings for this team and nothing else.`);
md.push("");
if (topCluster && topCluster.leverage > 1) {
  md.push(`## Highest-leverage move`);
  md.push("");
  md.push(`**${topCluster.name}** — one change closes **${topCluster.leverage} of ${metrics.findings}** findings (effort: ${topCluster.effort}, ${EFFORT_LABEL[topCluster.effort]}).`);
  if (topCluster.summary) md.push(`\n${topCluster.summary}`);
  if (topCluster.fix) md.push(`\n**Do this:** ${topCluster.fix}`);
  md.push("");
}
md.push(`## Root causes, by leverage`);
md.push("");
md.push(`| cluster | closes | worst band | effort | the one change |`);
md.push(`|---|---|---|---|---|`);
for (const c of clusters) {
  md.push(`| **${c.name}** | ${c.leverage} finding${c.leverage === 1 ? "" : "s"} | ${c.bestBand} | ${c.effort} · ${EFFORT_LABEL[c.effort]} | ${(c.fix ?? "—").replace(/\|/g, "\\|")} |`);
}
md.push("");
for (const w of waves) {
  if (!w.items.length) continue;
  const label = w.w === 1 ? "Wave 1 — start here" : w.w === 2 ? "Wave 2 — this cycle" : w.w === 3 ? "Wave 3 — scheduled" : "Backlog — accept explicitly, in writing";
  md.push(`## ${label} (${w.items.length})`);
  md.push("");
  md.push(`| id | band | effort | where | do this | verify with |`);
  md.push(`|---|---|---|---|---|---|`);
  for (const r of w.items) {
    md.push(
      `| \`${r.cell.id}\` | ${r.band} | ${r.effort} | ${r.location ? `\`${r.location}\`` : "_unlocated_"} | ${r.fix.replace(/\|/g, "\\|")} | ${r.probe ? `\`${r.probe.replace(/\|/g, "\\|")}\`` : "_no probe_"} |`,
    );
  }
  md.push("");
}
md.push(`## Reachability legend`);
md.push("");
for (const [k, v] of Object.entries(REACH_LABEL)) md.push(`- **${k}** — ${v}`);
md.push("");
md.push(`## Plan quality`);
md.push("");
md.push(`| measure | value | why it matters |`);
md.push(`|---|---|---|`);
md.push(`| Findings with a file location | ${metrics.locatedPct}% | an unlocated finding costs an engineer an hour before work starts |`);
md.push(`| Findings with a runnable probe | ${metrics.probedPct}% | without one, "fixed" is an opinion |`);
md.push(`| Root-cause concentration | ${(metrics.concentration * 100).toFixed(0)}% | share of findings the single biggest fix closes |`);
if (metrics.unremediated) md.push(`| **Findings with no plan** | **${metrics.unremediated}** | **these cannot be scheduled at all** |`);
writeFileSync(join(dir, "06-remediation.md"), md.join("\n"));

console.error(
  `wrote 06-remediation.{json,md} — ${metrics.findings} findings, ${clusters.length} clusters, ` +
    `wave1=${metrics.wave1Size} (${metrics.wave1CoversUrgentPct}% of band≤2), quick wins=${metrics.quickWins}` +
    (metrics.unremediated ? `, UNREMEDIATED=${metrics.unremediated}` : ""),
);
