/**
 * RenderSummary.ts — the one-page executive summary that sits beside REPORT.html.
 *
 * REPORT.html is the analysis: ten sections, the full grid, every scenario and
 * constraint. It is written for the engineers who will fix the findings, and it is
 * long because the method is exhaustive. Nobody forwards it to a founder.
 *
 * This is the page that gets forwarded. One screen, no JavaScript, no external
 * requests, prints to a single sheet: what the system is, what is at stake, the
 * findings that matter most, and where to start on Monday.
 *
 * THE DESIGN CONSTRAINT THAT MATTERS: a summary is the artifact most likely to be
 * read *instead of* the report, which makes it the artifact most likely to launder
 * an incomplete analysis into a confident one. That is precisely the failure class
 * this toolkit exists to find — a component meeting its spec while the composition
 * misleads. So every qualifier the report carries, this page carries too, ABOVE the
 * numbers rather than in a footnote: not peer-reviewed, sections missing, scope not
 * delivered, cells still open, findings unbound. A summary that drops them is not a
 * shorter report, it is a different and false claim.
 *
 * Every number here is computed from the artifacts. None is typed by hand — the
 * evidence gate exists because a stale hand-typed count reached a deliverable once.
 *
 * Usage: stpa summary [analysis-dir] [-o out.html] [--title "..."]
 * Reads grid.json (required), plus 06-remediation.json, 01-scope.md, model.json and
 * review-scorecard.json when present. Writes <dir>/SUMMARY.html.
 */

import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { join, resolve, basename } from "node:path";

type Cell = {
  id: string;
  controlAction?: string;
  controller?: string;
  state: "open" | "uca" | "tombstone";
  statement?: string;
  bindsTo?: string[];
  linksTo?: string[];
};
type Grid = {
  system?: string;
  totalCells: number;
  declaredElements?: string[];
  cells: Cell[];
  scope?: { requested?: string; candidateControlActions?: number; selectionCriteria?: string };
};

const die = (msg: string, code = 1): never => {
  console.error(msg);
  process.exit(code);
};

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) {
  die(
    [
      "RenderSummary.ts — one-page executive summary for an STPA analysis",
      "",
      "Usage: stpa summary [analysis-dir] [-o out.html] [--title \"...\"]",
      "",
      "Reads grid.json (required) plus 06-remediation.json, 01-scope.md, model.json",
      "and review-scorecard.json when present. Writes <dir>/SUMMARY.html.",
      "",
      "This is the page that gets forwarded. It carries every qualifier the full",
      "report carries — a summary that drops them is a different, false claim.",
    ].join("\n"),
    2,
  );
}

const flagArgs = new Set(["-o", "--title"]);
const dir = resolve(argv.find((a, i) => !a.startsWith("-") && !flagArgs.has(argv[i - 1] ?? "")) ?? ".stpa");
const oIdx = argv.indexOf("-o");
const outPath = oIdx !== -1 ? argv[oIdx + 1]! : join(dir, "SUMMARY.html");
const tIdx = argv.indexOf("--title");
const titleOverride = tIdx !== -1 ? argv[tIdx + 1] : undefined;

const read = (f: string) => (existsSync(join(dir, f)) ? readFileSync(join(dir, f), "utf8") : null);
const readJson = <T>(f: string): T | null => {
  const r = read(f);
  if (!r) return null;
  try {
    return JSON.parse(r) as T;
  } catch (e) {
    console.error(`warning: ${f} is not valid JSON (${(e as Error).message}) — continuing without it`);
    return null;
  }
};

const gridRaw = read("grid.json");
if (!gridRaw) die(`no grid.json in ${dir} — run the analysis first (Steps 2–3).`);
let grid: Grid;
try {
  grid = JSON.parse(gridRaw);
} catch (e) {
  die(`grid.json is not valid JSON: ${(e as Error).message}`);
}

const esc = (s: string) =>
  String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

// ── the same arithmetic the grid and the report use; never re-derived by hand ──
const declared = new Set(grid.declaredElements ?? []);
const isBound = (c: Cell) => (c.bindsTo ?? []).some((r) => declared.has(r));
const findings = grid.cells.filter((c) => c.state === "uca");
const bound = findings.filter(isBound);
const unbound = findings.filter((c) => !isBound(c));
const tombs = grid.cells.filter((c) => c.state === "tombstone");
const openCells = grid.cells.filter((c) => c.state === "open");
const pct = grid.totalCells ? ((bound.length + tombs.length) / grid.totalCells) * 100 : 0;

const modeledCAs = grid.totalCells / 4;
const candidateCAs = grid.scope?.candidateControlActions;
const surfacePct = candidateCAs && candidateCAs > 0 ? (modeledCAs / candidateCAs) * 100 : null;
const scopeBreach = grid.scope?.requested === "full" && typeof candidateCAs === "number" && modeledCAs < candidateCAs;

type Plan = {
  system?: string;
  metrics?: Record<string, any>;
  clusters?: { id: string; name: string; summary?: string; fix?: string; effort?: string; leverage?: number; bestBand?: number; findings?: string[] }[];
  waves?: { wave: number; label?: string; items?: any[] }[];
};
const plan = readJson<Plan>("06-remediation.json");
const bandOf = new Map<string, number>();
const itemOf = new Map<string, any>();
for (const w of plan?.waves ?? [])
  for (const it of w.items ?? []) {
    if (typeof it?.band === "number") bandOf.set(it.id, it.band);
    itemOf.set(it.id, it);
  }
const band1 = findings.filter((c) => bandOf.get(c.id) === 1);

// The same section contract the report enforces. A summary of an analysis missing
// its scenarios is a summary of half a method, and must say so.
const SECTIONS = [
  { file: "01-scope.md", label: "Scope, losses and hazards" },
  { file: "02-control-structure.md", label: "Control structure" },
  { file: "04-scenarios.md", label: "Loss scenarios" },
  { file: "07-chains.md", label: "Composition" },
  { file: "05-constraints.md", label: "Security constraints" },
  { file: "06-remediation.json", label: "Engineering plan" },
];
const missingSections = SECTIONS.filter((x) => !read(x.file));

// ── losses and hazards, parsed out of 01-scope.md exactly as the report does ──
const scopeMd = read("01-scope.md") ?? "";
const parseLH = (letter: string): { id: string; title: string; text: string }[] => {
  const out: { id: string; title: string; text: string }[] = [];
  const re = new RegExp(`-\\s*\\*\\*(${letter}-\\d+)[^*]*\\*\\*\\s*([\\s\\S]*?)(?=\\n\\s*-\\s*\\*\\*|\\n\\s*\\n|\\n#|$)`, "g");
  for (const m of scopeMd.matchAll(re)) {
    const boldInner = (m[0].match(/\*\*([^*]+)\*\*/)?.[1] ?? m[1]).trim();
    const title = boldInner
      .replace(new RegExp(`^${letter}-\\d+\\s*[—:–-]?\\s*`), "")
      .replace(/[.:]\s*$/, "")
      .trim();
    const text = (m[2] ?? "")
      .replace(/\s+/g, " ")
      .replace(/`?\[[^\]]*\]`?/g, "")
      .replace(/[`*_]/g, "")
      // "- **L-1** — the loss" leaves the dash on the text half once the id is
      // stripped from the title half; without this the row renders "L-1 — — the loss"
      .replace(/^[—–-]\s*/, "")
      .trim();
    out.push({ id: m[1]!, title, text });
  }
  return out;
};
const losses = parseLH("L");
const hazards = parseLH("H");
/**
 * How many findings reach each hazard. `linksTo` is the recorded linkage and is
 * always preferred — but plenty of real analyses never fill it in, and a column of
 * zeros beside findings whose own statements say "leading to H-3" is not a missing
 * number, it is a WRONG one. So when no finding records a link, fall back to the
 * hazard ids the statements themselves name. That is a derivation from the artifact,
 * not a guess, and the table says which of the two produced the column.
 */
const linkedCount = findings.filter((c) => (c.linksTo ?? []).length).length;
const hazardsIn = (c: Cell): string[] =>
  linkedCount ? (c.linksTo ?? []) : [...new Set((c.statement ?? "").match(/\bH-\d+\b/g) ?? [])];
const reachSource = linkedCount ? "recorded links" : "hazard ids named in each finding";
const hazCount = new Map<string, { n: number; worst: number }>();
for (const c of findings)
  for (const h of hazardsIn(c)) {
    const cur = hazCount.get(h) ?? { n: 0, worst: 9 };
    cur.n++;
    const b = bandOf.get(c.id);
    if (b && b < cur.worst) cur.worst = b;
    hazCount.set(h, cur);
  }

const scorecard = readJson<any>("review-scorecard.json");
const reviewed = !!(scorecard?.passed && scorecard?.independentReview);

const model = readJson<any>("model.json");
const title = titleOverride ?? plan?.system ?? grid.system ?? model?.system ?? "STPA Threat Model";
const reportHref = existsSync(join(dir, "REPORT.html")) ? "REPORT.html" : null;

// ── the page ──────────────────────────────────────────────────────────────────
const qualifiers: string[] = [];
if (!reviewed)
  qualifiers.push(
    `<div class="q bad"><b>NOT INDEPENDENTLY REVIEWED.</b> No second model has adversarially reviewed these findings, so every finding and every band below is a <em>draft</em>, not a verdict. Run <code>stpa verify</code> after the review pass before circulating this page.</div>`,
  );
if (missingSections.length)
  qualifiers.push(
    `<div class="q bad"><b>THE ANALYSIS IS INCOMPLETE — ${missingSections.length} of ${SECTIONS.length} sections are absent:</b> ${missingSections.map((x) => esc(x.label)).join(", ")}. The findings below are real, but nothing here can tell you whether they are the <em>important</em> ones.</div>`,
  );
if (scopeBreach)
  qualifiers.push(
    `<div class="q bad"><b>SCOPE NOT DELIVERED AS REQUESTED.</b> A full-surface analysis was asked for; ${modeledCAs} of ${candidateCAs} control actions were modeled. The ${candidateCAs! - modeledCAs} unmodeled action(s) are outstanding work, not a declared boundary.</div>`,
  );
if (surfacePct !== null && surfacePct < 100)
  qualifiers.push(
    `<div class="q"><b>GRID COVERAGE IS NOT SYSTEM COVERAGE.</b> ${modeledCAs} of ${candidateCAs} candidate control actions were modeled (${surfacePct.toFixed(0)}% of the surface). The ${pct.toFixed(1)}% below describes the analysis of that subset only.</div>`,
  );
else if (surfacePct === null)
  qualifiers.push(
    `<div class="q"><b>SURFACE COVERAGE NOT DECLARED.</b> The model does not record how many candidate control actions this system has, so the coverage figure below cannot be read as system coverage.</div>`,
  );
if (openCells.length)
  qualifiers.push(`<div class="q"><b>${openCells.length} cell(s) remain OPEN.</b> An open cell is a hole in the analysis, not a pass.</div>`);
if (unbound.length)
  qualifiers.push(
    `<div class="q"><b>${unbound.length} finding(s) are UNBOUND</b> — they cite no declared process-model variable or feedback channel, so they are not yet grounded in this system's control structure and do not count toward coverage.</div>`,
  );

const stat = (v: string, k: string, cls = "") => `<div class="stat ${cls}"><div class="v">${v}</div><div class="k">${k}</div></div>`;
const statsHtml = `<div class="stats">
  ${stat(String(findings.length), "findings")}
  ${stat(String(band1.length), "band 1 — fix first", band1.length ? "urgent" : "")}
  ${stat(`${pct.toFixed(0)}%`, "analysis complete")}
  ${stat(String(plan?.metrics?.rootCauses ?? plan?.clusters?.length ?? "—"), "root causes")}
  ${stat(String(plan?.metrics?.wave1Size ?? (plan?.waves?.[0]?.items?.length ?? "—")), "in wave 1")}
</div>`;

const stakeHtml =
  losses.length || hazards.length
    ? `<section><h2>What is at stake</h2>
  ${
    losses.length
      ? `<ul class="losses">${losses
          .map((l) => `<li><span class="id">${esc(l.id)}</span> ${l.title ? `<strong>${esc(l.title)}</strong>` : ""}${l.text ? ` — ${esc(l.text)}` : ""}</li>`)
          .join("")}</ul>`
      : ""
  }
  ${
    hazards.length
      ? `<table class="hz"><thead><tr><th>Hazard — an unsafe system state, not an attack</th><th title="from ${esc(reachSource)}">Findings</th><th>Worst</th></tr></thead><tbody>${[...hazards]
          .sort((a, b) => (hazCount.get(b.id)?.n ?? 0) - (hazCount.get(a.id)?.n ?? 0))
          .slice(0, 6)
          .map((h) => {
            const hc = hazCount.get(h.id);
            const worst = hc && hc.worst < 9 ? hc.worst : null;
            return `<tr><td><span class="id">${esc(h.id)}</span> ${esc(h.title || h.text)}</td><td class="c">${hc?.n ?? 0}</td><td class="c">${worst ? `<span class="band b${worst}">${worst}</span>` : "—"}</td></tr>`;
          })
          .join("")}</tbody></table>
      <p class="note">Findings column counted from ${esc(reachSource)}.</p>`
      : ""
  }
</section>`
    : "";

// The findings a reader must not miss: wave 1 if the plan ran, else band-1/2, else
// the first few findings. Always says which rule produced the list, because "top
// findings" chosen by an undisclosed rule is how a summary quietly editorialises.
const wave1 = plan?.waves?.find((w) => w.wave === 1)?.items ?? [];
const picked = wave1.length
  ? { items: wave1, why: "Wave 1 of the engineering plan — ranked by band, then by leverage." }
  : {
      items: findings
        .filter((c) => (bandOf.get(c.id) ?? 9) <= 2)
        .map((c) => itemOf.get(c.id) ?? { id: c.id, statement: c.statement, controller: c.controller, band: bandOf.get(c.id) })
        .slice(0, 5),
      why: "Band 1 and band 2 findings. No engineering plan was generated — run <code>stpa plan</code> for a ranked order.",
    };

const findingsHtml = picked.items.length
  ? `<section><h2>What to fix first</h2>
  <p class="lede">${picked.why}</p>
  ${picked.items
    .slice(0, 6)
    .map(
      (it: any) => `<div class="f">
      <div class="fh">${it.band ? `<span class="band b${it.band}">${it.band}</span>` : ""}<span class="fid">${esc(it.id ?? "")}</span>${it.controller ? `<span class="muted">${esc(it.controller)}</span>` : ""}${it.effort ? `<span class="chip">${esc(it.effort)} effort</span>` : ""}</div>
      ${it.statement ? `<p class="fs">${esc(it.statement)}</p>` : ""}
      ${it.fix ? `<p class="fx"><b>Fix</b> — ${esc(it.fix)}</p>` : ""}
      ${it.location ? `<p class="loc"><b>Where</b> — <code>${esc(it.location)}</code></p>` : ""}
    </div>`,
    )
    .join("")}
</section>`
  : "";

const clusters = [...(plan?.clusters ?? [])].sort((a, b) => (b.leverage ?? 0) - (a.leverage ?? 0)).slice(0, 3);
const rootHtml = clusters.length
  ? `<section><h2>The few changes that close the most</h2>
  <p class="lede">Root causes ranked by leverage — how many findings each one closes. Fixing these ${clusters.length} resolves ${clusters.reduce((n, c) => n + (c.findings?.length ?? 0), 0)} of ${findings.length} findings.</p>
  ${clusters
    .map(
      (c) => `<div class="rc">
      <div class="fh"><span class="fid">${esc(c.id)}</span><span class="chip lev">closes ${c.findings?.length ?? c.leverage ?? 0}</span>${c.effort ? `<span class="chip">${esc(c.effort)} effort</span>` : ""}</div>
      <p class="rcn"><strong>${esc(c.name)}</strong></p>
      ${c.summary ? `<p class="fs">${esc(c.summary)}</p>` : ""}
      ${c.fix ? `<p class="fx"><b>Fix</b> — ${esc(c.fix)}</p>` : ""}
    </div>`,
    )
    .join("")}
</section>`
  : "";

const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} — STPA Executive Summary</title>
<style>
:root{
  --bg:#fbfbfa; --panel:#fff; --ink:#16181d; --muted:#5c6270; --line:#e3e5ea;
  --accent:#1f4ed8; --uca:#b42318; --uca-bg:#fef3f2; --tomb:#475467; --tomb-bg:#f4f5f7;
  --open:#b54708; --open-bg:#fffaeb; --ok:#067647;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0e1014; --panel:#15181e; --ink:#e6e8ec; --muted:#9aa2b1; --line:#262b34;
  --accent:#7da2ff; --uca:#ff8a80; --uca-bg:#2a1614; --tomb:#9aa2b1; --tomb-bg:#1a1e25;
  --open:#f0b429; --open-bg:#2a2211; --ok:#5ed6a4;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.65 ui-sans-serif,-apple-system,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:860px;margin:0 auto;padding:44px 24px 80px}
header.top{border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:24px}
.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-weight:650}
h1{font-size:28px;line-height:1.25;margin:8px 0 6px;letter-spacing:-.02em}
.sub{color:var(--muted);font-size:13px}
h2{font-size:16px;margin:34px 0 12px;letter-spacing:-.01em}
section{margin:0}
p.lede{color:var(--muted);font-size:13.5px;margin:0 0 14px}
.q{background:var(--open-bg);border:1px solid var(--open);color:var(--open);border-radius:10px;
  padding:12px 16px;margin:10px 0;font-size:13px;line-height:1.55}
.q.bad{background:var(--uca-bg);border-color:var(--uca);color:var(--uca)}
.q b{font-weight:750}
.q code{font-size:12px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:22px 0 6px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:13px 12px;text-align:center}
.stat.urgent{border-color:var(--uca)}
.stat .v{font-size:23px;font-weight:750;letter-spacing:-.02em}
.stat.urgent .v{color:var(--uca)}
.stat .k{font-size:10.5px;color:var(--muted);margin-top:3px;line-height:1.35}
@media (max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}}
ul.losses{list-style:none;padding:0;margin:0 0 18px}
ul.losses li{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:11px 14px;margin-bottom:8px;font-size:13.5px;line-height:1.55}
.id{display:inline-block;font-weight:750;font-size:11px;color:var(--accent);
  background:var(--tomb-bg);border:1px solid var(--line);border-radius:5px;padding:1px 6px;margin-right:6px}
table.hz{width:100%;border-collapse:collapse;background:var(--panel);
  border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px}
table.hz th{text-align:left;font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--muted);padding:9px 13px;border-bottom:1px solid var(--line);font-weight:650}
table.hz td{padding:10px 13px;border-bottom:1px solid var(--line);vertical-align:top}
table.hz tr:last-child td{border-bottom:none}
table.hz td.c,table.hz th:nth-child(2),table.hz th:nth-child(3){text-align:center}
.band{display:inline-block;min-width:19px;text-align:center;font-size:11px;font-weight:750;
  border-radius:5px;padding:1px 6px}
.b1{background:var(--uca-bg);color:var(--uca);border:1px solid var(--uca)}
.b2{background:var(--open-bg);color:var(--open);border:1px solid var(--open)}
.b3{background:var(--tomb-bg);color:var(--tomb);border:1px solid var(--line)}
.b4{background:transparent;color:var(--muted);border:1px dashed var(--line)}
.f,.rc{background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:14px 16px;margin-bottom:10px}
.fh{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:7px}
.fid{font-weight:700;font-size:12.5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.muted{color:var(--muted);font-size:12.5px}
.chip{font-size:10.5px;color:var(--muted);background:var(--tomb-bg);border:1px solid var(--line);
  border-radius:5px;padding:1px 7px;font-weight:600}
.chip.lev{color:var(--accent);border-color:var(--accent)}
.fs{margin:0 0 8px;font-size:13.5px;line-height:1.6}
.rcn{margin:0 0 6px;font-size:14px}
.fx{margin:0 0 6px;font-size:13px;line-height:1.55;color:var(--ink)}
.fx b,.loc b{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.loc{margin:0;font-size:12px}
.loc code{font-size:11.5px;background:var(--tomb-bg);border:1px solid var(--line);
  border-radius:5px;padding:2px 6px;overflow-wrap:break-word}
p.note{color:var(--muted);font-size:11.5px;margin:7px 0 0}
footer{margin-top:40px;padding-top:20px;border-top:1px solid var(--line);
  color:var(--muted);font-size:12.5px}
footer a{color:var(--accent);font-weight:650}
.more{background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:14px 18px;margin-top:26px;font-size:13.5px}
@media print{body{background:#fff}.wrap{max-width:none;padding:0}.f,.rc,.stat,table.hz{break-inside:avoid}}
</style></head><body><div class="wrap">
<header class="top">
  <div class="eyebrow">STPA threat model — executive summary</div>
  <h1>${esc(title)}</h1>
  <div class="sub">${grid.totalCells} questions asked (${modeledCAs} control actions × 4 ways to be unsafe) · generated ${new Date().toISOString().slice(0, 10)}</div>
</header>
${qualifiers.join("\n")}
${statsHtml}
${stakeHtml}
${findingsHtml}
${rootHtml}
${
  reportHref
    ? `<div class="more"><b>This is the summary.</b> The full analysis — every unsafe control action, the loss scenarios behind each finding, the security constraints with runnable probes, and the complete engineering plan — is in <a href="${reportHref}">${esc(reportHref)}</a>, beside this file.</div>`
    : `<div class="more"><b>This is the summary.</b> Run <code>stpa report</code> to generate the full analysis beside it.</div>`
}
<footer>
  <p>STPA (System-Theoretic Process Analysis, Leveson &amp; Thomas) with its security adaptation STPA-Sec. It looks for losses that happen when <em>every component works as designed</em> — broken authorization, tenant leaks, stale permissions, bypass paths. It is not a scanner: no CVEs, no injection, no dependency audit.</p>
  <p>Generated from <code>${esc(basename(dir))}/</code>. Every figure on this page is computed from the analysis artifacts, not written by hand.</p>
</footer>
</div></body></html>`;

try {
  writeFileSync(outPath, html);
} catch (e) {
  die(`cannot write ${outPath}: ${(e as Error).message}`);
}
console.error(
  `wrote ${outPath}  (${findings.length} findings, ${band1.length} band-1, ${pct.toFixed(1)}% coverage` +
    `${qualifiers.length ? `, ${qualifiers.length} qualifier(s) carried` : ""})`,
);
