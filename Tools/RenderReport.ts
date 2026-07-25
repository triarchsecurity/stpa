#!/usr/bin/env bun
/**
 * RenderReport.ts — the default terminal output of an STPA analysis.
 *
 * Reads an analysis directory (`.stpa/` by default) and emits a single
 * self-contained REPORT.html: no CDN, no external fonts, no scripts fetched at
 * runtime. It opens correctly from a file:// URL on a machine with no network,
 * which is the point — a threat model that only renders on someone's intranet is
 * a threat model that does not get read.
 *
 * Why a tool and not a prompt: the coverage figure, the finding counts, the
 * concentration qualifier and the tombstone/finding split are all derived from
 * grid.json arithmetic. Anything derived deterministically should not be
 * re-narrated by a model each run — it drifts, and this is exactly the number
 * whose integrity the rest of the skill works to protect.
 *
 * Usage:
 *   bun RenderReport.ts [analysis-dir] [-o out.html] [--title "..."]
 *
 * Inputs (all optional except grid.json — missing sections are simply omitted):
 *   model.json  01-scope.md  02-control-structure.md  grid.json
 *   03-ucas.md  04-scenarios.md  05-constraints.md
 */

import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * The Handbook's type names ("not provided", "provided") describe the CONTROL
 * ACTION. Read cold by someone who has not read the Handbook, they sound like
 * complaints about the analysis itself — "not provided" reads as a missing input
 * to the modelling exercise. These labels say what goes wrong in the SYSTEM.
 * The Handbook term is kept alongside so the mapping stays honest.
 */
const UCA_TYPE_LABEL: Record<string, string> = {
  "not-provided": "Required control never happens",
  provided: "Unsafe action is performed",
  "timing-order": "Right action, wrong moment",
  duration: "Right action, wrong duration",
};
const UCA_TYPE_HINT: Record<string, string> = {
  "not-provided": "a check, revocation, or record the system must do — and doesn't",
  provided: "an action the system performs in a context where it causes harm",
  "timing-order": "too early, too late, or out of sequence with something else",
  duration: "held open too long, or stopped before it finished doing its job",
};
const UCA_TYPE_TERM: Record<string, string> = {
  "not-provided": "not provided",
  provided: "provided",
  "timing-order": "wrong timing / order",
  duration: "too long / stopped too soon",
};

interface Cell {
  id: string;
  controlActionId: string;
  controlAction: string;
  controller: string;
  ucaType: string;
  state: "open" | "uca" | "tombstone";
  statement?: string;
  reason?: string;
  bindsTo?: string[];
  linksTo?: string[];
}
interface Grid {
  system: string;
  generated?: string;
  totalCells: number;
  scope?: { candidateControlActions?: number; selectionCriteria?: string; deferred?: { name: string; reason: string }[] };
  declaredElements?: string[];
  cells: Cell[];
}

function die(m: string, code = 1): never {
  console.error(m);
  process.exit(code);
}

const esc = (s: string) =>
  String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

/** Inline markdown: code, bold, italic, links. Applied after escaping. */
function inline(s: string): string {
  return esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
}

/**
 * Deliberately small markdown subset — headings, tables, lists, blockquotes,
 * fenced code (mermaid rendered as a labelled diagram source block, since a
 * self-contained file cannot pull a renderer). Enough for the artifacts this
 * skill writes; not a general-purpose converter.
 */
function md(src: string): string {
  const lines = src.split("\n");
  const out: string[] = [];
  let i = 0;
  let inList = false;
  const closeList = () => {
    if (inList) {
      out.push("</ul>");
      inList = false;
    }
  };

  while (i < lines.length) {
    const line = lines[i]!;

    if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const buf: string[] = [];
      i++;
      while (i < lines.length && !lines[i]!.startsWith("```")) buf.push(lines[i++]!);
      i++;
      closeList();
      const label = lang === "mermaid" ? '<div class="diagram-label">control structure — mermaid source</div>' : "";
      out.push(`<div class="codeblock">${label}<pre>${esc(buf.join("\n"))}</pre></div>`);
      continue;
    }

    if (/^\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\|[\s:|-]+\|\s*$/.test(lines[i + 1]!)) {
      closeList();
      /**
       * Split a markdown table row on cell delimiters, NOT on every pipe.
       * Shell commands in the probe columns are full of pipes (`rg x | wc -l`),
       * and splitting inside a code span invents phantom columns that spill the
       * table sideways. Backslash-escaped pipes are literal too.
       */
      const cells = (r: string) => {
        const body = r.trim().replace(/^\||\|$/g, "");
        const out: string[] = [];
        let cur = "";
        let inCode = false;
        for (let k = 0; k < body.length; k++) {
          const ch = body[k]!;
          if (ch === "\\" && body[k + 1] === "|") {
            cur += "|";
            k++;
            continue;
          }
          if (ch === "`") inCode = !inCode;
          if (ch === "|" && !inCode) {
            out.push(cur.trim());
            cur = "";
            continue;
          }
          cur += ch;
        }
        out.push(cur.trim());
        return out;
      };
      const head = cells(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && /^\|.*\|\s*$/.test(lines[i]!)) rows.push(cells(lines[i++]!));
      out.push(
        `<div class="tablewrap"><table><thead><tr>${head.map((h) => `<th>${inline(h)}</th>`).join("")}</tr></thead><tbody>` +
          rows.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("") +
          `</tbody></table></div>`,
      );
      continue;
    }

    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      closeList();
      const lvl = h[1]!.length;
      out.push(`<h${lvl}>${inline(h[2]!)}</h${lvl}>`);
      i++;
      continue;
    }

    if (/^>\s?/.test(line)) {
      closeList();
      const buf: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i]!)) buf.push(lines[i++]!.replace(/^>\s?/, ""));
      out.push(`<blockquote>${inline(buf.join(" "))}</blockquote>`);
      continue;
    }

    if (/^[-*]\s+/.test(line)) {
      if (!inList) {
        out.push("<ul>");
        inList = true;
      }
      let item = line.replace(/^[-*]\s+/, "");
      // fold indented soft-wrapped continuation lines into the same list item
      while (
        i + 1 < lines.length &&
        /^\s+\S/.test(lines[i + 1]!) &&
        !/^\s*[-*]\s+/.test(lines[i + 1]!) &&
        !lines[i + 1]!.startsWith("```")
      ) {
        item += " " + lines[++i]!.trim();
      }
      out.push(`<li>${inline(item)}</li>`);
      i++;
      continue;
    }

    if (!line.trim()) {
      closeList();
      i++;
      continue;
    }

    // paragraph: a markdown soft-wrap (single newline) is one paragraph, not many.
    // Accumulate consecutive plain lines until a blank line or a block element.
    closeList();
    const para: string[] = [line];
    while (
      i + 1 < lines.length &&
      lines[i + 1]!.trim() &&
      !/^[-*]\s+/.test(lines[i + 1]!) &&
      !/^#{1,6}\s/.test(lines[i + 1]!) &&
      !/^>\s/.test(lines[i + 1]!) &&
      !lines[i + 1]!.startsWith("```") &&
      !/^\|.*\|\s*$/.test(lines[i + 1]!)
    ) {
      para.push(lines[++i]!);
    }
    out.push(`<p>${inline(para.join(" "))}</p>`);
    i++;
  }
  closeList();
  return out.join("\n");
}

// ── inputs ────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) {
  die(
    [
      "RenderReport.ts — self-contained HTML report for an STPA analysis",
      "",
      "Usage: bun RenderReport.ts [analysis-dir] [-o out.html] [--title \"...\"]",
      "",
      "Reads grid.json (required) plus model.json and any 0*.md artifacts present.",
    ].join("\n"),
    2,
  );
}
const dir = resolve(argv.find((a) => !a.startsWith("-") && argv[argv.indexOf(a) - 1] !== "-o" && argv[argv.indexOf(a) - 1] !== "--title") ?? ".stpa");
const oIdx = argv.indexOf("-o");
const outPath = oIdx !== -1 ? argv[oIdx + 1]! : join(dir, "REPORT.html");
const tIdx = argv.indexOf("--title");
const titleOverride = tIdx !== -1 ? argv[tIdx + 1] : undefined;

const read = (f: string) => (existsSync(join(dir, f)) ? readFileSync(join(dir, f), "utf8") : null);
const gridRaw = read("grid.json");
if (!gridRaw) die(`no grid.json in ${dir} — run the analysis first (Steps 2–3).`);
let grid: Grid;
try {
  grid = JSON.parse(gridRaw);
} catch (e) {
  die(`grid.json is not valid JSON: ${(e as Error).message}`);
}

const declared = new Set(grid.declaredElements ?? []);
const isBound = (c: Cell) => (c.bindsTo ?? []).some((r) => declared.has(r));
const findings = grid.cells.filter((c) => c.state === "uca");
const bound = findings.filter(isBound);
const unbound = findings.filter((c) => !isBound(c));
const tombs = grid.cells.filter((c) => c.state === "tombstone");
const open = grid.cells.filter((c) => c.state === "open");
const resolved = bound.length + tombs.length;
const pct = grid.totalCells ? (resolved / grid.totalCells) * 100 : 0;

// same concentration rule as UcaGrid.ts — the qualifier must travel with the figure
const counts = new Map<string, number>();
for (const c of bound) for (const id of new Set((c.bindsTo ?? []).filter((r) => declared.has(r)))) counts.set(id, (counts.get(id) ?? 0) + 1);
const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
const topShare = bound.length && top ? top[1] / bound.length : 0;
const concentrated = bound.length >= 4 && (counts.size <= 1 || topShare >= 0.8);

/**
 * A report that silently omits its missing sections looks finished. This is the
 * same silent-degradation defect the toolkit exists to find, so the report says
 * what is absent, at the top, before anyone reads a finding.
 */
const SECTIONS: { file: string; label: string; why: string; weight: "core" | "supporting" }[] = [
  { file: "01-scope.md", label: "Scope, losses and hazards", why: "without it, findings have nothing to be severe *about*", weight: "core" },
  { file: "02-control-structure.md", label: "Control structure", why: "the diagram and process-model tables readers need to check the reasoning", weight: "core" },
  { file: "04-scenarios.md", label: "Loss scenarios", why: "why each finding occurs (Part A) and why a CORRECT control action fails to land (Part B — the bypass class, which Step 3 structurally cannot find). This is where mitigations come from", weight: "core" },
  { file: "07-chains.md", label: "Composition", why: "reachability is a property of a finding GIVEN what the others grant an attacker — without it an R0 chain ships rated R3. Run `stpa compose`", weight: "core" },
  { file: "05-constraints.md", label: "Security constraints", why: "the MUST-NOT assertions and probes that make findings testable", weight: "core" },
  { file: "06-remediation.json", label: "Engineering plan", why: "severity, effort, file locations, root causes and waves — run `stpa plan`", weight: "core" },
];
const missingSections = SECTIONS.filter((x) => !read(x.file));


const modeledCAs = grid.totalCells / 4;
const candidateCAs = (grid as any).scope?.candidateControlActions as number | undefined;
const surfacePct = candidateCAs && candidateCAs > 0 ? (modeledCAs / candidateCAs) * 100 : null;

/**
 * The scope CONTRACT, distinct from scope coverage. Coverage says how much was
 * modeled; the contract says how much was asked for. A 60% that was requested is
 * a boundary; a 60% that was not is an unfinished analysis, and only the contract
 * distinguishes them.
 *
 * Declared HERE, after candidateCAs — it read the binding before initialization
 * when it sat above, which is a TDZ crash rather than a wrong number. Worth the
 * comment: a gate that throws is a gate nobody can ship past, which is the safe
 * failure direction, but it still has to run.
 */
const requestedScope: string | undefined = (grid as any).scope?.requested;
const scopeBreach =
  requestedScope === "full" && typeof candidateCAs === "number" && modeledCAs < candidateCAs;

const model = (() => {
  const r = read("model.json");
  if (!r) return null;
  try {
    return JSON.parse(r);
  } catch {
    return null;
  }
})();

const title = titleOverride ?? grid.system ?? "STPA Threat Model";

// ── findings, grouped by control action, then collapsed by plane ───────────
const byCA = new Map<string, Cell[]>();
for (const c of grid.cells) {
  if (!byCA.has(c.controlActionId)) byCA.set(c.controlActionId, []);
  byCA.get(c.controlActionId)!.push(c);
}

const prettyPlane = (p: string) => p.replace(/[-_]/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());

// one card (table of the 4 UCA-type cells) per control action
const caCardHtml = (id: string, cells: Cell[]): string => {
  const first = cells[0]!;
  const rows = cells
    .map((c) => {
      const state =
        c.state === "uca"
          ? isBound(c)
            ? `<span class="pill pill-uca">UCA</span>`
            : `<span class="pill pill-unbound">UCA · unbound</span>`
          : c.state === "tombstone"
            ? `<span class="pill pill-tomb">no hazard</span>`
            : `<span class="pill pill-open">OPEN</span>`;
      const body = c.state === "uca" ? c.statement : c.state === "tombstone" ? c.reason : "—";
      const binds = (c.bindsTo ?? []).map((b) => `<code>${esc(b)}</code>`).join(" ");
      const links = (c.linksTo ?? []).map((b) => `<code>${esc(b)}</code>`).join(" ");
      return `<tr class="${c.state}"><td class="ttype">${esc(UCA_TYPE_LABEL[c.ucaType] ?? c.ucaType)}</td><td>${state}</td><td class="tbody">${inline(body ?? "")}</td><td class="tmeta">${binds}</td><td class="tmeta">${links}</td></tr>`;
    })
    .join("");
  const n = cells.filter((c) => c.state === "uca").length;
  return `<section class="ca"><h3><span class="caid">${esc(id)}</span> ${esc(first.controlAction)}<span class="ctrl">${esc(first.controller)}</span><span class="cacount">${n} finding${n === 1 ? "" : "s"}</span></h3><div class="tablewrap"><table class="grid"><thead><tr><th>UCA type</th><th>State</th><th>Statement / reason</th><th>Binds to</th><th>Hazards</th></tr></thead><tbody>${rows}</tbody></table></div></section>`;
};

// group control actions by their plane; falls back to one group when cells carry no plane
const planeSeq: string[] = [];
const caByPlane = new Map<string, string[]>();
for (const id of byCA.keys()) {
  const pl = (byCA.get(id)!.find((c) => (c as any).plane)?.["plane" as keyof Cell] as unknown as string) || "";
  const key = pl || "All control actions";
  if (!caByPlane.has(key)) {
    caByPlane.set(key, []);
    planeSeq.push(key);
  }
  caByPlane.get(key)!.push(id);
}
// findingCards defined after bandOf (needs band data for the band-1 badge)

const pmRows = (model?.processModels ?? [])
  .flatMap((pm: any) =>
    (pm.variables ?? []).map(
      (v: any) =>
        `<tr><td><code>${esc(v.id)}</code></td><td>${esc(pm.controller)}</td><td>${esc(v.belief)}</td><td>${esc(v.sourcedFrom ?? "")}</td><td>${esc(v.staleness ?? "")}</td></tr>`,
    ),
  )
  .join("");

const fbRows = (model?.feedback ?? [])
  .map(
    (f: any) =>
      `<tr><td><code>${esc(f.id)}</code></td><td>${esc(f.from)} → ${esc(f.to)}</td><td>${esc(f.signal)}</td></tr>`,
  )
  .join("");

// ── engineering plan (06-remediation.json, produced by Prioritize.ts) ──────
const plan = (() => {
  const r = read("06-remediation.json");
  if (!r) return null;
  try {
    return JSON.parse(r);
  } catch {
    return null;
  }
})();

const BAND_LABEL: Record<number, string> = {
  1: "Fix before ship",
  2: "Fix this cycle",
  3: "Constrain &amp; schedule",
  4: "Accept in writing",
};
const EFFORT_LABEL: Record<string, string> = { S: "hours", M: "days", L: "weeks" };
const REACH_TITLE: Record<string, string> = {
  R0: "R0 — adversary creates the context directly",
  R1: "R1 — adversary induces it through normal interaction",
  R2: "R2 — adversary waits for it to arise",
  R3: "R3 — requires a prior foothold",
  R4: "R4 — requires an insider or supply-chain compromise",
};

const planHtml = (() => {
  if (!plan) return "";
  const m = plan.metrics;
  const top = plan.clusters?.[0];

  const waveBlocks = (plan.waves ?? [])
    .filter((w: any) => w.items.length)
    .map((w: any) => {
      const rows = w.items
        .map(
          (it: any) => `<tr>
        <td><code>${esc(it.id)}</code>${it.cluster ? `<div class="rcref">${esc(it.cluster)}</div>` : ""}</td>
        <td class="bandcell"><span class="band band-${it.band}">${it.band}</span>
          <div class="bandwhy"><span class="sev sev-${esc(it.severity)}">${esc(it.severity)}</span> <span class="mult">×</span> <span class="reach" title="${esc(REACH_TITLE[it.reachability] ?? "")}">${esc(it.reachability)}</span></div></td>
        <td><span class="eff eff-${it.effort}">${esc(it.effort)}</span> <span class="effw">${EFFORT_LABEL[it.effort] ?? ""}</span></td>
        <td class="loc">${it.location ? `<code>${esc(it.location)}</code>` : '<span class="muted">unlocated</span>'}</td>
        <td class="fix">${esc(it.fix)}</td>
        <td class="probe">${it.probe ? `<code>${esc(it.probe)}</code>` : '<span class="muted">no probe</span>'}</td>
      </tr>`,
        )
        .join("");
      return `<h3 class="wave w${w.wave}">Wave ${w.wave} — ${esc(w.label)} <span class="cacount">${w.items.length} item${w.items.length === 1 ? "" : "s"}</span></h3>
      <div class="tablewrap"><table class="plan"><colgroup><col class="c-id"><col class="c-bandd"><col class="c-eff"><col class="c-loc"><col class="c-fix"><col class="c-probe"></colgroup><thead><tr><th>ID</th><th>Band<span class="thsub">severity × reach</span></th><th>Effort</th><th>Where</th><th>Do this</th><th>Verify with</th></tr></thead><tbody>${rows}</tbody></table></div>`;
    })
    .join("");

  const clusterRows = (plan.clusters ?? [])
    .map(
      (c: any) => `<tr>
      <td><span class="rcid">${esc(c.id)}</span></td>
      <td><strong>${esc(c.name)}</strong>${c.summary ? `<div class="muted csum">${esc(c.summary)}</div>` : ""}</td>
      <td class="lev" style="text-align:center"><span class="levn">${c.leverage}</span><span class="muted"> / ${m.findings}</span></td>
      <td><span class="band band-${c.bestBand}">${c.bestBand}</span></td>
      <td><span class="eff eff-${c.effort}">${esc(c.effort)}</span> <span class="effw">${EFFORT_LABEL[c.effort] ?? ""}</span></td>
      <td class="fix">${esc(c.fix ?? "—")}</td>
    </tr>`,
    )
    .join("");

  return `<section id="plan"><details class="fold plan-block"><summary><span class="foldh">10 · Engineering plan</span><span class="gcount"><span class="gbadge">${m.findings} findings → ${m.rootCauses || (plan.clusters ?? []).length} root causes</span>${m.wave1Size ? `<span class="gbadge b1">Wave 1 · ${m.wave1Size} item${m.wave1Size === 1 ? "" : "s"}</span>` : ""}</span></summary><div class="foldbody">
  <p class="lede"><strong>${m.findings} findings collapse to ${m.rootCauses || (plan.clusters ?? []).length} root causes.</strong>
  ${m.bands.band1} band-1, ${m.bands.band2} band-2. ${m.quickWins} quick win${m.quickWins === 1 ? "" : "s"} (band&nbsp;≤2, hours of work).
  Wave&nbsp;1 is ${m.wave1Size} item${m.wave1Size === 1 ? "" : "s"} and closes ${m.wave1CoversUrgentPct}% of everything band-2-or-worse.</p>

  <div class="planstats">
    <div class="pstat"><div class="k">Root causes</div><div class="v">${m.rootCauses || (plan.clusters ?? []).length}</div><div class="h">from ${m.findings} findings</div></div>
    <div class="pstat"><div class="k">Max leverage</div><div class="v">${m.maxLeverage}</div><div class="h">closed by one fix (${(m.concentration * 100).toFixed(0)}%)</div></div>
    <div class="pstat"><div class="k">Quick wins</div><div class="v">${m.quickWins}</div><div class="h">band ≤2, effort S</div></div>
    <div class="pstat"><div class="k">Band 1 / 2</div><div class="v">${m.bands.band1} / ${m.bands.band2}</div><div class="h">ship-blocking / this cycle</div></div>
    <div class="pstat"><div class="k">Located</div><div class="v">${m.locatedPct}%</div><div class="h">have a file:line</div></div>
    <div class="pstat"><div class="k">Probed</div><div class="v">${m.probedPct}%</div><div class="h">have a runnable check</div></div>
  </div>
  <p class="caveat">Band is severity × context reachability — a toolkit extension, <strong>not a probability and not CVSS-comparable</strong>. It orders this analysis's findings for this team and nothing else. Effort is an analyst estimate: S ≈ hours, M ≈ days, L ≈ weeks.</p>

  ${
    top && top.leverage > 1
      ? `<div class="leadfix"><div class="k">Highest-leverage move</div>
      <h3>${esc(top.name)}</h3>
      <p><strong>One change closes ${top.leverage} of ${m.findings} findings.</strong> Effort ${esc(top.effort)} · ${EFFORT_LABEL[top.effort] ?? ""}.</p>
      ${top.summary ? `<p>${esc(top.summary)}</p>` : ""}
      ${top.fix ? `<p class="do"><strong>Do this:</strong> ${esc(top.fix)}</p>` : ""}</div>`
      : ""
  }

  <h3>Root causes, by leverage</h3>
  <div class="tablewrap"><table class="plan rc"><colgroup><col class="c-rcid"><col class="c-rcname"><col class="c-lev"><col class="c-band"><col class="c-eff"><col class="c-fix"></colgroup><thead><tr><th>ID</th><th>Root cause</th><th>Closes</th><th>Worst band</th><th>Effort</th><th>The one change</th></tr></thead><tbody>${clusterRows}</tbody></table></div>

  ${waveBlocks}

  <h3>Legend</h3>
  <div class="tablewrap"><table><thead><tr><th>Band</th><th>Means</th><th>Reachability</th><th>Means</th></tr></thead><tbody>
  <tr><td><span class="band band-1">1</span></td><td>${BAND_LABEL[1]}</td><td><code>R0</code></td><td>adversary creates the context directly</td></tr>
  <tr><td><span class="band band-2">2</span></td><td>${BAND_LABEL[2]}</td><td><code>R1</code></td><td>adversary induces it through normal interaction</td></tr>
  <tr><td><span class="band band-3">3</span></td><td>${BAND_LABEL[3]}</td><td><code>R2</code></td><td>adversary waits for it to arise</td></tr>
  <tr><td><span class="band band-4">4</span></td><td>${BAND_LABEL[4]}</td><td><code>R3</code></td><td>requires a prior foothold</td></tr>
  <tr><td></td><td></td><td><code>R4</code></td><td>requires an insider or supply-chain compromise</td></tr>
  </tbody></table></div>
  </div></details></section>`;
})();

// drop a doc's own leading heading — the collapsible summary already labels the section
const dropTopHeading = (m: string) => m.replace(/^\s*#{1,6}\s+.*\r?\n?/, "");
const section = (id: string, heading: string, body: string | null, open = false) =>
  body
    ? `<section id="${id}"><details class="fold"${open ? " open" : ""}><summary><span class="foldh">${esc(heading)}</span></summary><div class="foldbody doc">${md(dropTopHeading(body))}</div></details></section>`
    : "";

// Band per cell id, when a plan exists. Length = how many; colour = how bad.
// Colouring every bar the same red made the biggest category look like the worst
// one, which encodes count as severity — the wrong claim.
const bandOf = new Map<string, number>();
for (const w of plan?.waves ?? []) for (const it of w.items ?? []) bandOf.set(it.id, it.band);

// Per-plane collapsed groups: one <details> per plane, summary carries the counts
// so the reader sees the shape before opening. Collapsed by default; a big grid is
// a wall of tables otherwise.
const singlePlane = planeSeq.length === 1;
const findingCards = planeSeq
  .map((plane) => {
    const ids = caByPlane.get(plane)!;
    const cells = ids.flatMap((id) => byCA.get(id)!);
    const f = cells.filter((c) => c.state === "uca").length;
    const t = cells.filter((c) => c.state === "tombstone").length;
    const b1 = cells.filter((c) => bandOf.get(c.id) === 1).length;
    const cards = ids.map((id) => caCardHtml(id, byCA.get(id)!)).join("");
    const title = plane === "All control actions" ? plane : prettyPlane(plane);
    const badges =
      `<span class="gbadge f">${f} finding${f === 1 ? "" : "s"}</span>` +
      `<span class="gbadge t">${t} ruled out</span>` +
      (b1 ? `<span class="gbadge b1">${b1} band-1</span>` : "") +
      `<span class="gbadge">${ids.length} action${ids.length === 1 ? "" : "s"}</span>`;
    return `<details class="planegroup"${singlePlane ? " open" : ""}><summary><span class="foldh">${esc(title)}</span><span class="gcount">${badges}</span></summary><div class="pgbody">${cards}</div></details>`;
  })
  .join("");

// ── "What's at stake": the human layer — losses + hazards in plain language ──
// Parsed from 01-scope.md so it stays in sync with the analysis. Hazards are
// ranked by how many findings reach them, which turns the finding count into a
// map of which dangerous states are most live — readable without any code.
const scopeMd = read("01-scope.md") ?? "";
const parseLH = (letter: string): { id: string; title: string; text: string }[] => {
  const out: { id: string; title: string; text: string }[] = [];
  // capture the whole item, including soft-wrapped continuation lines, up to the
  // next list item / blank line / heading
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
      .trim();
    out.push({ id: m[1]!, title, text });
  }
  return out;
};
const losses = parseLH("L");
const hazards = parseLH("H");
const hazCount = new Map<string, { n: number; worst: number }>();
for (const c of findings)
  for (const h of c.linksTo ?? []) {
    const cur = hazCount.get(h) ?? { n: 0, worst: 9 };
    cur.n++;
    const b = bandOf.get(c.id);
    if (b && b < cur.worst) cur.worst = b;
    hazCount.set(h, cur);
  }
const atStakeHtml =
  losses.length || hazards.length
    ? `<section id="stake"><details class="fold stake" open><summary><span class="foldh">4 · What's at stake</span></summary><div class="foldbody">

  <p class="lede">The losses this system must avoid, and the hazardous states that lead to them. Everything below — the plan, the control structure, the ${findings.length} findings — exists to keep the system out of these states.</p>
  ${
    losses.length
      ? `<h3>Losses <span class="muted">— what would actually hurt, in business terms</span></h3>
  <ul class="stakelist">${losses.map((l) => `<li><span class="lid">${esc(l.id)}</span> ${l.title ? `<strong>${esc(l.title)}</strong>` : ""}${l.text ? ` — ${esc(l.text)}` : ""}</li>`).join("")}</ul>`
      : ""
  }
  ${
    hazards.length
      ? `<h3>Hazards <span class="muted">— unsafe system states, ranked by how many findings reach them</span></h3>
  <div class="tablewrap"><table class="hz"><thead><tr><th>Hazard</th><th>What it means (a state, not an attack)</th><th>Findings</th><th>Worst</th></tr></thead><tbody>${[...hazards]
    .sort((a, b) => (hazCount.get(b.id)?.n ?? 0) - (hazCount.get(a.id)?.n ?? 0))
    .map((h) => {
      const hc = hazCount.get(h.id);
      const n = hc?.n ?? 0;
      const worst = hc && hc.worst < 9 ? hc.worst : null;
      return `<tr><td><span class="hid">${esc(h.id)}</span></td><td>${esc(h.title || h.text)}</td><td class="hzn">${n ? `<span class="hcount">${n}</span>` : '<span class="muted">0</span>'}</td><td>${worst ? `<span class="band band-${worst}">${worst}</span>` : '<span class="muted">—</span>'}</td></tr>`;
    })
    .join("")}</tbody></table></div>`
      : ""
  }
</div></details></section>`
    : "";

// ── narrative slices of 01-scope.md, so the report reads as a story instead of
// re-dumping the whole file (the "Scope" section used to duplicate What's at stake) ──
const scopeSecMap = new Map<string, string>();
{
  const idxs: { t: string; s: number }[] = [];
  for (const mm of scopeMd.matchAll(/^##\s+(.*)$/gm)) idxs.push({ t: mm[1]!.trim(), s: mm.index! });
  scopeSecMap.set("_pre", scopeMd.slice(0, idxs.length ? idxs[0]!.s : scopeMd.length));
  for (let k = 0; k < idxs.length; k++) {
    const e = k + 1 < idxs.length ? idxs[k + 1]!.s : scopeMd.length;
    scopeSecMap.set(idxs[k]!.t.toLowerCase(), scopeMd.slice(idxs[k]!.s, e));
  }
}
const scopeSec = (prefix: string): string | null => {
  for (const [k, v] of scopeSecMap) if (k.startsWith(prefix)) return v;
  return null;
};
const overviewMd = (scopeSecMap.get("_pre") ?? "").replace(/^\s*#{1,6}\s+.*\r?\n?/, "").trim();
const boundaryMd = scopeSec("boundary");
const assumptionsMd = scopeSec("assumption");
const subsystems = planeSeq.filter((p) => p !== "All control actions").map(prettyPlane);

// §1 — what the system is (visible; the story opener)
const overviewHtml = overviewMd
  ? `<section id="overview"><details class="fold" open><summary><span class="foldh">1 · What this system is</span></summary><div class="foldbody doc">${md(overviewMd)}</div></details></section>`
  : "";

// §2 — how it's built: a generated high-level control-structure loop diagram
// (self-contained SVG, no JS, theme-aware via CSS vars), then the full detail folded under it.
const systemDiagramSvg = (() => {
  const W = 940;
  const e2 = (s: string) => String(s).replace(/[&<>]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[m]!);
  const short = (nm: string) => {
    nm = nm.replace(/\s*\(.*$/, "").trim();
    return nm.length > 26 ? nm.slice(0, 24) + "…" : nm;
  };
  const rawActors: string[] = ((model as any)?.controllers ?? []).filter((c: any) => c.type && c.type !== "automated").map((c: any) => String(c.name));
  const humanish = rawActors.filter(
    (a) =>
      /operator|\buser\b|human|principal|staff|support|customer|tenant|person|people|engineer/i.test(a) &&
      !/resolver|node|handler|service|engine|daemon|worker|store|pool|middleware|gate|server|mechanism|runtime|processor|client/i.test(a),
  );
  const pick = [...new Set(humanish.map(short))];
  const actorText = pick.length ? pick.slice(0, 3).join("   ·   ") + (pick.length > 3 ? `   +${pick.length - 3}` : "") : "Tenant users & operators";
  const bucketOf = (p: string) => {
    const s = (p || "").toLowerCase();
    if (/pulsar|topic|\bbus\b|cdc|atom|metricmetadata|ingest_status|publish|consume/.test(s)) return "Pulsar bus";
    if (/aws|cloudwatch|cloudtrail|\bs3\b|\brole\b|account|\bsdk\b|\biam\b|eks|credential|foreign|\bsts\b/.test(s)) return "Customer AWS";
    if (/session|orchestrat|instance|pty|shell|\bhost\b|terminal/.test(s)) return "Sessions & host";
    return "Shared Postgres";
  };
  const bc = new Map<string, number>();
  for (const ca of (model as any)?.controlActions ?? []) { const b = bucketOf(ca.process || ""); bc.set(b, (bc.get(b) || 0) + 1); }
  const resources = [...bc.entries()].sort((a, b) => b[1] - a[1]).map((x) => x[0]);
  const appX = 30, appW = W - 60, appPad = 14, chipH = 28, headH = 28;
  const perRow = Math.max(1, Math.min(5, Math.floor((appW - appPad * 2) / 176)));
  const rows = Math.max(1, Math.ceil(subsystems.length / perRow));
  const appY = 92, appH = headH + rows * (chipH + 8) + appPad;
  const resY = appY + appH + 64, resH = 46, aY = 18, aH = 44, aW = 400, aX = (W - aW) / 2;
  const H = resY + resH + 34;
  const box = (x: number, y: number, w: number, h: number, label: string, kind: "actor" | "res" | "danger") => {
    const fill = kind === "danger" ? "var(--uca-bg)" : "var(--bg)";
    const stroke = kind === "danger" ? "var(--uca)" : "var(--line)";
    const tcol = kind === "danger" ? "var(--uca)" : "var(--ink)";
    return `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="9" fill="${fill}" stroke="${stroke}"/><text x="${x + w / 2}" y="${y + h / 2 + 4}" font-size="12" font-weight="600" text-anchor="middle" fill="${tcol}">${e2(label)}</text>`;
  };
  let s = `<svg class="sysdiagram" viewBox="0 0 ${W} ${H}" width="100%" xmlns="http://www.w3.org/2000/svg">`;
  s += `<defs><marker id="ar" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="var(--muted)"/></marker><marker id="ard" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="var(--uca)"/></marker></defs>`;
  s += box(aX, aY, aW, aH, actorText, "actor");
  s += `<rect x="${appX}" y="${appY}" width="${appW}" height="${appH}" rx="12" fill="none" stroke="var(--line)" stroke-dasharray="5 4"/>`;
  const appLabel = ((grid.system || "").split(/[—(@:]/)[0] || "").trim().toUpperCase().slice(0, 40) || "THE APPLICATION";
  s += `<text x="${appX + 14}" y="${appY + 19}" font-size="11" font-weight="700" letter-spacing="0.06em" fill="var(--muted)">${e2(appLabel)} · ${subsystems.length} SUBSYSTEMS</text>`;
  const chipW = (appW - appPad * 2 - (perRow - 1) * 10) / perRow;
  subsystems.forEach((name, i) => {
    const r = Math.floor(i / perRow), c = i % perRow;
    const x = appX + appPad + c * (chipW + 10), y = appY + headH + r * (chipH + 8);
    s += `<rect x="${x}" y="${y}" width="${chipW}" height="${chipH}" rx="7" fill="var(--panel)" stroke="var(--line)"/><text x="${x + chipW / 2}" y="${y + chipH / 2 + 4}" font-size="11" text-anchor="middle" fill="var(--ink)">${e2(name)}</text>`;
  });
  const n = resources.length || 1, rGap = 16, rW = (W - 60 - (n - 1) * rGap) / n;
  resources.forEach((name, i) => {
    const x = 30 + i * (rW + rGap), cx = x + rW / 2;
    const danger = /Customer AWS|Pulsar/.test(name);
    s += box(x, resY, rW, resH, name, danger ? "danger" : "res");
    s += `<line x1="${cx - 8}" y1="${appY + appH}" x2="${cx - 8}" y2="${resY}" stroke="${danger ? "var(--uca)" : "var(--muted)"}" stroke-width="1.4" marker-end="url(#${danger ? "ard" : "ar"})"/>`;
    s += `<line x1="${cx + 8}" y1="${resY}" x2="${cx + 8}" y2="${appY + appH}" stroke="var(--line)" stroke-width="1.2" stroke-dasharray="4 3" marker-end="url(#ar)"/>`;
  });
  s += `<line x1="${W / 2}" y1="${aY + aH}" x2="${W / 2}" y2="${appY}" stroke="var(--muted)" stroke-width="1.6" marker-end="url(#ar)"/>`;
  s += `</svg>`;
  return `<div class="diagramwrap">${s}<p class="diagcap"><span class="dk"><b>→</b> control action</span> <span class="dk"><b>⇢</b> feedback (dashed — often absent; see §9)</span> <span class="dk dkr"><b>→</b> cross-account / bus edges (the crown-jewel paths)</span></p></div>`;
})();
const structDoc = read("02-control-structure.md");
const structureHtml = `<section id="structure"><details class="fold" open><summary><span class="foldh">2 · How it's built — systems &amp; subsystems</span>${subsystems.length ? `<span class="gcount">${subsystems.map((s) => `<span class="gbadge">${esc(s)}</span>`).join("")}</span>` : ""}</summary><div class="foldbody">${systemDiagramSvg}${structDoc ? `<details class="fold subfold"><summary><span class="foldh sfh">Control-structure detail — controllers, control actions, process-model beliefs</span></summary><div class="foldbody doc">${md(dropTopHeading(structDoc))}</div></details>` : ""}</div></details></section>`;

// §4 — the trust boundary and the assumptions, folded together
const boundaryHtml = boundaryMd
  ? section("boundary", "3 · Boundary & seams", assumptionsMd ? boundaryMd + "\n\n" + assumptionsMd : boundaryMd)
  : "";

// §0 — a plain-language primer + glossary, so every term is defined before it is
// used. STPA is a decomposition chain; naming it up front is what makes the rest
// readable to someone who is not a control theorist.
const primerHtml = `<section id="primer"><details class="fold primer" open><summary><span class="foldh">Reading this report — STPA in 90 seconds</span></summary><div class="foldbody">
  <p class="lede">This is an <strong>STPA</strong> analysis (System-Theoretic Process Analysis, and its security extension <strong>STPA-Sec</strong>). Instead of enumerating attacker techniques against each component — the approach of checklist methods like <strong>STRIDE</strong> — it models the system as <em>controllers</em> issuing <em>control actions</em> over <em>processes</em>, and asks where a legitimate action, in the wrong context, drives the system into a dangerous state. Its power is finding failures that <strong>emerge from the interaction of correctly-built components</strong> — broken authorization, tenant leaks, confused-deputy, bypass paths — the class attacker-checklists structurally miss. It complements STRIDE rather than replacing it.</p>
  <p><strong>The analysis is a chain, each link narrowing the last:</strong></p>
  <p class="chain"><span class="chip-l">Losses</span> <span class="arw">▸ caused by ▸</span> <span class="chip-l">Hazards</span> <span class="arw">▸ reached through ▸</span> <span class="chip-l">Unsafe control actions</span> <span class="arw">▸ which happen via ▸</span> <span class="chip-l">Loss scenarios</span> <span class="arw">▸ each inverted into ▸</span> <span class="chip-l">Constraints</span></p>
  <p>So the three ways this report groups things are <em>one</em> picture from three angles: the <strong>four UCA types</strong> are the <em>mechanism</em> (the four ways any control can be unsafe) · the <strong>hazards</strong> are the dangerous <em>states</em> those mechanisms produce · the <strong>root causes</strong> (in <a href="#focus">Where to focus</a>) are the shared <em>fixes</em> — the few changes that close many findings at once.</p>
  <dl class="glossary">
    <dt>Loss</dt><dd>an outcome stakeholders find unacceptable — data exposed, money lost, trust broken.</dd>
    <dt>Hazard</dt><dd>a system <em>state</em> that, in a worst-case environment, leads to a loss. A state, never an attacker action.</dd>
    <dt>Controller</dt><dd>anything that exercises authority: a service, a human operator, a pipeline, a third party.</dd>
    <dt>Control action</dt><dd>an authority-bearing action a controller takes — grant access, run a command, assume a role, write data.</dd>
    <dt>Process model</dt><dd>what a controller <em>believes</em> about the system. Most authorization bugs are a controller acting on a stale or wrong belief.</dd>
    <dt>Unsafe control action (UCA)</dt><dd>a control action that is unsafe in a specific context. Exactly four types: <em>not provided</em> (a needed control never happens) · <em>provided</em> (an action taken where it causes harm) · <em>wrong timing/order</em> · <em>too long / stopped too soon</em>.</dd>
    <dt>Loss scenario</dt><dd>why a UCA occurs — or why a <em>correct</em> control fails to land because something bypasses it (the highest-value class).</dd>
    <dt>Constraint</dt><dd>a MUST-NOT rule that <em>prevents</em> the hazard where prevention is possible, or <em>bounds</em> it — shrinks the blast radius, forces attribution — where it isn't. Each carries a runnable check.</dd>
    <dt>Trust zone / blast radius</dt><dd>where a component sits (a per-customer deployment, the central plane, a cloud account) and how far a failure reaches (one tenant vs all). Together they set severity.</dd>
    <dt>Band (1–4)</dt><dd>this analysis's priority order = severity × reachability. Not a probability, not a CVSS score.</dd>
    <dt>IDOR</dt><dd>Insecure Direct Object Reference — using a caller-supplied id to read or act on a resource without checking the caller owns it.</dd>
    <dt>Confused deputy</dt><dd>tricking a privileged component into using its authority on the attacker's behalf.</dd>
    <dt>TOCTOU</dt><dd>time-of-check to time-of-use — a check and the action it guards race, so the state changes in between.</dd>
    <dt>Prompt injection</dt><dd>attacker-controlled text that reaches an LLM agent and steers its tool calls or output.</dd>
  </dl>
</div></details></section>`;

// §0b — objective self-assessment: computed by the peer-review gate, never narrated.
const scorecardRaw = read("review-scorecard.json");
const scorecard = scorecardRaw ? (JSON.parse(scorecardRaw) as any) : null;
const trustPanelHtml = (() => {
  if (!scorecard) {
    return `<div id="trust" class="notreviewed">⚠ <strong>NOT INDEPENDENTLY REVIEWED.</strong> This analysis has not passed an adversarial peer review by a second model — treat every finding and every band as a <em>draft</em>, not a verdict. Run <code>stpa verify</code> after the review pass.</div>`;
  }
  const ok = scorecard.passed && scorecard.independentReview;
  return `<section id="trust" class="block trust${ok ? "" : " warn"}"><h2>How much to trust this analysis</h2>
  <p class="lede">${ok ? "Every finding was attacked by an <strong>independent second model</strong> before you saw it" : "Peer review is <strong>incomplete</strong> — read this section before trusting the bands"}. The verdicts below are the reviewer's, not the author's.</p>
  <div class="trustgrid">
    <div class="tstat"><div class="v">${scorecard.reviewedPct}%</div><div class="k">findings peer-reviewed</div></div>
    <div class="tstat"><div class="v">${scorecard.independentReview ? "✓" : "✗"}</div><div class="k">independent model<div class="muted">${esc(scorecard.authorModel || "?")} → ${esc(scorecard.reviewerModel || "?")}</div></div></div>
    <div class="tstat"><div class="v">${scorecard.reachabilityPathPct}%</div><div class="k">live findings that name a deployed reachability path</div></div>
    <div class="tstat"><div class="v">${scorecard.trustZonesModeled ? "✓" : "✗"}</div><div class="k">deployment trust zones modeled</div></div>
  </div>
  <p class="foldhint"><strong>${scorecard.confirmed}</strong> confirmed · <strong>${scorecard.downgraded}</strong> downgraded on review · <strong>${scorecard.provisional}</strong> provisional (assumption-dependent) · <strong>${scorecard.refuted}</strong> refuted. A downgrade or refutation means the first-pass rating was corrected before it reached you.</p>
  </section>`;
})();

// §6 — where to focus: 187 findings → a short list of highest-leverage fixes.
// Full remediation (locations, probes, waves) stays at the end in the plan.
const focusHtml = (() => {
  if (!plan || !(plan.clusters ?? []).length) return "";
  const cl = [...(plan.clusters as any[])].sort((a, b) => (b.leverage ?? 0) - (a.leverage ?? 0));
  const total = plan.metrics.findings || findings.length;
  const K = Math.min(4, cl.length);
  const topSum = cl.slice(0, K).reduce((a, c) => a + (c.leverage ?? 0), 0);
  const pct = total ? Math.round((topSum / total) * 100) : 0;
  const b1 = plan.metrics.bands?.band1 ?? 0;
  const cards = cl
    .slice(0, K)
    .map(
      (c, i) => `<div class="fcard">
      <div class="frank">${i + 1}</div>
      <div class="fbody">
        <div class="fmeta"><span class="fclose">${c.leverage}</span> findings <span class="muted">·</span> <span class="band band-${c.bestBand}">band ${c.bestBand}</span> <span class="muted">·</span> <span class="eff eff-${c.effort}">${esc(c.effort)}</span> <span class="effw">${EFFORT_LABEL[c.effort] ?? ""}</span></div>
        <div class="fname">${c.id ? `<span class="lid">${esc(c.id)}</span> ` : ""}${esc(c.summary ?? c.name)}</div>
        ${c.fix ? `<div class="ffix"><strong>Do:</strong> ${esc(c.fix)}</div>` : ""}
      </div>
    </div>`,
    )
    .join("");
  return `<section id="focus"><details class="fold focus" open><summary><span class="foldh">5 · Where to focus</span></summary><div class="foldbody">

  <p class="lede">${total} findings is a lot — but they collapse to ${plan.metrics.rootCauses || cl.length} root causes, and a handful close most of them. <strong>The top ${K} account for ${topSum} of ${total} findings (${pct}%).</strong> ${b1 ? `${b1} findings are band-1 — ship-blockers.` : ""} Fix these first; the rest is downstream.</p>
  <div class="focuscards">${cards}</div>
  <p class="foldhint">Full remediation — every finding with its <code>file:line</code> and a runnable probe, sequenced into waves — is in <a href="#plan">the engineering plan</a> at the end.</p>
</div></details></section>`;
})();

const typeCounts = Object.keys(UCA_TYPE_LABEL).map((k) => {
  const items = findings.filter((c) => c.ucaType === k);
  const byBand = [1, 2, 3, 4].map((b) => items.filter((c) => bandOf.get(c.id) === b).length);
  const unbanded = items.length - byBand.reduce((a, b) => a + b, 0);
  return { key: k, label: UCA_TYPE_LABEL[k]!, hint: UCA_TYPE_HINT[k]!, term: UCA_TYPE_TERM[k]!, n: items.length, byBand, unbanded };
});
const maxType = Math.max(1, ...typeCounts.map((t) => t.n));
const anyBanded = typeCounts.some((t) => t.byBand.some((n) => n > 0));

const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} — STPA Threat Model</title>
<style>
:root{
  --bg:#fbfbfa; --panel:#fff; --ink:#16181d; --muted:#5c6270; --line:#e3e5ea;
  --accent:#1f4ed8; --uca:#b42318; --uca-bg:#fef3f2; --tomb:#475467; --tomb-bg:#f4f5f7;
  --open:#b54708; --open-bg:#fffaeb; --unbound:#7a5af8; --unbound-bg:#f4f3ff; --ok:#067647;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0e1014; --panel:#15181e; --ink:#e6e8ec; --muted:#9aa2b1; --line:#262b34;
  --accent:#7da2ff; --uca:#ff8a80; --uca-bg:#2a1614; --tomb:#9aa2b1; --tomb-bg:#1a1e25;
  --open:#f0b429; --open-bg:#2a2211; --unbound:#c4b5fd; --unbound-bg:#1e1b2e; --ok:#5ed6a4;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.65 ui-sans-serif,-apple-system,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1140px;margin:0 auto;padding:40px 24px 96px}
header.top{border-bottom:1px solid var(--line);padding-bottom:24px;margin-bottom:32px}
.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-weight:650}
h1{font-size:29px;line-height:1.25;margin:8px 0 6px;letter-spacing:-.02em}
.sub{color:var(--muted);font-size:13.5px}
.sources{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-top:12px;
  font-size:12px;color:var(--muted)}
.sources .k{font-size:10px;letter-spacing:.07em;text-transform:uppercase;font-weight:650}
.sources .src{background:var(--tomb-bg);border:1px solid var(--line);border-radius:6px;padding:3px 9px}
.sources .src b{color:var(--ink);font-weight:600}
.covrow{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:24px 0 12px}
.covrow .stat{padding:18px 20px;text-align:center}
.covrow .h{max-width:44ch;margin-left:auto;margin-right:auto}
.covrow .v{font-size:34px}
.covrow .h{font-size:12.5px;color:var(--muted);margin-top:5px;line-height:1.45}
.stats2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:0 0 12px}
.stats2 .stat{padding:14px 16px;text-align:center}
.stats2 .k{font-size:10px}
.stats2 .v{font-size:28px;margin-top:3px}
.stats2 .h{font-size:11.5px;color:var(--muted);margin-top:4px;line-height:1.4}
.composition{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:15px 18px;margin:0 0 8px}
.comphead{display:flex;justify-content:space-between;align-items:baseline;gap:12px;
  font-size:11px;letter-spacing:.06em;text-transform:uppercase;font-weight:650;margin-bottom:10px}
.comphead .muted{letter-spacing:0;text-transform:none;font-weight:400;font-size:11.5px}
.compbar{height:14px;border-radius:99px;overflow:hidden;display:flex;background:var(--tomb-bg)}
.cseg{height:100%}
.c-find{background:var(--uca)} .c-ruled{background:var(--tomb)} .c-open{background:var(--open)}
.complegend{display:flex;flex-wrap:wrap;gap:18px;margin-top:11px;font-size:12px;color:var(--muted)}
.complegend .lg{display:flex;align-items:center;gap:7px}
.complegend b{color:var(--ink);font-variant-numeric:tabular-nums}
.complegend .sw{width:11px;height:11px;border-radius:3px;display:inline-block}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:0 0 8px}
.stats .stat{padding:12px 14px;text-align:center}
.stats .k{font-size:10px}
.stats .v{font-size:24px;margin-top:4px}
@media (max-width:760px){.covrow{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.stat .k{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);font-weight:650}
.stat .v{font-size:25px;font-weight:660;letter-spacing:-.02em;margin-top:3px}
.stat.cov .v{color:var(--ok)}
.stat.cov.warn .v{color:var(--open)}
.qualifier{margin-top:14px;background:var(--open-bg);border:1px solid var(--open);border-radius:11px;
  padding:13px 16px;color:var(--ink);font-size:13.5px}
.qualifier b{color:var(--open)}
.qualifier.incomplete{background:var(--uca-bg);border-color:var(--uca)}
.qualifier.incomplete b{color:var(--uca)}
.qualifier ul{margin:10px 0 6px;padding-left:20px}
.qualifier li{margin:5px 0;font-size:13px}
.req{font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;font-weight:750;color:var(--uca);
  border:1px solid var(--uca);border-radius:4px;padding:1px 5px;vertical-align:1px}
.bars{margin:22px 0 0;background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:16px}
.bars h4{margin:0 0 12px;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
.bars h4{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.barsub{font-size:10.5px;letter-spacing:0;text-transform:none;font-weight:400;color:var(--muted)}
.bar{display:grid;grid-template-columns:270px 1fr 34px;align-items:center;gap:14px;margin:11px 0;font-size:13px}
.bar .blabel{line-height:1.3}
.bar .bname{font-weight:600;font-size:13px}
.bar .bhint{font-size:11px;color:var(--muted);margin-top:2px}
.bar .track{height:11px;display:flex;align-items:center}
.bar .fill{height:100%;display:flex;border-radius:99px;overflow:hidden;min-width:4px}
.bar .seg{height:100%}
.bar .n{text-align:center;color:var(--ink);font-weight:650;font-variant-numeric:tabular-nums}
.sb-1{background:var(--uca)} .sb-2{background:var(--open)}
.sb-3{background:var(--muted)} .sb-4{background:var(--line)}
.sb-x{background:var(--accent);opacity:.55}
.barlegend{display:flex;flex-wrap:wrap;gap:14px;margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}
.barlegend .lg{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted)}
.barlegend .sw{width:11px;height:11px;border-radius:3px;display:inline-block}
.barfoot{font-size:11.5px;color:var(--muted);margin:12px 0 0}
nav.toc{display:flex;flex-wrap:wrap;gap:8px;margin:30px 0 6px}
nav.toc a{font-size:12.5px;color:var(--muted);text-decoration:none;border:1px solid var(--line);
  border-radius:99px;padding:5px 12px;background:var(--panel)}
nav.toc a:hover{color:var(--accent);border-color:var(--accent)}
section.doc,section.block{background:var(--panel);border:1px solid var(--line);border-radius:13px;
  padding:22px 26px;margin:20px 0}
h2{font-size:19px;margin:0 0 14px;letter-spacing:-.01em;padding-bottom:9px;border-bottom:1px solid var(--line)}
h3{font-size:15.5px;margin:22px 0 9px}
h4{font-size:13.5px;margin:16px 0 6px}
p{margin:9px 0}
ul{margin:9px 0;padding-left:20px} li{margin:4px 0}
code{font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  background:var(--tomb-bg);border-radius:4px;padding:1px 4px;
  overflow-wrap:break-word;word-break:normal}
td code{background:transparent;padding:0}
td.loc code,td.probe code{background:var(--tomb-bg);padding:2px 5px;display:inline;max-width:none}
blockquote{margin:12px 0;padding:11px 15px;border-left:3px solid var(--open);
  background:var(--open-bg);border-radius:0 8px 8px 0;font-size:13.5px}
.codeblock{margin:14px 0;border:1px solid var(--line);border-radius:9px;overflow:hidden;background:var(--tomb-bg)}
.diagram-label{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);
  padding:8px 13px;border-bottom:1px solid var(--line);font-weight:650}
.codeblock pre{margin:0;padding:14px;overflow-x:auto;
  font:12.5px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.tablewrap{overflow-x:auto;margin:13px 0;border:1px solid var(--line);border-radius:9px}
table{border-collapse:collapse;width:100%;font-size:13px;min-width:520px}
th{background:var(--tomb-bg);text-align:left;padding:9px 12px;font-weight:650;font-size:11.5px;
  letter-spacing:.05em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--line)}
td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
section.ca{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:20px 24px;margin:16px 0}
section.ca h3{margin:0 0 4px;display:flex;flex-wrap:wrap;align-items:baseline;gap:10px}
.caid{font:12px ui-monospace,Menlo,monospace;background:var(--accent);color:#fff;
  border-radius:5px;padding:2px 7px;letter-spacing:.03em}
.ctrl{font-size:12.5px;color:var(--muted);font-weight:400}
.cacount{margin-left:auto;font-size:11.5px;color:var(--muted);font-weight:500}
table.grid td.ttype{white-space:nowrap;color:var(--muted);font-size:12.5px}
table.grid td.tbody{min-width:300px}
table.grid td.tmeta{white-space:nowrap;font-size:12px}
tr.tombstone td.tbody{color:var(--muted)}
.pill{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
  border-radius:99px;padding:3px 9px;white-space:nowrap}
.pill-uca{background:var(--uca-bg);color:var(--uca);border:1px solid var(--uca)}
.pill-tomb{background:var(--tomb-bg);color:var(--tomb);border:1px solid var(--line)}
.pill-open{background:var(--open-bg);color:var(--open);border:1px solid var(--open)}
.pill-unbound{background:var(--unbound-bg);color:var(--unbound);border:1px solid var(--unbound)}

.plan-block{border-color:var(--accent);border-width:2px}
.lede{font-size:15.5px;margin:0 0 16px}
.planstats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}
.pstat{background:var(--tomb-bg);border:1px solid var(--line);border-radius:10px;padding:13px 14px;text-align:center}
.pstat .k{font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);font-weight:650}
.pstat .v{font-size:23px;font-weight:660;letter-spacing:-.02em;margin:2px 0 1px}
.pstat .h{font-size:11.5px;color:var(--muted)}
.caveat{font-size:12.5px;color:var(--muted);margin:12px 0 0}
.leadfix{margin:22px 0;padding:18px 20px;border:1px solid var(--accent);border-radius:11px;background:var(--tomb-bg)}
.leadfix .k{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--accent);font-weight:700}
.leadfix h3{margin:6px 0 8px;font-size:17px}
.leadfix .do{margin-top:10px}
h3.wave{margin:26px 0 10px;display:flex;align-items:baseline;gap:10px;
  padding-bottom:7px;border-bottom:1px solid var(--line)}
h3.wave.w1{color:var(--uca)}
.band{display:inline-block;min-width:20px;text-align:center;font-size:11.5px;font-weight:750;
  border-radius:5px;padding:2px 6px}
.band-1{background:var(--uca-bg);color:var(--uca);border:1px solid var(--uca)}
.band-2{background:var(--open-bg);color:var(--open);border:1px solid var(--open)}
.band-3{background:var(--tomb-bg);color:var(--tomb);border:1px solid var(--line)}
.band-4{background:transparent;color:var(--muted);border:1px dashed var(--line)}
.eff{display:inline-block;font-size:11px;font-weight:750;border-radius:4px;padding:1px 5px;
  background:var(--tomb-bg);border:1px solid var(--line)}
.eff-S{color:var(--ok);border-color:var(--ok)}
.effw{font-size:11px;color:var(--muted)}
table.plan{table-layout:fixed;min-width:940px}
table.plan.rc{min-width:1000px}
table.plan col.c-rcid{width:62px} table.plan col.c-rcname{width:260px}
table.plan col.c-lev{width:78px} table.plan col.c-fix{width:auto}
table.plan col.c-bandd{width:118px}
.rcid{display:inline-block;font:11.5px ui-monospace,Menlo,monospace;font-weight:700;
  background:var(--accent);color:#fff;border-radius:5px;padding:2px 7px}
.rcref{font:10.5px ui-monospace,Menlo,monospace;color:var(--accent);margin-top:3px;font-weight:650}
.bandcell{white-space:nowrap}
.bandwhy{margin-top:4px;font-size:10.5px;white-space:nowrap}
.sev{font-weight:650;text-transform:capitalize}
.sev-catastrophic{color:var(--uca)} .sev-severe{color:var(--open)}
.sev-moderate{color:var(--muted)} .sev-minor{color:var(--muted)}
.mult{color:var(--muted)}
.reach{font:10.5px ui-monospace,Menlo,monospace;font-weight:700;color:var(--accent);
  border-bottom:1px dotted var(--accent);cursor:help}
.thsub{display:block;font-size:9.5px;letter-spacing:.03em;text-transform:none;font-weight:400;opacity:.75}
table.plan col.c-id{width:132px} table.plan col.c-band{width:56px}
table.plan col.c-eff{width:78px} table.plan col.c-loc{width:210px}
table.plan col.c-fix{width:auto} table.plan col.c-probe{width:250px}
table.plan td:first-child code{font-size:11px}
/* nowrap applies to the WAVE tables only — on the root-cause table column 2 is
   prose, and nowrap there overflows the cell across every column to its right. */
table.plan:not(.rc) td:nth-child(1),table.plan:not(.rc) td:nth-child(2),table.plan:not(.rc) td:nth-child(3){white-space:nowrap}
table.plan.rc{table-layout:fixed}
table.plan.rc td:first-child{white-space:nowrap}
table.plan.rc td.lev{white-space:nowrap;text-align:center}
table.plan td:nth-child(2).bandcell,table.plan .bandcell{text-align:center}
table.plan.rc th:nth-child(3),table.plan.rc th:nth-child(4),table.plan.rc th:nth-child(5){text-align:center}
table.plan.rc td:nth-child(4),table.plan.rc td:nth-child(5){text-align:center}
table.plan:not(.rc) th:nth-child(2),table.plan:not(.rc) th:nth-child(3){text-align:center}
table.plan:not(.rc) td:nth-child(3){text-align:center}
.csum{font-size:12px;margin-top:4px;font-weight:400;line-height:1.5;overflow-wrap:break-word}
table.plan td.fix{font-size:12.5px;line-height:1.55}
table.plan td.loc code,table.plan td.probe code{white-space:normal;overflow-wrap:break-word;
  word-break:normal;hyphens:none}
table.plan td.loc{font-size:11.5px}
table.plan td.probe code{font-size:11.5px;white-space:pre-wrap;word-break:break-word;
  display:block;padding:7px 9px;border-radius:6px;line-height:1.5}
table.plan td.loc code{display:block;padding:7px 9px;border-radius:6px;font-size:11.5px;line-height:1.5}
table.plan td.loc code{font-size:11.5px}
td.lev .levn{font-size:17px;font-weight:700;color:var(--accent)}
.csum{font-size:12px;margin-top:4px;font-weight:400}
.muted{color:var(--muted)}
nav.toc a.primary{color:var(--accent);border-color:var(--accent);font-weight:650}
footer{margin-top:40px;padding-top:20px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px;
  display:flex;align-items:flex-end;justify-content:space-between;gap:28px;flex-wrap:wrap}
footer p{margin:0;max-width:74ch}
.brand{display:flex;align-items:center;gap:9px;text-decoration:none;color:var(--muted);
  flex-shrink:0;opacity:.85;transition:opacity .15s,color .15s}
.brand:hover{opacity:1;color:var(--accent)}
.tmark{width:26px;height:25px;display:block;flex-shrink:0}
/* Black artwork on alpha: invert in dark mode or it vanishes into the panel. */
@media (prefers-color-scheme:dark){.tmark{filter:invert(1)}}
:root[data-theme="dark"] .tmark{filter:invert(1)}
:root[data-theme="light"] .tmark{filter:none}
.btxt{display:flex;flex-direction:column;line-height:1.25}
.btxt b{font-size:12px;font-weight:650;color:inherit}
.bsub{font-size:10.5px;opacity:.75}
@media print{.brand{opacity:1}}
@media print{
  body{background:#fff} .wrap{max-width:none;padding:0}
  section.doc,section.block,section.ca,.stat,.bars{break-inside:avoid;box-shadow:none}
  nav.toc{display:none}
}
/* ── progressive disclosure (native <details>, no JS) ── */
details.fold,details.planegroup{background:var(--panel);border:1px solid var(--line);border-radius:13px;margin:16px 0;overflow:hidden}
details.fold>summary,details.planegroup>summary{cursor:pointer;list-style:none;padding:17px 24px;display:flex;flex-wrap:wrap;align-items:center;gap:12px;user-select:none}
details.fold>summary::-webkit-details-marker,details.planegroup>summary::-webkit-details-marker{display:none}
details.fold>summary::before,details.planegroup>summary::before{content:"\25B8";color:var(--muted);font-size:13px;transition:transform .12s ease;flex:none}
details[open]>summary::before{transform:rotate(90deg)}
details.fold>summary:hover .foldh,details.planegroup>summary:hover .foldh{color:var(--accent)}
.foldh{font-size:16px;font-weight:650}
.foldbody{padding:2px 24px 20px}
.foldbody.doc>*:first-child{margin-top:0}
.pgbody{padding:2px 16px 14px}
.pgbody section.ca{margin:12px 0}
.gcount{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.gbadge{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.gbadge.f{background:var(--uca-bg);color:var(--uca);border-color:var(--uca)}
.gbadge.t{background:var(--tomb-bg);color:var(--tomb)}
.gbadge.b1{background:var(--uca);color:#fff;border-color:var(--uca)}
.foldhint{font-size:12.5px;color:var(--muted);margin:8px 0 0}
/* what's at stake — the human layer */
.stake{border-left:3px solid var(--accent)}
.stake>.lede{font-size:14.5px}
ul.stakelist{list-style:none;margin:8px 0 6px;padding:0;display:grid;gap:7px}
ul.stakelist li{padding:10px 14px;background:var(--bg);border:1px solid var(--line);border-radius:9px;font-size:13.5px;line-height:1.55}
.lid,.hid{display:inline-block;font-weight:750;font-size:11.5px;color:var(--accent);background:var(--uca-bg);border:1px solid var(--uca);border-radius:6px;padding:1px 7px;margin-right:5px}
.hz .hid{margin:0}
table.hz th:nth-child(3),table.hz td:nth-child(3),table.hz th:nth-child(4),table.hz td:nth-child(4){text-align:center;white-space:nowrap;width:1%}
.hcount{display:inline-block;font-weight:750;min-width:24px;padding:1px 9px;border-radius:20px;background:var(--uca-bg);color:var(--uca);border:1px solid var(--uca)}
/* where to focus — the prioritization view */
.focus{border-left:3px solid var(--uca)}
.focuscards{display:grid;gap:10px;margin:10px 0 4px}
.fcard{display:grid;grid-template-columns:34px 1fr;gap:14px;align-items:start;padding:14px 16px;background:var(--bg);border:1px solid var(--line);border-radius:11px}
.frank{font-weight:750;font-size:19px;color:var(--uca);text-align:center;line-height:1.15}
.fmeta{font-size:12px;color:var(--muted);margin-bottom:3px}
.fclose{font-weight:750;color:var(--uca);font-size:14px}
.fname{font-weight:650;font-size:14px;line-height:1.4;margin-bottom:4px}
.ffix{font-size:13px;line-height:1.5}
/* generated system diagram */
.diagramwrap{margin:4px 0 6px}
.sysdiagram{display:block;max-width:820px;margin:0 auto}
.diagcap{font-size:11.5px;color:var(--muted);text-align:center;margin:8px 0 0;display:flex;gap:16px;justify-content:center;flex-wrap:wrap}
.diagcap .dk b{color:var(--muted)}
.diagcap .dkr b{color:var(--uca)}
.subfold{margin-top:16px}
.subfold>summary{padding:12px 16px}
.sfh{font-size:13px!important;color:var(--muted)}
/* trust / peer-review scorecard */
.notreviewed{background:var(--uca-bg);border:1px solid var(--uca);color:var(--uca);border-radius:11px;padding:14px 18px;margin:16px 0;font-size:13.5px}
.trust{border-left:3px solid var(--ok,#16a34a)}
.trust.warn{border-left-color:var(--uca)}
.trustgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0 4px}
.tstat{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tstat .v{font-size:22px;font-weight:750;line-height:1.1}
.tstat .k{font-size:11.5px;color:var(--muted);margin-top:4px;line-height:1.35}
.tstat .k .muted{font-size:10.5px}
/* STPA primer + glossary */
.primer{border-left:3px solid var(--accent)}
.chain{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:8px 0 12px}
.chip-l{font-weight:650;font-size:12.5px;padding:3px 10px;border-radius:7px;background:var(--bg);border:1px solid var(--line)}
.chain .arw{font-size:11px;color:var(--muted)}
dl.glossary{display:grid;grid-template-columns:180px 1fr;gap:6px 16px;margin:14px 0 2px;font-size:13px;border-top:1px solid var(--line);padding-top:14px}
dl.glossary dt{font-weight:700;color:var(--ink)}
dl.glossary dd{margin:0;color:var(--ink);line-height:1.5}
@media(max-width:640px){dl.glossary{grid-template-columns:1fr;gap:2px 0}dl.glossary dd{margin-bottom:8px;color:var(--muted)}}
@media print{details.fold,details.planegroup{break-inside:avoid}details>*{display:block!important}details>summary::before{display:none}}
</style></head><body><div class="wrap">

<header class="top">
  <div class="eyebrow">STPA · System-Theoretic Process Analysis</div>
  <h1>${esc(title)}</h1>
  <div class="sub">Control-theoretic threat model${grid.generated ? ` · grid generated ${esc(grid.generated)}` : ""}</div>
${
  ((grid as any).scope?.sources ?? []).length
    ? `<div class="sources"><span class="k">Analyzed from</span>${((grid as any).scope.sources as any[])
        .map((x) => `<span class="src"><b>${esc(x.type ?? "?")}</b> ${esc(x.locator ?? "?")}${x.ref ? ` <span class="muted">@${esc(x.ref)}</span>` : ""}</span>`)
        .join("")}</div>`
    : ""
}

  <div class="covrow">
    <div class="stat cov${concentrated ? " warn" : ""}">
      <div class="k">Analysis completeness</div>
      <div class="v">${pct.toFixed(1)}%</div>
      <div class="h">of the ${modeledCAs} control action${modeledCAs === 1 ? "" : "s"} modeled${surfacePct !== null ? ` — which is <strong>${surfacePct.toFixed(0)}% of the system</strong>` : ""}</div>
    </div>
    ${
      surfacePct !== null
        ? `<div class="stat cov${surfacePct < 100 ? " warn" : ""}">
            <div class="k">System covered</div>
            <div class="v">${surfacePct.toFixed(0)}%</div>
            <div class="h">${modeledCAs} of ${grid.scope!.candidateControlActions} control actions in the system were modeled</div>
          </div>`
        : `<div class="stat cov warn"><div class="k">System covered</div><div class="v">not declared</div><div class="h">the model does not say how large the system is, so completeness above cannot be read as system coverage</div></div>`
    }
  </div>
  <div class="stats2">
    <div class="stat"><div class="k">Authority-bearing actions analyzed</div><div class="v">${grid.totalCells / 4}</div>
      <div class="h">each asked 4 questions — one per way a control action can be unsafe</div></div>
    <div class="stat"><div class="k">Findings</div><div class="v">${findings.length}</div>
      <div class="h">contexts where an action of this system produces a loss</div></div>
  </div>
  <!--
    The 264 cells are ONE population, not four scores. Rendered as separate tiles,
    "no issue found: 65" sits beside "findings: 199" as though it were a competing
    result — a reader can take it as "65 things are fine". It is the remainder of
    the same denominator, so it is drawn as a composition of that denominator.
  -->
  <div class="composition">
    <div class="comphead"><span>${grid.totalCells} questions asked</span>
      <span class="muted">${grid.totalCells / 4} actions × 4 ways to be unsafe</span></div>
    <div class="compbar">
      ${findings.length ? `<div class="cseg c-find" style="width:${(findings.length / grid.totalCells) * 100}%" title="${findings.length} findings"></div>` : ""}
      ${tombs.length ? `<div class="cseg c-ruled" style="width:${(tombs.length / grid.totalCells) * 100}%" title="${tombs.length} ruled out with a written reason"></div>` : ""}
      ${open.length ? `<div class="cseg c-open" style="width:${(open.length / grid.totalCells) * 100}%" title="${open.length} never answered"></div>` : ""}
    </div>
    <div class="complegend">
      <span class="lg"><i class="sw c-find"></i><b>${findings.length}</b> produced a finding</span>
      <span class="lg"><i class="sw c-ruled"></i><b>${tombs.length}</b> ruled out, each with a written reason</span>
      <span class="lg"><i class="sw c-open"></i><b>${open.length}</b> never answered${open.length ? " — these are holes, not passes" : ""}</span>
    </div>
  </div>
${
  surfacePct !== null && surfacePct < 100
    ? `<div class="qualifier"><b>GRID COVERAGE IS NOT SYSTEM COVERAGE.</b> ${modeledCAs} of ${grid.scope!.candidateControlActions} candidate control actions were modeled (${surfacePct.toFixed(0)}%). The ${pct.toFixed(1)}% above describes the analysis of that subset — it says nothing about the ${grid.scope!.candidateControlActions! - modeledCAs} control actions not modeled.${grid.scope?.selectionCriteria ? ` <br><br><b>Selection criteria:</b> ${esc(grid.scope.selectionCriteria)}` : ""}${(grid.scope?.deferred ?? []).length ? `<br><br><b>Deferred:</b> ${(grid.scope!.deferred ?? []).map((d: any) => `${esc(d.name)} <span class="muted">(${esc(d.reason)})</span>`).join("; ")}` : ""}</div>`
    : surfacePct === null
      ? `<div class="qualifier"><b>SURFACE COVERAGE NOT DECLARED.</b> The model does not record how many candidate control actions the system has, so the grid coverage above cannot be read as system coverage. Add <code>scope.candidateControlActions</code> to model.json.</div>`
      : ""
}
${
  concentrated
    ? `<div class="qualifier"><b>THIS COVERAGE FIGURE IS NOT A CLEAN PASS.</b> ${counts.size} distinct control-structure element(s) across ${bound.length} bound findings${top ? `; <code>${esc(top[0])}</code> is cited by ${(topShare * 100).toFixed(0)}% of them` : ""}. Genuine analysis spreads across the model, because different control actions depend on different beliefs. If the concentration is real — a small system, or one belief that genuinely drives everything — state that explicitly. Do not quote the percentage above without this paragraph.</div>`
    : ""
}
${
  unbound.length
    ? `<div class="qualifier"><b>${unbound.length} finding(s) are UNBOUND</b> and do not count toward coverage — they reference no declared process-model variable or feedback channel, so they are not grounded in this system's control structure.</div>`
    : ""
}
${
  open.length
    ? `<div class="qualifier"><b>${open.length} cell(s) remain OPEN.</b> An open cell is a hole in the analysis, not a pass.</div>`
    : ""
}

${
  scopeBreach
    ? `<div class="qualifier incomplete"><b>SCOPE NOT DELIVERED AS REQUESTED.</b> A <strong>full-surface</strong> analysis was requested; ${modeledCAs} of ${candidateCAs} control actions were modeled. The ${candidateCAs! - modeledCAs} unmodeled action(s) are <strong>outstanding work, not a declared boundary</strong> — read the coverage figures below with that in mind.</div>`
    : ""
}
${
  missingSections.length
    ? `<div class="qualifier incomplete"><b>THIS REPORT IS INCOMPLETE — ${missingSections.length} of ${SECTIONS.length} sections are absent.</b>
       <ul>${missingSections.map((x) => `<li><strong>${esc(x.label)}</strong>${x.weight === "core" ? ' <span class="req">required</span>' : ""} — ${esc(x.why)} <span class="muted">(${esc(x.file)})</span></li>`).join("")}</ul>
       Findings below are real, but this document is not yet a deliverable: nothing here tells a reader which findings matter, what they cost, or where to start.</div>`
    : ""
}
  <div class="bars"><h4>What kind of thing goes wrong ${anyBanded ? `<span class="barsub">bar length = how many · colour = how urgent</span>` : `<span class="barsub">bar length = how many</span>`}</h4>
  ${typeCounts
    .map(
      (t) => `<div class="bar">
        <div class="blabel"><div class="bname">${esc(t.label)}</div><div class="bhint">${esc(t.hint)}</div></div>
        <div class="track"><div class="fill" style="width:${(t.n / maxType) * 100}%">${
          anyBanded
            ? t.byBand
                .map((n, i) => (n ? `<div class="seg sb-${i + 1}" style="width:${t.n ? (n / t.n) * 100 : 0}%" title="${n} in band ${i + 1}"></div>` : ""))
                .join("") + (t.unbanded ? `<div class="seg sb-x" style="width:${t.n ? (t.unbanded / t.n) * 100 : 0}%" title="${t.unbanded} not yet planned"></div>` : "")
            : `<div class="seg sb-x" style="width:100%"></div>`
        }</div></div>
        <div class="n">${t.n}</div>
      </div>`,
    )
    .join("")}
  ${
    anyBanded
      ? `<div class="barlegend"><span class="lg"><i class="sw sb-1"></i>band 1 · fix before ship</span><span class="lg"><i class="sw sb-2"></i>band 2 · this cycle</span><span class="lg"><i class="sw sb-3"></i>band 3 · scheduled</span><span class="lg"><i class="sw sb-4"></i>band 4 · accepted</span><span class="lg"><i class="sw sb-x"></i>not yet planned</span></div>`
      : ""
  }
  <p class="barfoot">These are the four ways a control action can be unsafe (STPA terms: ${typeCounts.map((t) => `<em>${esc(t.term)}</em>`).join(", ")}). They describe the <strong>system</strong>, not this analysis.</p>
  </div>

  <nav class="toc">
    <a href="#primer">Reading this report</a>
    ${overviewHtml ? `<a href="#overview" class="primary">▸ What this system is</a>` : ""}
    <a href="#structure">How it's built</a>
    ${boundaryHtml ? '<a href="#boundary">Boundary &amp; seams</a>' : ""}
    ${atStakeHtml ? `<a href="#stake">What's at stake</a>` : ""}
    ${focusHtml ? `<a href="#focus" class="primary">▸ Where to focus</a>` : ""}
    <a href="#scenarios">How it goes wrong</a>
    <a href="#constraints">What stops it</a>
    <a href="#grid">Full grid</a>
    <a href="#pm">Process models</a>
    ${plan ? '<a href="#plan">Engineering plan</a>' : ""}
  </nav>
</header>

<!-- Narrative arc: what it is → how it's built → the seams → what's at stake →
     the unsafe actions → scenarios → constraints → what to do (plan, last). -->
<!-- Narrative arc: primer/glossary → what it is → how it's built (diagram) → the
     seams → what's at stake → where to focus → findings & analysis → plan (last). -->
${primerHtml}

${trustPanelHtml}

${overviewHtml}

${structureHtml}

${boundaryHtml}

${atStakeHtml}

${focusHtml}

${section("scenarios", "6 · How it goes wrong — loss scenarios", read("04-scenarios.md"), true)}
${section("chains", "6b · How findings chain — composed reachability", read("07-chains.md"), true)}
${section("constraints", "7 · What must hold to stop it — security constraints", read("05-constraints.md"))}

<section id="grid" class="block"><h2>8 · Unsafe control actions — the full enumeration</h2>
<p>The exhaustive backing for the scenarios above: every control action considered against all four UCA types — <strong>${grid.totalCells}</strong> cells. A cell resolves as a finding bound to a declared control-structure element, or as a tombstone with a written reason. Both are results; an open cell is not.</p>
${singlePlane ? "" : `<p class="foldhint">Grouped by plane below and collapsed to the counts — click a plane to open its control actions.</p>`}
</section>
${findingCards}

${
  pmRows || fbRows
    ? `<section id="pm"><details class="fold"><summary><span class="foldh">9 · What each part believes — process models &amp; feedback</span></summary><div class="foldbody">
  <p>The detailed belief table: what each controller <em>believes</em>, where the belief comes from, and how stale it can be. Process-model inconsistency is the general form of the authorization bug — this is the reference behind the findings above.</p>
  ${pmRows ? `<div class="tablewrap"><table><thead><tr><th>ID</th><th>Controller</th><th>Believes</th><th>Sourced from</th><th>Staleness</th></tr></thead><tbody>${pmRows}</tbody></table></div>` : ""}
  ${fbRows ? `<h3>Feedback channels</h3><div class="tablewrap"><table><thead><tr><th>ID</th><th>Path</th><th>Signal</th></tr></thead><tbody>${fbRows}</tbody></table></div>` : ""}
  </div></details></section>`
    : ""
}

${planHtml}

<footer>
<p>Generated by <strong>stpa</strong> · method: STPA (Leveson &amp; Thomas, <em>STPA Handbook</em>, 2018) with the STPA-Sec security framing (Young &amp; Leveson, <em>CACM</em> 57(2), 2014).
Coverage counts findings bound to a declared control-structure element plus reasoned tombstones. The stopping rule and the prioritisation banding are additions to STPA, not STPA doctrine, and are never probabilities.</p>
<a class="brand" href="https://triarchsecurity.com" target="_blank" rel="noopener noreferrer">
<img class="tmark" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEgAAABGCAYAAABv59I3AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAADRmVYSWZNTQAqAAAACAAIARIAAwAAAAEAAQAAARoABQAAAAEAAABuARsABQAAAAEAAAB2ASgAAwAAAAEAAgAAATEAAgAAAAgAAAB+ATIAAgAAABQAAACGATsAAgAAABAAAACah2kABAAAAAEAAACqAAAAAAAAAGAAAAABAAAAYAAAAAFQaWNzYXJ0ADIwMjY6MDI6MTUgMTA6MjU6NTEAdHJpYXJjaHNlY3VyaXR5AAAFkAMAAgAAABQAAADsoAEAAwAAAAEAAQAAoAIABAAAAAEAAABIoAMABAAAAAEAAABGpDAAAgAAAkUAAAEAAAAAADIwMjY6MDI6MTUgMTA6MjU6NTEAeyJzdWJzb3VyY2UiOiJkb25lX2J1dHRvbiIsInVpZCI6IkE0QTM4RTQwLTM5QjQtNDVERC04NzRCLUM4MkMyMDAwOUJERSIsInNvdXJjZSI6Im90aGVyIiwib3JpZ2luIjoidW5rbm93biIsInRyYW5zcGFyZW5jeV92YWx1ZSI6eyJtYXhfYWxwaGEiOjEsIm1pbl9hbHBoYSI6MCwib3BhY2l0eTkwIjp7InBlcmNlbnRhZ2UiOjkzLjkwNzk4OTUwMTk1MzEyNSwib3BhcXVlX2JvdW5kcyI6eyJ5IjoxODQsInciOjEwMjUsIngiOjIwNSwiaCI6OTg0fX0sIm9wYWNpdHkwIjp7InBlcmNlbnRhZ2UiOjkyLjE2Mjg1NzA1NTY2NDA2Miwib3BhcXVlX2JvdW5kcyI6eyJ5IjoxODAsInciOjEwMzIsIngiOjIwMSwiaCI6OTkyfX0sIm9wYWNpdHk5OSI6eyJwZXJjZW50YWdlIjo5NC40MTAxOTQzOTY5NzI2NTYsIm9wYXF1ZV9ib3VuZHMiOnsieSI6MTg1LCJ3IjoxMDIzLCJ4IjoyMDYsImgiOjk4Mn19fSwidXRfdHlwZV9tZXRhIjoicHVibGljLnBuZyIsInVzZWRfc291cmNlcyI6IntcInZlcnNpb25cIjoxLFwic291cmNlc1wiOltdfSIsImlzX3JlbWl4IjpmYWxzZSwicHJlbWl1bV9zb3VyY2VzIjpbXSwiZnRlX3NvdXJjZXMiOltdfQAASBEMHAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAB3JpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IlhNUCBDb3JlIDYuMC4wIj4KICAgPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICAgICAgPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIKICAgICAgICAgICAgeG1sbnM6ZXhpZj0iaHR0cDovL25zLmFkb2JlLmNvbS9leGlmLzEuMC8iCiAgICAgICAgICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgICAgICAgICAgeG1sbnM6dGlmZj0iaHR0cDovL25zLmFkb2JlLmNvbS90aWZmLzEuMC8iCiAgICAgICAgICAgIHhtbG5zOnBob3Rvc2hvcD0iaHR0cDovL25zLmFkb2JlLmNvbS9waG90b3Nob3AvMS4wLyIKICAgICAgICAgICAgeG1sbnM6ZXhpZkVYPSJodHRwOi8vY2lwYS5qcC9leGlmLzEuMC8iCiAgICAgICAgICAgIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyI+CiAgICAgICAgIDxleGlmOkNvbG9yU3BhY2U+MTwvZXhpZjpDb2xvclNwYWNlPgogICAgICAgICA8ZXhpZjpQaXhlbFhEaW1lbnNpb24+MTAwPC9leGlmOlBpeGVsWERpbWVuc2lvbj4KICAgICAgICAgPGV4aWY6UGl4ZWxZRGltZW5zaW9uPjk4PC9leGlmOlBpeGVsWURpbWVuc2lvbj4KICAgICAgICAgPHhtcDpNb2RpZnlEYXRlPjIwMjYtMDItMTVUMTA6MjU6NTE8L3htcDpNb2RpZnlEYXRlPgogICAgICAgICA8eG1wOkNyZWF0b3JUb29sPlBpY3NhcnQ8L3htcDpDcmVhdG9yVG9vbD4KICAgICAgICAgPHRpZmY6UmVzb2x1dGlvblVuaXQ+MjwvdGlmZjpSZXNvbHV0aW9uVW5pdD4KICAgICAgICAgPHRpZmY6T3JpZW50YXRpb24+MTwvdGlmZjpPcmllbnRhdGlvbj4KICAgICAgICAgPHRpZmY6WFJlc29sdXRpb24+OTY8L3RpZmY6WFJlc29sdXRpb24+CiAgICAgICAgIDx0aWZmOllSZXNvbHV0aW9uPjk2PC90aWZmOllSZXNvbHV0aW9uPgogICAgICAgICA8cGhvdG9zaG9wOkRhdGVDcmVhdGVkPjIwMjYtMDItMTVUMTA6MjU6NTE8L3Bob3Rvc2hvcDpEYXRlQ3JlYXRlZD4KICAgICAgICAgPGV4aWZFWDpDYW1lcmFPd25lck5hbWU+eyJzdWJzb3VyY2UiOiJkb25lX2J1dHRvbiIsInVpZCI6IkE0QTM4RTQwLTM5QjQtNDVERC04NzRCLUM4MkMyMDAwOUJERSIsInNvdXJjZSI6Im90aGVyIiwib3JpZ2luIjoidW5rbm93biIsInRyYW5zcGFyZW5jeV92YWx1ZSI6eyJtYXhfYWxwaGEiOjEsIm1pbl9hbHBoYSI6MCwib3BhY2l0eTkwIjp7InBlcmNlbnRhZ2UiOjkzLjkwNzk4OTUwMTk1MzEyNSwib3BhcXVlX2JvdW5kcyI6eyJ5IjoxODQsInciOjEwMjUsIngiOjIwNSwiaCI6OTg0fX0sIm9wYWNpdHkwIjp7InBlcmNlbnRhZ2UiOjkyLjE2Mjg1NzA1NTY2NDA2Miwib3BhcXVlX2JvdW5kcyI6eyJ5IjoxODAsInciOjEwMzIsIngiOjIwMSwiaCI6OTkyfX0sIm9wYWNpdHk5OSI6eyJwZXJjZW50YWdlIjo5NC40MTAxOTQzOTY5NzI2NTYsIm9wYXF1ZV9ib3VuZHMiOnsieSI6MTg1LCJ3IjoxMDIzLCJ4IjoyMDYsImgiOjk4Mn19fSwidXRfdHlwZV9tZXRhIjoicHVibGljLnBuZyIsInVzZWRfc291cmNlcyI6IntcInZlcnNpb25cIjoxLFwic291cmNlc1wiOltdfSIsImlzX3JlbWl4IjpmYWxzZSwicHJlbWl1bV9zb3VyY2VzIjpbXSwiZnRlX3NvdXJjZXMiOltdfTwvZXhpZkVYOkNhbWVyYU93bmVyTmFtZT4KICAgICAgICAgPGRj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" alt="" width="26" height="25">
  <span class="btxt"><b>Triarch Security</b><span class="bsub">triarchsecurity.com</span></span>
</a>
</footer>
</div></body></html>`;

try {
  writeFileSync(outPath, html);
} catch (e) {
  die(`cannot write ${outPath}: ${(e as Error).message}`);
}
console.error(`wrote ${outPath}  (${grid.totalCells} cells, ${findings.length} findings, ${pct.toFixed(1)}% coverage${concentrated ? ", CONCENTRATED" : ""})`);
const missingCore = missingSections.filter((x) => x.weight === "core");
if (missingCore.length) {
  console.error(`\nINCOMPLETE — ${missingCore.length} required section(s) absent:`);
  for (const x of missingCore) console.error(`  ${x.file.padEnd(22)} ${x.label} — ${x.why}`);
  console.error(`\nThe report rendered, but it is not a deliverable yet. Exit 5.`);
  process.exit(5);
}
