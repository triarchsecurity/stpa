#!/usr/bin/env bun
/**
 * VerifyGate.ts — adversarial peer-review gate. Output must be independently
 * reviewed before a human sees it; this refuses to certify a report that wasn't.
 *
 * WHY THIS EXISTS. An analysis is produced by the reasoning of one model, and a
 * single model rationalises its own inflation — it rated a latent, single-tenant,
 * internal path as a live cross-tenant one and shipped it. The fix is structural,
 * not exhortation: every finding must survive an adversarial review by a
 * DIFFERENT model (cross-vendor where possible), and the review must be recorded,
 * so "peer-reviewed before a human" is a gate, not a good intention. Objective
 * self-assessment is computed here from the record — never self-narrated.
 *
 * The review REASONING is done by review agents at analysis time (see
 * Workflows/AdversarialReview.md); this tool only checks the record they wrote
 * and refuses to pass if it is missing, self-reviewed, or incomplete.
 *
 * Usage:
 *   bun VerifyGate.ts <analysis-dir> [--warn-only]
 *
 * reviews.json (written by the adversarial-review pass):
 *   {
 *     "authorModel":   "claude-opus-4-8",
 *     "reviewerModel": "gpt-5.5",            // MUST differ from authorModel
 *     "findings": {
 *       "CA-x.provided": {
 *         "verdict": "confirmed|downgrade|provisional|refuted",
 *         "reasons": ["..."],
 *         "reachabilityPath": "the concrete deployed path — required for a confirmed-live finding",
 *         "zone": "per-deployment|central-plane|customer-cloud|...",
 *         "newBand": 3,           // when downgrade
 *         "assumption": "A-4"     // when provisional
 *       }, ...
 *     }
 *   }
 *
 * Exit: 0 pass · 3 no review · 4 not independent · 5 unreviewed findings ·
 *       6 confirmed-live finding with no deployed reachability path.
 * Writes review-scorecard.json for the renderer regardless of pass/fail.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) {
  console.log(
    [
      "VerifyGate.ts — adversarial peer-review gate",
      "",
      "Usage: bun VerifyGate.ts <analysis-dir> [--warn-only]",
      "",
      "Refuses to certify an analysis unless every UCA finding was reviewed by an",
      "INDEPENDENT model and every confirmed-live finding names a deployed path.",
      "Objective self-assessment is computed from reviews.json, never narrated.",
    ].join("\n"),
  );
  process.exit(2);
}
const warnOnly = argv.includes("--warn-only");
const dir = resolve(argv.find((a) => !a.startsWith("-")) ?? ".stpa");

function die(msg: string, code: number): never {
  console.error(msg);
  process.exit(warnOnly ? 0 : code);
}
function readJson(p: string): any | null {
  const f = join(dir, p);
  if (!existsSync(f)) return null;
  try {
    return JSON.parse(readFileSync(f, "utf8"));
  } catch (e) {
    die(`${p} is not valid JSON: ${(e as Error).message}`, 2);
  }
}

const grid = readJson("grid.json");
if (!grid) die(`no grid.json in ${dir}`, 2);
const findings: any[] = (grid.cells ?? []).filter((c: any) => c.state === "uca");
const reviews = readJson("reviews.json");

// bands, if a plan exists — used to know which findings are "live" (band ≤2)
const remed = readJson("06-remediation.json") ?? readJson("remediation.json");
const bandOf = new Map<string, number>();
for (const w of remed?.waves ?? []) for (const it of w.items ?? []) bandOf.set(it.id, it.band);
const isLive = (id: string) => {
  const b = bandOf.get(id);
  return b === undefined ? true : b <= 2; // unknown → treat as live (conservative)
};

// ── compute the scorecard from the record (never narrated) ──────────────────
const total = findings.length;
const revMap: Record<string, any> = reviews?.findings ?? {};
const reviewed = findings.filter((f) => revMap[f.id]);
const byVerdict = (v: string) => reviewed.filter((f) => revMap[f.id]?.verdict === v).length;
const authorModel = reviews?.authorModel ?? null;
const reviewerModel = reviews?.reviewerModel ?? null;
const independent = !!(authorModel && reviewerModel && authorModel !== reviewerModel);
const liveConfirmed = findings.filter((f) => revMap[f.id]?.verdict === "confirmed" && isLive(f.id));
const liveWithPath = liveConfirmed.filter((f) => (revMap[f.id]?.reachabilityPath ?? "").trim());
const provisional = findings.filter((f) => revMap[f.id]?.verdict === "provisional");

const scorecard = {
  computedAt: null as string | null,
  reviewed: reviewed.length,
  total,
  reviewedPct: total ? Math.round((reviewed.length / total) * 100) : 0,
  independentReview: independent,
  authorModel,
  reviewerModel,
  confirmed: byVerdict("confirmed"),
  downgraded: byVerdict("downgrade"),
  provisional: provisional.length,
  refuted: byVerdict("refuted"),
  liveConfirmed: liveConfirmed.length,
  liveWithReachabilityPath: liveWithPath.length,
  reachabilityPathPct: liveConfirmed.length ? Math.round((liveWithPath.length / liveConfirmed.length) * 100) : 100,
  trustZonesModeled: Array.isArray(grid.scope?.trustZones) && grid.scope.trustZones.length > 0,
  passed: false as boolean,
};
writeFileSync(join(dir, "review-scorecard.json"), JSON.stringify(scorecard, null, 2));

// ── print + gate ────────────────────────────────────────────────────────────
console.log(`adversarial peer review — ${dir}\n`);
console.log(`  author model:    ${authorModel ?? "NOT RECORDED"}`);
console.log(`  reviewer model:  ${reviewerModel ?? "NOT RECORDED"}${independent ? "  (independent ✓)" : "  (NOT independent)"}`);
console.log(`  reviewed:        ${reviewed.length} / ${total} findings (${scorecard.reviewedPct}%)`);
console.log(`  verdicts:        ${scorecard.confirmed} confirmed · ${scorecard.downgraded} downgraded · ${scorecard.provisional} provisional · ${scorecard.refuted} refuted`);
console.log(`  live w/ deployed path: ${liveWithPath.length} / ${liveConfirmed.length} (${scorecard.reachabilityPathPct}%)`);
console.log(`  trust zones modeled:   ${scorecard.trustZonesModeled ? "yes" : "NO"}\n`);

if (!reviews) {
  die(
    [
      "!! NOT PEER-REVIEWED. No reviews.json — the output has not been independently",
      "   reviewed, so it must not be presented to a human as final. Run the",
      "   adversarial-review pass (Workflows/AdversarialReview.md) with a DIFFERENT",
      "   model than the one that authored the findings, then re-gate.",
    ].join("\n"),
    3,
  );
}
if (!independent) {
  die(
    `!! REVIEW NOT INDEPENDENT. author (${authorModel}) and reviewer (${reviewerModel}) must differ — a model does not catch the inflation it rationalises. Use a different (ideally cross-vendor) model for the review.`,
    4,
  );
}
const unreviewed = findings.filter((f) => !revMap[f.id]);
if (unreviewed.length) {
  console.error(`!! ${unreviewed.length} findings not reviewed:`);
  for (const f of unreviewed.slice(0, 20)) console.error(`   ${f.id}`);
  die(`   every finding must be adversarially reviewed before delivery.`, 5);
}
const missingPath = liveConfirmed.filter((f) => !(revMap[f.id]?.reachabilityPath ?? "").trim());
if (missingPath.length) {
  console.error(`!! ${missingPath.length} confirmed-LIVE findings name no deployed reachability path:`);
  for (const f of missingPath.slice(0, 20)) console.error(`   ${f.id}`);
  die(`   a live finding must name the concrete deployed path — code presence is not reachability.`, 6);
}

scorecard.passed = true;
writeFileSync(join(dir, "review-scorecard.json"), JSON.stringify(scorecard, null, 2));
console.log(`peer review complete — every finding survived an independent adversarial pass.`);
process.exit(0);
