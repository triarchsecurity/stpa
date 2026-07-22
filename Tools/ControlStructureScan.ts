#!/usr/bin/env bun
/**
 * ControlStructureScan.ts — candidate extraction for STPA Step 2.
 *
 * Modeling the control structure is the expensive, judgment-heavy part of STPA
 * and the reason people abandon it on real codebases. This tool does not model
 * anything. It enumerates the *places in the repo where control is exercised*,
 * so the analyst starts from a list instead of a blank page.
 *
 * Four categories, because these are the four things a control loop is made of:
 *   entryPoints    — where external actors inject control actions (routes, handlers,
 *                    queue consumers, cron, CLI, webhooks, event subscriptions)
 *   guards         — where authority decisions are made (middleware, auth checks,
 *                    policy evaluation, tenant scoping, rate limits)
 *   dataAccess     — where the controlled process is actually read/written
 *   externalEffects— where control leaves the system (payments, mail, deploy, IAM,
 *                    outbound HTTP, shell execution)
 *
 * EVERYTHING THIS EMITS IS A CANDIDATE, NOT A FINDING. Pattern matching cannot
 * tell you what a controller believes. The analyst confirms, merges, discards,
 * and — most importantly — adds the controllers that leave no textual trace
 * (humans, operators, third parties, the deploy pipeline, the DBA with prod access).
 *
 * Language-agnostic by design: patterns are regex heuristics tagged by ecosystem,
 * and unknown stacks still get the generic sweep.
 *
 * Usage:
 *   bun ControlStructureScan.ts <repo-path> [--json] [--max-per-category N] [--include-tests]
 *
 * Default output is a human-readable report; --json emits the structured candidate
 * set that feeds the ModelControlStructure workflow.
 */

import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, relative, extname } from "node:path";

interface Hit {
  file: string;
  line: number;
  text: string;
  pattern: string;
  ecosystem: string;
  tags?: string;
}

interface Category {
  key: "entryPoints" | "guards" | "dataAccess" | "externalEffects";
  label: string;
  note: string;
  patterns: { re: RegExp; name: string; ecosystem: string; tags?: string }[];
}

const CATEGORIES: Category[] = [
  {
    key: "entryPoints",
    label: "Entry points — where external actors inject control actions",
    note: "Each of these is a place an adversary can attempt to issue a control action. Every entry point maps to >=1 control action in the model.",
    patterns: [
      { re: /\b(?:app|router|server|api)\.(get|post|put|patch|delete|all)\s*\(/i, name: "express-style route", ecosystem: "node" , tags: "api,http" },
      { re: /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/, name: "next.js route handler", ecosystem: "next" , tags: "api,http" },
      { re: /@(Get|Post|Put|Patch|Delete|All)\s*\(/, name: "decorator route", ecosystem: "nest/ts" , tags: "api,http" },
      { re: /@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\b/, name: "spring mapping", ecosystem: "java" , tags: "api,http" },
      { re: /@(app|router|blueprint)\.(route|get|post|put|patch|delete)\s*\(/, name: "flask/fastapi route", ecosystem: "python" , tags: "api,http" },
      { re: /\bfunc\s+\w*(Handler|Handle)\s*\(\s*\w+\s+http\.ResponseWriter/, name: "go http handler", ecosystem: "go" , tags: "api,http" },
      { re: /\b(?:resources|get|post|patch|put|delete)\s+['"]\//, name: "rails route", ecosystem: "ruby" , tags: "api,http" },
      { re: /\b(?:consume|subscribe|onMessage|handleMessage|processMessage)\s*\(/i, name: "queue/event consumer", ecosystem: "generic" , tags: "queue,async" },
      { re: /\b(cron|schedule|setInterval|CronJob|@Scheduled)\b/, name: "scheduled trigger", ecosystem: "generic" , tags: "cron,async" },
      { re: /\bwebhook/i, name: "webhook surface", ecosystem: "generic" , tags: "webhook,api" },
      { re: /\b(?:process\.argv|commander|yargs|argparse|clap::)\b/, name: "CLI entry", ecosystem: "generic" , tags: "cli" },
      { re: /\b(?:onRequest|onCall|functions\.https)\b/, name: "serverless entry", ecosystem: "firebase/faas" , tags: "api,serverless" },
      { re: /\b(?:graphql|Resolver|typeDefs|@Query|@Mutation)\b/, name: "graphql surface", ecosystem: "generic" , tags: "api,graphql" },
      // Server actions are entry points that are NOT routes. Missing them leaves an
      // entire parallel write surface outside the control structure while the route
      // count implies full coverage — found the hard way on a real analysis where 53
      // routes were enumerated and 19 "use server" modules wrote the same tables.
      { re: /^\s*['"]use server['"]/m, name: "server action module", ecosystem: "next", tags: "api,rpc,serveraction" },
      { re: /\b(?:createServerFn|defineAction|server\$|useServerAction)\b/, name: "rpc action helper", ecosystem: "generic", tags: "rpc,serveraction" },
      { re: /\b(?:publicProcedure|protectedProcedure|\.mutation\(|\.query\()/, name: "trpc procedure", ecosystem: "trpc", tags: "api,rpc,serveraction" },
    ],
  },
  {
    key: "guards",
    label: "Guards — where authority decisions are made",
    note: "These are the controllers whose process model matters most. A guard is only as correct as its beliefs about identity, role, tenancy, and freshness.",
    patterns: [
      { re: /\b(?:requireAuth|isAuthenticated|ensureLoggedIn|authGuard|withAuth|authenticate)\b/i, name: "authn check", ecosystem: "generic" , tags: "auth,authn" },
      { re: /\b(?:authorize|can|ability|hasPermission|hasRole|checkPermission|requireRole|isAdmin|enforce)\b/i, name: "authz check", ecosystem: "generic" , tags: "auth,authz" },
      { re: /\buse\s*\(\s*\w*(?:auth|guard|middleware|protect)/i, name: "middleware mount", ecosystem: "node" , tags: "auth,middleware" },
      { re: /\b(?:middleware|beforeEach|before_action|Depends\s*\()/i, name: "middleware/filter", ecosystem: "generic" , tags: "auth,middleware" },
      { re: /\b(?:jwt|jose|verifyToken|decodeToken|jwtVerify|validateSession)\b/i, name: "token validation", ecosystem: "generic" , tags: "auth,authn,crypto" },
      { re: /\b(?:tenantId|tenant_id|orgId|org_id|workspaceId|accountId)\b/, name: "tenancy scoping", ecosystem: "generic" , tags: "authz,tenancy" },
      { re: /\b(?:rateLimit|rate_limit|throttle|Ratelimit|limiter)\b/i, name: "rate limiting", ecosystem: "generic" , tags: "ratelimit" },
      { re: /\b(?:csrf|sameSite|originCheck|cors)\b/i, name: "request-origin control", ecosystem: "generic" , tags: "auth,web" },
      { re: /\b(?:featureFlag|isEnabled|flags?\.\w+|unleash|launchdarkly)\b/i, name: "feature flag gate", ecosystem: "generic" , tags: "authz,config" },
      { re: /\b(?:allow|deny|Policy|policy|rbac|abac|casbin|opa)\b/, name: "policy engine", ecosystem: "generic" , tags: "authz,policy" },
    ],
  },
  {
    key: "dataAccess",
    label: "Data access — where the controlled process is read and written",
    note: "Every path that reaches storage without passing a guard is a candidate bypass. Compare this list against the guard list, not against itself.",
    patterns: [
      { re: /\b(?:db|prisma|knex|drizzle|sequelize|mongoose)\.\w+/, name: "orm/query builder", ecosystem: "node" , tags: "data" },
      { re: /\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/, name: "raw sql", ecosystem: "generic" , tags: "data,sql" },
      { re: /\b(?:session|cookies?)\.(get|set|delete)\b/i, name: "session store access", ecosystem: "generic" , tags: "data,auth" },
      { re: /\b(?:redis|memcached|cache)\.(get|set|del)\b/i, name: "cache access", ecosystem: "generic" , tags: "data,cache" },
      { re: /\b(?:s3|blob|bucket|storage)\.(get|put|upload|download|delete)/i, name: "object storage", ecosystem: "generic" , tags: "data,storage" },
      { re: /\b(?:collection|doc|firestore)\s*\(/, name: "document store", ecosystem: "firebase" , tags: "data" },
      { re: /\b(?:readFileSync|writeFileSync|fs\.(read|write)|open\s*\()/, name: "filesystem access", ecosystem: "generic" , tags: "data,fs" },
    ],
  },
  {
    key: "externalEffects",
    label: "External effects — where control leaves the system",
    note: "Actions here are irreversible or externally visible. They deserve UCA analysis even when nothing is 'protected' behind them.",
    patterns: [
      { re: /\b(?:stripe|paypal|charge|refund|payout|createPaymentIntent)\b/i, name: "payment effect", ecosystem: "generic" , tags: "effects,payments" },
      { re: /\b(?:sendMail|sendEmail|sendgrid|ses\.|nodemailer|twilio|sendSms)\b/i, name: "messaging effect", ecosystem: "generic" , tags: "effects,messaging" },
      { re: /\b(?:deploy|firebase\s+deploy|kubectl|terraform|helm|gh\s+workflow|actions\/)\b/i, name: "deploy effect", ecosystem: "generic" , tags: "effects,deploy" },
      { re: /\b(?:iam|createUser|deleteUser|assignRole|grantRole|setIamPolicy)\b/i, name: "identity effect", ecosystem: "generic" , tags: "effects,iam" },
      { re: /\b(?:exec|execSync|spawn|child_process|system\s*\(|subprocess\.)/, name: "process execution", ecosystem: "generic" , tags: "effects,exec" },
      { re: /\b(?:fetch|axios|got|requests\.(get|post)|http\.Client)\b/, name: "outbound http", ecosystem: "generic" , tags: "effects,net" },
      { re: /\b(?:publish|emit|produce|sendMessage|enqueue)\s*\(/i, name: "outbound event", ecosystem: "generic" , tags: "effects,queue" },
    ],
  },
];

const CODE_EXT = new Set([
  // application languages
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".java",
  ".kt", ".cs", ".php", ".rs", ".ex", ".exs", ".scala", ".sql", ".pl", ".lua",
  // systems / embedded — STPA's home domain; omitting these was a real gap
  ".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".ino",
  // mobile
  ".swift", ".m", ".mm", ".dart",
  // shell and ops — deploy scripts are external-effect control actions, per SoftwareMapping.md
  ".sh", ".bash", ".zsh", ".ps1",
  // infrastructure as code
  ".yml", ".yaml", ".tf", ".tfvars", ".hcl", ".bicep",
]);

/** Extensionless files that still carry control structure. */
const CODE_FILENAMES = new Set([
  "Dockerfile", "Makefile", "Jenkinsfile", "Procfile", "Vagrantfile", "Containerfile",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "out", "vendor", "target",
  "__pycache__", ".venv", "venv", "coverage", ".turbo", ".cache", "public",
]);

const TEST_RE = /(^|[\/.])(test|tests|spec|__tests__|e2e|fixtures?|mocks?)([\/.]|$)/i;

/** Every lens any pattern declares — the closed vocabulary for --focus. */
const ALL_TAGS = new Set<string>(
  CATEGORIES.flatMap((c) => c.patterns.flatMap((p) => (p.tags ?? "").split(",").map((t) => t.trim()).filter(Boolean))),
);

/** Path substring filters from --include / --exclude. */
const pathFilters: { include: string[]; exclude: string[] } = { include: [], exclude: [] };

const FILE_BUDGET = 20000;

/** Set when the walk hit its file budget — surfaced everywhere, never silent. */
const truncation = { hit: false, skipped: 0 };

function walk(dir: string, root: string, includeTests: boolean, acc: string[], budget = { n: 0 }): string[] {
  if (budget.n > FILE_BUDGET) {
    truncation.hit = true;
    truncation.skipped++;
    return acc;
  }
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return acc;
  }
  for (const e of entries) {
    if (SKIP_DIRS.has(e)) continue;
    const p = join(dir, e);
    let st;
    try {
      st = statSync(p);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walk(p, root, includeTests, acc, budget);
    } else if (CODE_EXT.has(extname(e)) || CODE_FILENAMES.has(e)) {
      const rel = relative(root, p);
      if (!includeTests && TEST_RE.test(rel)) continue;
      if (pathFilters.exclude.some((g) => rel.includes(g))) continue;
      if (pathFilters.include.length && !pathFilters.include.some((g) => rel.includes(g))) continue;
      if (st.size > 1_500_000) continue;
      budget.n++;
      acc.push(p);
    }
  }
  return acc;
}

/** Per-category cap hits, recorded rather than silently dropped. */
const capped = new Map<string, number>();

function matchesFocus(p: { name: string; tags?: string }, focus: string[]): boolean {
  if (!focus.length) return true;
  const tags = (p.tags ?? "").split(",").map((t) => t.trim()).filter(Boolean);
  return focus.some((f) => tags.includes(f));
}

function scan(root: string, includeTests: boolean, maxPer: number, focus: string[]) {
  const files = walk(root, root, includeTests, []);
  const out: Record<string, Hit[]> = {
    entryPoints: [], guards: [], dataAccess: [], externalEffects: [],
  };
  const seen = new Set<string>();

  for (const f of files) {
    let content: string;
    try {
      content = readFileSync(f, "utf8");
    } catch {
      continue;
    }
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (line.length > 400) continue;
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("#")) continue;
      for (const cat of CATEGORIES) {
        for (const p of cat.patterns) {
          if (!matchesFocus(p, focus)) continue;
          if (p.re.test(line)) {
            if (out[cat.key]!.length >= maxPer) {
              // Cap reached. Count it and move on — a dropped hit that nothing
              // reports reads as an absent hit, which is the failure this whole
              // toolkit is about.
              capped.set(cat.key, (capped.get(cat.key) ?? 0) + 1);
              break;
            }
            const key = `${cat.key}:${relative(root, f)}:${i + 1}`;
            if (seen.has(key)) break;
            seen.add(key);
            out[cat.key]!.push({
              file: relative(root, f),
              line: i + 1,
              text: trimmed.slice(0, 180),
              pattern: p.name,
              ecosystem: p.ecosystem,
              tags: p.tags,
            });
            break;
          }
        }
      }
    }
  }
  return { filesScanned: files.length, candidates: out };
}

function summarize(hits: Hit[]) {
  const byPattern = new Map<string, number>();
  const byFile = new Map<string, number>();
  for (const h of hits) {
    byPattern.set(h.pattern, (byPattern.get(h.pattern) ?? 0) + 1);
    byFile.set(h.file, (byFile.get(h.file) ?? 0) + 1);
  }
  return {
    byPattern: [...byPattern.entries()].sort((a, b) => b[1] - a[1]),
    topFiles: [...byFile.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10),
  };
}

// ---- main ----
const argv = process.argv.slice(2);

if (argv.includes("--list-focus")) {
  console.log("Focus lenses (--focus a,b,c). A pattern matches if it carries ANY named lens.\n");
  for (const cat of CATEGORIES) {
    console.log(`${cat.label}`);
    const seen = new Map<string, string[]>();
    for (const p of cat.patterns) {
      for (const t of (p.tags ?? "").split(",").map((x) => x.trim()).filter(Boolean)) {
        if (!seen.has(t)) seen.set(t, []);
        seen.get(t)!.push(p.name);
      }
    }
    for (const [t, names] of [...seen].sort()) console.log(`  ${t.padEnd(12)} ${names.join(", ")}`);
    console.log("");
  }
  console.log("Common combinations:");
  console.log("  --focus authz,tenancy     authorization and multi-tenancy boundaries");
  console.log("  --focus api,webhook       every externally reachable entry point");
  console.log("  --focus auth,authn,crypto the authentication plane");
  console.log("  --focus effects,payments  irreversible and money-moving actions");
  console.log("  --focus cron,queue,async  the unattended plane (usually over-privileged, under-reviewed)");
  process.exit(0);
}

const root = argv.find((a) => !a.startsWith("-"));
if (!root) {
  console.error(
    [
      "ControlStructureScan.ts — candidate extraction for STPA Step 2",
      "",
      "Usage: bun ControlStructureScan.ts <repo-path> [options]",
      "",
      "  --focus <lenses>      comma-separated; only patterns carrying these tags",
      "                        e.g. --focus authz,tenancy   or   --focus api",
      "  --list-focus          print every available lens and exit",
      "  --depth <level>       survey | standard (default) | deep",
      "                          survey   counts + hot files only; fast on huge repos",
      "                          standard capped per category, tests excluded",
      "                          deep     no cap, tests included, every hit listed",
      "  --include <substr>    only paths containing this (repeatable)",
      "  --exclude <substr>    skip paths containing this (repeatable)",
      "  --max-per-category N  override the cap (default 300; ignored at depth=deep)",
      "  --include-tests       include test/fixture paths",
      "  --json                structured output",
      "",
      "Emits CANDIDATE control-structure elements. Everything it produces requires",
      "analyst confirmation; controllers with no textual trace (humans, operators,",
      "third parties, prod DB access) must be added by hand.",
    ].join("\n"),
  );
  process.exit(2);
}
try {
  if (!statSync(root).isDirectory()) throw new Error("not a directory");
} catch {
  console.error(`not a readable directory: ${root}`);
  process.exit(1);
}

const asJson = argv.includes("--json");

const depthIdx = argv.indexOf("--depth");
const depth = (depthIdx !== -1 ? argv[depthIdx + 1] : "standard") as "survey" | "standard" | "deep";
if (!["survey", "standard", "deep"].includes(depth)) {
  console.error(`unknown --depth "${depth}" (survey | standard | deep)`);
  process.exit(2);
}

const focusIdx = argv.indexOf("--focus");
const focus = focusIdx !== -1 ? (argv[focusIdx + 1] ?? "").split(",").map((f) => f.trim().toLowerCase()).filter(Boolean) : [];
const unknownFocus = focus.filter((f) => !ALL_TAGS.has(f));
if (unknownFocus.length) {
  console.error(`unknown focus lens: ${unknownFocus.join(", ")}\n\nAvailable: ${[...ALL_TAGS].sort().join(", ")}`);
  process.exit(2);
}

const collectRepeat = (flag: string) =>
  argv.reduce<string[]>((acc, a, i) => (a === flag && argv[i + 1] ? [...acc, argv[i + 1]!] : acc), []);
const includeGlobs = collectRepeat("--include");
const excludeGlobs = collectRepeat("--exclude");

const includeTests = argv.includes("--include-tests") || depth === "deep";
const mpIdx = argv.indexOf("--max-per-category");
const maxPer = depth === "deep" ? Number.MAX_SAFE_INTEGER : mpIdx !== -1 ? Number(argv[mpIdx + 1]) || 300 : 300;

pathFilters.include = includeGlobs;
pathFilters.exclude = excludeGlobs;

const result = scan(root, includeTests, maxPer, focus);

if (asJson) {
  console.log(
    JSON.stringify(
      {
        root,
        scannedAt: new Date().toISOString(),
        filesScanned: result.filesScanned,
        depth,
        focus: focus.length ? focus : "all",
        include: includeGlobs.length ? includeGlobs : null,
        exclude: excludeGlobs.length ? excludeGlobs : null,
        capPerCategory: depth === "deep" ? null : maxPer,
        droppedByCap: Object.fromEntries(capped),
        capWarning: capped.size
          ? `INCOMPLETE PER CATEGORY — ${[...capped.values()].reduce((a, b) => a + b, 0)} matches were dropped after the ${maxPer}-per-category cap. Re-run with --depth deep or a higher --max-per-category to see them.`
          : null,
        truncated: truncation.hit,
        fileBudget: FILE_BUDGET,
        truncationWarning: truncation.hit
          ? `INCOMPLETE SCAN — the ${FILE_BUDGET}-file budget was reached, so parts of this repository were never read. Treat absence of candidates as unknown, not as absence of control structure. Re-run against subdirectories, or slice by trust boundary.`
          : null,
        status: "CANDIDATES — require analyst confirmation; not ground truth",
        caveat:
          "Pattern matching finds where control is exercised in text. It cannot find controllers with no code trace (human operators, third-party services, direct database access, the deploy pipeline itself). Add those by hand before modeling.",
        candidates: result.candidates,
      },
      null,
      2,
    ),
  );
  process.exit(0);
}

console.log(`STPA control-structure candidates — ${root}`);
console.log(`files scanned: ${result.filesScanned}   depth: ${depth}   focus: ${focus.length ? focus.join(",") : "all"}`);
if (includeGlobs.length) console.log(`include: ${includeGlobs.join(", ")}`);
if (excludeGlobs.length) console.log(`exclude: ${excludeGlobs.join(", ")}`);
if (capped.size) {
  const total = [...capped.values()].reduce((a, b) => a + b, 0);
  console.log(`\n!! ${total} MATCHES DROPPED by the ${maxPer}-per-category cap:`);
  for (const [k, n] of capped) console.log(`     ${k}: ${n} not shown`);
  console.log(`   Re-run with --depth deep (no cap) or --max-per-category N to see them.`);
}
if (truncation.hit) {
  console.log(`\n!! INCOMPLETE SCAN — the ${FILE_BUDGET}-file budget was reached. Parts of this`);
  console.log(`   repository were NEVER READ. Absence of candidates below means unknown, not`);
  console.log(`   absent. Re-run against subdirectories, or slice the analysis by trust boundary.`);
}
console.log(`\n!! CANDIDATES ONLY — these require analyst confirmation. Controllers with no`);
console.log(`   code trace (humans, operators, third parties, direct prod DB access, the`);
console.log(`   deploy pipeline) will NOT appear here and must be added by hand.\n`);

for (const cat of CATEGORIES) {
  const hits = result.candidates[cat.key]!;
  console.log(`=== ${cat.label} — ${hits.length} candidates ===`);
  console.log(`    ${cat.note}`);
  if (!hits.length) {
    console.log(`    (none matched — either absent, or this stack's idiom is unrecognized; sweep manually)\n`);
    continue;
  }
  const sum = summarize(hits);
  console.log(`    by pattern: ${sum.byPattern.map(([p, n]) => `${p}(${n})`).join(", ")}`);
  console.log(`    hot files:`);
  for (const [f, n] of sum.topFiles) console.log(`      ${String(n).padStart(4)}  ${f}`);
  if (depth === "deep") {
    console.log(`    all ${hits.length} hits:`);
    for (const h of hits) console.log(`      ${h.file}:${h.line}  [${h.pattern}]  ${h.text.slice(0, 110)}`);
  }
  console.log("");
}

console.log(`Next: stpa init <model.json> — after you have written the model.`);
