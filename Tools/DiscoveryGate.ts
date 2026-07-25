#!/usr/bin/env bun
/**
 * DiscoveryGate.ts — STPA Step 2b: prove the INVENTORY was multi-modal before the grid exists.
 *
 * WHY THIS EXISTS (learned the hard way, 2026-07-25):
 *
 *   A full-surface run of a large TS monorepo enumerated authority by sweeping
 *   `app.get|post|put|delete` — 408 route registrations, collapsed to 25 control
 *   actions, and `ScopeGate` certified "full surface delivered" at 100%.
 *
 *   It missed an interactive PTY (`pty.spawn($SHELL, {env: {...process.env}})`)
 *   reachable over a WebSocket upgrade, and an in-process `.eval` command backed by
 *   `new Function()`. Both were band-1-class. Both had been found by an earlier run
 *   of the same target. Neither is an express route, so neither was ever a CANDIDATE
 *   — they were not rejected, they were never seen.
 *
 *   The coverage number was 100% and it was arithmetically honest, because coverage
 *   is computed over the inventory and the inventory was built from one modality.
 *   **A denominator built by a single search shape cannot be audited by a ratio.**
 *
 * So this tool does not ask the analyst whether discovery was thorough. It runs the
 * sweep itself, one pattern family per modality, and then requires that every
 * modality with hits is either mapped to control actions or explicitly ruled out
 * with a reason. Silence on a modality that has hits is a failure, not a pass.
 *
 * The modality list is the point. It is short, it is fixed, and it contains the
 * three shapes analysts reliably forget: non-HTTP entry points, in-process command
 * registries, and dynamic execution primitives.
 *
 * Usage:
 *   bun DiscoveryGate.ts <repo> [analysis-dir] [--json] [--check]
 *
 * Reads  <repo> source, and <analysis-dir>/discovery.json if present
 * Writes <analysis-dir>/discovery.json (a template, when absent)
 * Exit:  0 pass · 1 bad input · 7 a modality has hits but is neither mapped nor ruled out
 */

import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, extname } from "node:path";

interface Modality {
  id: string;
  label: string;
  why: string;
  patterns: RegExp[];
  /** Must be acknowledged even at zero hits — used where a grep is not evidence. */
  alwaysRequired?: boolean;
}

/**
 * Ten modalities. Every one of these has been, in some real system, the only path to
 * a band-1 finding. `http-routes` is first because it is what everyone does; the
 * three marked FORGOTTEN are the ones a route grep structurally cannot see.
 */
const MODALITIES: Modality[] = [
  {
    id: "http-routes",
    label: "HTTP route registrations",
    why: "the modality everyone runs; necessary and never sufficient",
    patterns: [
      /^\s*(?:app|router|r|server|api)\s*\.\s*(?:get|post|put|patch|delete|options|all)\s*\(/,
      /@(?:Get|Post|Put|Patch|Delete|RequestMapping|route)\s*\(/,
      /^\s*(?:@app\.route|app\.add_url_rule)\s*\(/,
    ],
  },
  {
    id: "websocket",
    label: "WebSocket / upgrade handlers  [FORGOTTEN]",
    why: "an upgrade handler is an entry point with its own auth path and no route registration; this is what hid an interactive shell",
    patterns: [
      /\.on\s*\(\s*['"`]upgrade['"`]/,
      /new\s+WebSocketServer\s*\(/,
      /require\s*\(\s*['"`]ws['"`]/,
      /socket\.io|io\s*\.\s*on\s*\(\s*['"`]connection/,
      /addEventListener\s*\(\s*['"`]message['"`]/,
    ],
  },
  {
    id: "command-registry",
    label: "In-process command / tool registries  [FORGOTTEN]",
    why: "a registry entry is an authority-bearing action invoked by name, never by URL — MCP tools, session commands, CLI verbs",
    patterns: [
      /\baddCommand\s*\(/,
      /\bregisterTool\s*\(|\bsetRequestHandler\s*\(|\btools\s*:\s*\[/,
      /\baddExtension\s*\(|\bregisterCommand\s*\(/,
      /\bcommands?\s*\[\s*['"`]/,
    ],
  },
  {
    id: "dynamic-exec",
    label: "Dynamic execution primitives  [FORGOTTEN]",
    why: "eval / Function / spawn / pty are authority multipliers; they rarely look like entry points and are usually the worst finding in the report",
    patterns: [
      /\bnew\s+Function\s*\(/,
      /(?<![.\w])eval\s*\(/,
      /\bpty\s*\.\s*spawn\s*\(|node-pty/,
      /child_process|\bspawn\s*\(|\bexecSync\s*\(|\bexec\s*\(/,
      /\bvm\s*\.\s*run|createContext\s*\(/,
    ],
  },
  {
    id: "queue-consumers",
    label: "Queue / bus consumers",
    why: "a subscriber writes the same stores the guarded routes guard, having passed no HTTP control",
    patterns: [
      /\bsubscribe\s*\(|createConsumer|\bconsumer\s*\.\s*receive/,
      /\.on\s*\(\s*['"`]message['"`]/,
      /new\s+(?:Kafka|Pulsar|SQS)Client|@?pulsar-client|kafkajs/,
    ],
  },
  {
    id: "scheduled",
    label: "Scheduled / cron / timer entry",
    why: "a job runs with no user session and often more authority than any user",
    patterns: [/\bcron:|CronJob|new\s+CronScheduler|\bschedule\s*\(|setInterval\s*\(|EventBridge\s*Rule/],
  },
  {
    id: "rpc-ipc",
    label: "RPC / IPC / node-to-node calls",
    why: "internal calls frequently trust their caller by construction",
    patterns: [/\bgrpc\b|\.invoke\s*\(|process\.send\s*\(|postMessage\s*\(|execute_command|forwardTo/i],
  },
  {
    id: "credential-providers",
    label: "Credential resolution & ambient identity",
    why: "assume-role chains, metadata endpoints and secret loaders decide what authority the process HAS, which bounds every other finding",
    patterns: [
      /AssumeRole|assumeRole|assumeForeignRole|GetSessionToken/,
      /169\.254\.169\.254|metadata\.google|instance-identity/,
      /getSecretValue|SecretsManager|sops|GetParameter/i,
      /defaultRole\s*\(|DefaultAzureCredential|fromNodeProviderChain/,
    ],
  },
  {
    id: "iac-identity",
    label: "IaC-declared identity & network position",
    why: "reachability and blast radius live here and NEVER in application code; skipping it is how bands get mis-rated",
    patterns: [
      /task_role_arn|assume_role_policy|aws_iam_role|AssumeRolePolicyDocument/,
      /internal\s*=\s*(?:false|true)|load_balancer_type|cidr_blocks|SecurityGroupIngress/,
      /BucketPolicy|PolicyDocument|ManagedPolicyArns/,
    ],
  },
  {
    id: "human-controllers",
    label: "Human & pipeline controllers  (NOT code-visible — ALWAYS required)",
    why: "operators, support staff, on-call with prod access, CI/CD, third parties. A grep cannot find these, so its hit count is NOT evidence either way — this modality must be acknowledged whatever the count says, because every real system has them",
    patterns: [/\bimpersonat|break-?glass|\brunbook\b|support[_-]?access|on-?call\s+engineer/i],
    alwaysRequired: true,
  },
];

const SRC_EXT = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rb", ".go", ".java", ".kt",
  ".cs", ".php", ".rs", ".c", ".cc", ".cpp", ".h", ".sh", ".bash",
  ".tf", ".yml", ".yaml", ".json",
]);
const SKIP_DIR = /(^|\/)(node_modules|\.git|dist|build|out|vendor|target|\.next|coverage|__pycache__)(\/|$)/;
const SKIP_FILE = /\.(test|spec|integration)\.|__tests__|\.min\.js$|\.lock$/;

function die(msg: string, code = 1): never {
  console.error(msg);
  process.exit(code);
}

const argv = process.argv.slice(2);
const asJson = argv.includes("--json");
const check = argv.includes("--check");
const positional = argv.filter((a) => !a.startsWith("--"));
const repo = resolve(positional[0] ?? die("usage: DiscoveryGate.ts <repo> [analysis-dir]"));
const dir = resolve(positional[1] ?? join(repo, ".stpa"));
if (!existsSync(repo)) die(`no such path: ${repo}`);

const FILE_BUDGET = 20000;
let scanned = 0;
let truncated = false;
const hits = new Map<string, { count: number; files: Map<string, number> }>();
for (const m of MODALITIES) hits.set(m.id, { count: 0, files: new Map() });

function walk(d: string): void {
  if (truncated) return;
  let entries;
  try {
    entries = readdirSync(d, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (truncated) return;
    const p = join(d, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIR.test(p)) walk(p);
      continue;
    }
    if (!SRC_EXT.has(extname(e.name)) || SKIP_FILE.test(p)) continue;
    if (scanned >= FILE_BUDGET) {
      truncated = true;
      return;
    }
    let text: string;
    try {
      if (statSync(p).size > 2_000_000) continue;
      text = readFileSync(p, "utf8");
    } catch {
      continue;
    }
    scanned++;
    const lines = text.split("\n");
    for (const m of MODALITIES) {
      let n = 0;
      for (const line of lines) for (const re of m.patterns) if (re.test(line)) { n++; break; }
      if (n) {
        const h = hits.get(m.id)!;
        h.count += n;
        h.files.set(p.slice(repo.length + 1), n);
      }
    }
  }
}
walk(repo);

// ── the acknowledgement record ───────────────────────────────────────────────
const discoveryPath = join(dir, "discovery.json");
type Ack = { modality: string; modeledAs?: string[]; ruledOut?: string; note?: string };
let acks: Ack[] = [];
if (existsSync(discoveryPath)) {
  try {
    const d = JSON.parse(readFileSync(discoveryPath, "utf8"));
    acks = Array.isArray(d.modalities) ? d.modalities : [];
  } catch (e) {
    die(`discovery.json is not valid JSON — ${(e as Error).message}`);
  }
}
const ackOf = new Map(acks.map((a) => [a.modality, a]));

const rows = MODALITIES.map((m) => {
  const h = hits.get(m.id)!;
  const a = ackOf.get(m.id);
  const top = [...h.files.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3);
  const mapped = (a?.modeledAs ?? []).length > 0;
  const ruled = !!(a?.ruledOut ?? "").trim();
  const unacknowledged = (h.count > 0 || !!m.alwaysRequired) && !mapped && !ruled;
  return { m, hits: h.count, files: h.files.size, top, mapped, ruled, unacknowledged, ack: a };
});

if (!existsSync(discoveryPath)) {
  const template = {
    _note:
      "One entry per modality. `modeledAs` lists the control-action ids that cover it; `ruledOut` is a REASON " +
      "why it needs no control action (not 'did not look'). A modality with hits and neither field fails the gate.",
    repo,
    filesScanned: scanned,
    truncated,
    modalities: rows.map((r) => ({
      modality: r.m.id,
      hits: r.hits,
      modeledAs: [] as string[],
      ruledOut: "",
      note: "",
    })),
  };
  writeFileSync(discoveryPath, JSON.stringify(template, null, 2));
}

if (asJson) {
  console.log(
    JSON.stringify(
      {
        repo, filesScanned: scanned, truncated,
        modalities: rows.map((r) => ({
          modality: r.m.id, label: r.m.label, hits: r.hits, files: r.files,
          topFiles: r.top.map(([f, n]) => ({ file: f, hits: n })),
          mapped: r.mapped, ruledOut: r.ack?.ruledOut ?? "", unacknowledged: r.unacknowledged,
        })),
        status: "CANDIDATES — a hit is not a finding; a modality is not a control action",
      },
      null, 2,
    ),
  );
} else {
  console.log(`discovery modalities — ${repo}`);
  console.log(`  files scanned: ${scanned}${truncated ? "  !! TRUNCATED — absence below means UNKNOWN" : ""}\n`);
  for (const r of rows) {
    const state = r.hits === 0 ? "—" : r.mapped ? "mapped" : r.ruled ? "ruled out" : "!! UNACKNOWLEDGED";
    console.log(`  ${String(r.hits).padStart(6)} hits  ${r.m.label}`);
    console.log(`${" ".repeat(15)}${state}${r.mapped ? `: ${(r.ack!.modeledAs ?? []).join(", ")}` : ""}`);
    if (r.unacknowledged) for (const [f, n] of r.top) console.log(`${" ".repeat(17)}${f}  (${n})`);
  }
}

const unack = rows.filter((r) => r.unacknowledged);
if (unack.length) {
  console.error(
    `\n!! ${unack.length} modality/modalities have hits but are neither mapped to a control action nor ruled out:\n` +
      unack
        .map((r) => `   ${r.m.id} — ${r.hits} hits${r.m.alwaysRequired ? " (hits are not evidence here)" : ""}. ${r.m.why}`)
        .join("\n") +
      `\n\n   Edit ${discoveryPath}: add the covering control-action ids to \`modeledAs\`, or a REASON to\n` +
      `   \`ruledOut\`. "Did not read it" is not a reason — that is outstanding work, and a coverage\n` +
      `   percentage computed over an inventory this incomplete is arithmetically true and misleading.`,
  );
  if (check) process.exit(7);
} else if (!asJson) {
  console.log(`\nevery modality with hits is mapped or explicitly ruled out.`);
}
