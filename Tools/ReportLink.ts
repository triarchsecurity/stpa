#!/usr/bin/env bun
/**
 * ReportLink.ts — say where the deliverable is, in a form the reader can click.
 *
 * WHY THIS EXISTS (learned the hard way, 2026-07-25):
 *
 *   A completed analysis was handed over ending in `.stpa/REPORT.html`. The next
 *   question was "where is the file?" — then, after an absolute path was given,
 *   "where is that relative to my hard drive?", because the run was inside a
 *   container and `/work/alertd-core/.stpa/REPORT.html` does not exist on the
 *   reader's Mac. Two round trips to answer *where is the output*, on an analysis
 *   that was otherwise finished.
 *
 * Three separate defects were behind that, and this tool fixes all three:
 *
 *   1. A PATH IS NOT A LINK. Modern terminals hyperlink `file://` URLs; they do not
 *      hyperlink bare paths. Emitting `file:///…/REPORT.html` makes it one click,
 *      which is the whole ask for the ~90% of runs that are NOT containerised.
 *
 *   2. THE OUTPUT DIRECTORY IS HIDDEN. `.stpa` begins with a dot, so macOS Finder
 *      and most file pickers hide it by default. A correct path into an invisible
 *      folder still reads as "missing". Say so, and offer `--copy-to` for a visible
 *      copy.
 *
 *   3. A CONTAINER PATH IS NOT A HOST PATH, AND THE PROCESS USUALLY CANNOT KNOW THE
 *      DIFFERENCE. This is the part to get right by NOT guessing. On the run above the
 *      mount was `virtiofs` with an opaque hash source — the host path is deliberately
 *      not exposed, and no env var carried it. A tool that guesses produces a
 *      confidently wrong path, which is worse than an honest "this is a container
 *      path, here is how to resolve it." So: resolve the host path when it is
 *      genuinely knowable (not containerised; a bind mount that exposes its source;
 *      an explicit STPA_HOST_MAP), and otherwise say plainly that it is unresolved
 *      and print the one command that resolves it.
 *
 * Usage:
 *   bun ReportLink.ts [analysis-dir] [--copy-to <dir>] [--quiet]
 *
 * Env:
 *   STPA_HOST_MAP   comma-separated container=host prefix pairs, e.g.
 *                   "/work=/Users/me/work,/src=/Users/me/code". Set this once and
 *                   every run afterwards prints a clickable host URL.
 *
 * Exit: 0 always when the report exists (this is a reporting aid, not a gate); 1 if
 *       there is no REPORT.html to point at — which IS worth a non-zero, because a
 *       run that produced no deliverable should not look successful.
 */

import { readFileSync, existsSync, copyFileSync, mkdirSync, statSync } from "node:fs";
import { join, resolve, basename, dirname, sep } from "node:path";

const argv = process.argv.slice(2);
const quiet = argv.includes("--quiet");
const copyIdx = argv.indexOf("--copy-to");
const copyTo = copyIdx !== -1 ? argv[copyIdx + 1] : undefined;
// Skip the value that belongs to --copy-to, but only when --copy-to is actually present:
// with copyIdx === -1, `copyIdx + 1` is 0 and would silently swallow the first positional,
// falling back to a cwd-relative ".stpa" and reporting a path the caller never asked about.
const copyValueIdx = copyIdx === -1 ? -1 : copyIdx + 1;
const dir = resolve(argv.find((a, i) => !a.startsWith("--") && i !== copyValueIdx) ?? ".stpa");

const reportPath = join(dir, "REPORT.html");
if (!existsSync(reportPath)) {
  console.error(`no REPORT.html in ${dir} — run \`stpa run ${dir}\` first`);
  process.exit(1);
}
const abs = resolve(reportPath);

// ── is this a container? ─────────────────────────────────────────────────────
function containerEvidence(): string | null {
  if (existsSync("/.dockerenv")) return "/.dockerenv present";
  if (existsSync("/run/.containerenv")) return "/run/.containerenv present (podman)";
  try {
    const cg = readFileSync("/proc/1/cgroup", "utf8");
    if (/docker|lxc|kubepods|containerd/.test(cg)) return "container cgroup on pid 1";
  } catch {
    /* not linux, or no procfs — fine */
  }
  return null;
}

/**
 * The filesystem type and source backing `abs`. A bind mount from a Linux host often
 * exposes a usable source path here; a VM-mediated share (virtiofs, 9p, gRPC-FUSE)
 * exposes an opaque handle, which is exactly the case that must NOT be guessed at.
 */
function mountFor(p: string): { fsType: string; source: string; mountPoint: string } | null {
  let lines: string[];
  try {
    lines = readFileSync("/proc/self/mountinfo", "utf8").split("\n");
  } catch {
    return null;
  }
  let best: { fsType: string; source: string; mountPoint: string; len: number } | null = null;
  for (const line of lines) {
    const parts = line.split(" ");
    const sepIdx = parts.indexOf("-");
    if (sepIdx === -1 || parts.length < sepIdx + 3) continue;
    const mountPoint = parts[4] ?? "";
    const fsType = parts[sepIdx + 1] ?? "";
    const source = parts[sepIdx + 2] ?? "";
    const root = parts[3] ?? "";
    if (p === mountPoint || p.startsWith(mountPoint === "/" ? "/" : mountPoint + "/")) {
      if (!best || mountPoint.length > best.len) {
        best = { fsType, source: source === "-" ? root : source, mountPoint, len: mountPoint.length };
      }
    }
  }
  return best ? { fsType: best.fsType, source: best.source, mountPoint: best.mountPoint } : null;
}

/** VM-mediated shares cannot be translated to a host path from inside. */
const OPAQUE_FS = /^(virtiofs|9p|fuse\.gRPC-FUSE|fuse\.grpcfuse|osxfs|fuse\.osxfs)$/;

function hostPathFor(p: string): { path: string; how: string } | null {
  // 1. An explicit map is authoritative — the user told us.
  const map = process.env.STPA_HOST_MAP;
  if (map) {
    for (const pair of map.split(",")) {
      const [c, h] = pair.split("=").map((s) => s?.trim());
      if (c && h && (p === c || p.startsWith(c.endsWith(sep) ? c : c + sep))) {
        return { path: h.replace(/\/+$/, "") + p.slice(c.replace(/\/+$/, "").length), how: "STPA_HOST_MAP" };
      }
    }
  }
  // 2. Tooling that volunteers the host workspace.
  for (const [envName, containerRoot] of [
    ["LOCAL_WORKSPACE_FOLDER", process.env.CONTAINER_WORKSPACE_FOLDER],
    ["HOST_PROJECT_PATH", undefined],
    ["HOST_PWD", undefined],
  ] as [string, string | undefined][]) {
    const hostRoot = process.env[envName];
    if (!hostRoot) continue;
    const cRoot = containerRoot ?? process.cwd();
    if (p.startsWith(cRoot)) return { path: hostRoot.replace(/\/+$/, "") + p.slice(cRoot.length), how: `$${envName}` };
  }
  // 3. A bind mount that exposes a real host source (common on Linux Docker).
  const m = mountFor(p);
  if (m && !OPAQUE_FS.test(m.fsType) && m.source.startsWith("/") && !/^\/[0-9a-f]{16,}$/.test(m.source)) {
    // Only trust this when the source looks like a filesystem path, not a device or hash.
    if (!m.source.startsWith("/dev/")) {
      const rel = p.slice(m.mountPoint === "/" ? 0 : m.mountPoint.length);
      return { path: m.source.replace(/\/+$/, "") + rel, how: `bind mount source (${m.fsType})` };
    }
  }
  return null;
}

const fileUrl = (p: string) => "file://" + p.split(sep).map(encodeURIComponent).join("/").replace(/^/, p.startsWith("/") ? "" : "/");

const mount = mountFor(abs);

/**
 * Decide translatability from the FILESYSTEM, not from container heuristics.
 *
 * Learned by this tool being wrong on its first run: the environment that motivated it
 * is a VM, not a Docker container — no /.dockerenv, pid-1 cgroup is `0::/`, root is on
 * /dev/vdb — so every conventional container probe returned false and the tool happily
 * printed `file:///work/...` as though the reader could click it. What is actually true
 * and checkable is that the path lives on a `virtiofs` share whose source is an opaque
 * handle. Any host-shared filesystem of that family (virtiofs, 9p, gRPC-FUSE, osxfs)
 * means "this path is meaningful only inside this sandbox", whether the sandbox is a
 * container, a VM, or something else. That is the property we care about; "is it Docker"
 * never was.
 */
const onOpaqueShare = !!(mount && OPAQUE_FS.test(mount.fsType));
const sandbox = onOpaqueShare
  ? `path is on a ${mount!.fsType} host share`
  : containerEvidence();

const explicit = hostPathFor(abs);
const host = explicit ?? (sandbox ? null : { path: abs, how: "local filesystem" });
const hidden = abs.split(sep).some((seg) => seg.startsWith(".") && seg.length > 1);

// ── optional visible copy ────────────────────────────────────────────────────
let copied: string | null = null;
if (copyTo) {
  try {
    const target = resolve(copyTo);
    const isDir = existsSync(target) && statSync(target).isDirectory();
    const dest = isDir ? join(target, "STPA-REPORT.html") : target;
    mkdirSync(dirname(dest), { recursive: true });
    copyFileSync(abs, dest);
    copied = dest;
  } catch (e) {
    console.error(`could not copy the report: ${(e as Error).message}`);
  }
}

const openCmd =
  process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";

// ── output ───────────────────────────────────────────────────────────────────
const RULE = "═".repeat(74);
const out: string[] = ["", RULE];

if (host) {
  out.push(`  REPORT   ${host.path}`);
  out.push(`  OPEN     ${fileUrl(host.path)}`);
  if (sandbox) out.push(`           (host path resolved via ${host.how})`);
} else {
  out.push(`  REPORT   ${abs}`);
  out.push(`           ^ path INSIDE THIS SANDBOX — it does not exist on your machine`);
}
out.push(RULE);

if (copied) out.push(`  visible copy:  ${copied}`);

if (!host) {
  out.push("");
  out.push(`  This run is sandboxed (${sandbox}) and the host path is not`);
  if (onOpaqueShare) {
    out.push(`  discoverable from in here — the share's source is an opaque handle, so`);
    out.push(`  translating it would be a guess, and a confidently wrong path is worse`);
    out.push(`  than an honest one.`);
  } else {
    out.push(`  exposed by the runtime, so translating it would be a guess.`);
  }
  out.push("");
  out.push(`  Relative to the mount, the report is:`);
  out.push(`      <host folder mounted at ${mount?.mountPoint ?? "/"}>${abs.slice((mount?.mountPoint ?? "/").replace(/\/$/, "").length)}`);
  out.push("");
  out.push(`  Resolve it once, on the HOST (not in this sandbox):`);
  out.push(`      find ~ -type f -path "*${abs.split(sep).slice(-3).join("/")}" 2>/dev/null`);
  out.push("");
  out.push(`  Then make every future run print a clickable link by setting:`);
  out.push(`      export STPA_HOST_MAP="${mount?.mountPoint ?? "/work"}=<the host folder>"`);
}

if (hidden) {
  out.push("");
  out.push(`  NOTE: the path contains a dot-directory, which Finder and most file`);
  out.push(`  pickers hide by default. In Finder press Cmd+Shift+. to reveal it, or`);
  out.push(`  re-run with --copy-to <dir> to drop a visible copy somewhere obvious.`);
}

out.push("");
out.push(`  ${openCmd} "${host ? host.path : abs}"`);
out.push("");

if (!quiet) console.error(out.join("\n"));
process.exit(0);
