# stpa — control-theoretic threat modeling for software

Point it at a repository or a design document. Get back a control structure, a countable grid of unsafe control actions, and a **ranked engineering backlog** where every item has a file location, a cost estimate, and a command that proves the fix landed.

Built on **STPA** (System-Theoretic Process Analysis — Leveson & Thomas, *STPA Handbook*, 2018) with the **STPA-Sec** security framing (Young & Leveson, *CACM* 57(2), 2014).

Runs entirely offline. No API keys, no network calls, no telemetry, no accounts.

---

## Why not STRIDE

STRIDE, attack trees, and their descendants are **component-and-technique enumeration**: decompose the system, walk a list of attacker techniques against each part. That works for the failure it was designed for — a component doing something it should not.

It structurally cannot find the dominant modern vulnerability class: **systems where every component behaves exactly as specified and the composition is still unsafe.**

Broken object-level authorization. Tenant-isolation failures. TOCTOU. Stale-permission windows. Confused deputy. Mass assignment. Workflow-state abuse. Double-spend races. Bypass paths through admin tooling. In every one of these, *nothing is broken*. The authorization middleware correctly authorizes what it was asked about. The database correctly returns the row it was asked for. The loss emerges from the **control relationships between correct components**.

There is a second failure, less discussed: **checklists age against the checklist.** A technique that did not exist when the list was written is not on the list. STPA's finding set changes only when the *design* changes, because it enumerates hazardous **contexts** rather than techniques.

Use both. This is not a STRIDE replacement — STRIDE is strong exactly where this is weak (component-level, protocol-level, known-technique coverage). The published comparison (Kavallieratos et al., *Computers & Security*, 2023) says so plainly, and `METHOD.md` quotes it.

---

## Install

**Runs on Node or Bun — no other prerequisites.** The `stpa` CLI dispatches every tool to
whichever runtime is executing it, so `./stpa` uses Node (≥22.6; types are stripped
natively from 22.18, and the flag is passed automatically below that) and `bun stpa` uses
Bun. There are no Bun-specific APIs anywhere in the toolkit.

Everything is offline either way: no API keys, no network calls, no telemetry. Nothing is
downloaded at install or at analysis time.

**As a Claude Code skill** — clone into your skills directory. `SKILL.md` carries the
frontmatter that registers and routes it, so the clone is the whole install:

```bash
git clone https://github.com/triarchsecurity/stpa.git ~/.claude/skills/triarch-stpa
chmod +x ~/.claude/skills/triarch-stpa/stpa
```

Then invoke it by name (`/triarch-stpa`) or just ask for a threat model. A bare invocation
runs `Workflows/Start.md`, which asks four questions — **which model authors the analysis
and which independent model attacks it**, what it is working from, how much to cover, and
what would actually hurt — then runs the whole assessment.

**As a standalone CLI**, with no agent involved:

```bash
git clone https://github.com/triarchsecurity/stpa.git && cd stpa
chmod +x stpa
./stpa --help
```

Everything is offline: no API keys, no network calls, no telemetry. The CLI does the
arithmetic and the gates; the judgement is yours either way.

Optionally put it on your PATH:

```bash
ln -s "$PWD/stpa" /usr/local/bin/stpa
```

---

## Tactical — run one

```bash
stpa scan ./my-repo --json > candidates.json   # 1. orientation (candidates, NOT findings)
stpa new .stpa                                 # 2. scaffold
#    ...write .stpa/01-scope.md  — losses and hazards
#    ...write .stpa/model.json   — the control structure  ← this is the actual work
stpa init .stpa/model.json -o .stpa/grid.json  # 3. the 4 x N grid
#    ...resolve every cell in grid.json
stpa status .stpa/grid.json                    # 4. coverage check
#    ...write .stpa/remediation.json — cost, location, fix, probe
stpa run .stpa                                 # 5. plan + REPORT.html
```

Open `.stpa/REPORT.html` in any browser. It is a single self-contained file — no CDN, no scripts, no fonts. Email it, commit it, print it.

### What each command does

| Command | Does |
|---|---|
| `stpa new [dir]` | scaffolds `model.json` + `01-scope.md` with the right shapes |
| `stpa scan <repo>` | enumerates entry points, guards, data-access and external-effect sites — **candidates requiring confirmation, never findings**. `--focus` picks the lens, `--depth` picks how much you see, `--list-focus` shows what's available |
| `stpa init <model>` | builds the grid: exactly `4 × (control actions)` cells |
| `stpa status <grid>` | coverage, binding spread, open cells. Exit **3** if findings are suspiciously concentrated |
| `stpa grid <grid>` | the grid as markdown |
| `stpa plan [dir]` | findings → root causes → waves → metrics. `--check` exits 1 if any finding has no plan |
| `stpa report [dir]` | the self-contained HTML deliverable |
| `stpa run [dir]` | `plan` + `report` |

### Choosing depth and focus

The scanner is a lens, not an inventory. Point it at what your hazards are actually about:

```bash
stpa scan ./repo --list-focus                 # every available lens
stpa scan ./repo --focus authz,tenancy        # authorization + multi-tenancy boundaries
stpa scan ./repo --focus api,webhook          # externally reachable entry points
stpa scan ./repo --focus auth,authn,crypto    # the authentication plane
stpa scan ./repo --focus effects,payments     # irreversible and money-moving actions
stpa scan ./repo --focus cron,queue,async     # the unattended plane
stpa scan ./repo --depth deep --focus authz   # no cap, tests included, every hit
stpa scan ./repo --depth survey               # counts only — orientation on a huge repo
stpa scan ./repo --include src/api --exclude legacy
```

`--depth standard` caps matches per category and **tells you how many it dropped**. On a large codebase that is routinely thousands. A capped scan is a sample; treating it as an inventory is how a control action leaves the analysis without anyone deciding to drop it.

### Two coverage numbers, always both

- **Grid coverage** — did you finish the analysis you scoped? `(bound findings + reasoned tombstones) / cells`
- **Surface coverage** — how much of the system did you scope? `modeled control actions / candidates`

Reporting the first without the second is how "100% coverage" becomes a false assurance. Declare `scope.candidateControlActions` in `model.json`; `stpa status` and the report print both side by side, and an undeclared scope is flagged rather than assumed complete.

### The three artifacts you write by hand

The tools do arithmetic. **You do the analysis.** That division is deliberate — a tool that guessed at your losses or your controllers would produce a confident, wrong threat model, which is worse than none.

1. **`01-scope.md`** — losses (stakeholder-level) and hazards (**system states**, never attacker actions).
2. **`model.json`** — controllers, control actions, feedback, and **process models**: what each controller *believes*, where the belief comes from, how stale it can be. This is where the yield is.
3. **`remediation.json`** — per finding: severity, reachability, effort, file location, the fix, the probe.

### Time budget

| Target | Realistic |
|---|---|
| One PR or feature | ~20 min (`Workflows/QuickTriage.md`) |
| One service, <10 control actions | 1–2 hours |
| Multi-service system, 10–40 | a day; parallelize per controller |
| Whole platform, 40+ | slice by trust boundary — a platform-wide grid is a way to never finish |

---

## Strategic — how it earns its place

**1. It runs before there is anything to test.** SAST needs code; DAST needs a deployment; pentests need a target. This needs a design document. The cheapest moment to find a control-structure defect is before the control structure exists — and the Handbook cites the standard estimate that 70–90% of safety-relevant design decisions are made in concept development.

**2. It produces requirements, not a report.** Every finding inverts mechanically into a constraint, and every constraint carries a probe. Land those probes in your test suite and the threat model becomes something CI enforces. A threat model that does not end in executable assertions will be stale within one quarter — that is the actual reason threat modeling has a reputation for theatre.

**3. It gives you a completeness number you can defend.** The analysis is a finite grid — `4 × N` cells — and coverage is `(bound findings + reasoned tombstones) / cells`. "We analyzed 84% of the grid; here is the 16% we did not reach" is a sentence you can say to an auditor, a customer, or a board. "We did a threat model" is not.

**4. It surfaces the controllers nobody models.** Every real system has authority that leaves no code trace: the on-call engineer with production database access, the CI pipeline, the support tool with impersonation, the third party processing your data, the package registry your build trusts. The method forces them onto the diagram. In practice this is where the uncomfortable findings live.

**5. Re-analysis is cheap, so it can be a habit rather than an event.** `stpa init model-v2.json --merge grid.json` carries resolved cells forward and lists only genuinely new ones. Re-run when the control structure changes — new controller, new integration, new operator role. That is a fundamentally different economics from an annual assessment.

### Where to put it in an SDLC

| Moment | Use |
|---|---|
| Design review / RFC | Full analysis from the document (Modality B). The assumptions log *is* the review agenda. |
| Architecture change | Merge-mode re-analysis. Only new control actions add cells. |
| PR touching auth, tenancy, billing, or jobs | `QuickTriage` — 20 minutes, same shape |
| Pre-audit / customer security review | The HTML report plus the coverage number |
| Post-incident | Feed the incident's control action back through the four types; it usually reveals siblings |

### What it will not do

- **It is not a scanner.** No CVEs, no dependency audit, no taint analysis. Use it *alongside* SAST/DAST/SCA, not instead.
- **It will not find memory-safety bugs, injection, or crypto misuse** — those are component defects, which is STRIDE's and SAST's home ground.
- **It produces no probabilities.** Nothing here is CVSS-comparable. Prioritisation is severity × reachability, an explicit judgment, documented as such.
- **It depends on the analyst.** Two people produce different control structures for the same system. The method structures judgment; it does not replace it. `METHOD.md` lists the published critiques rather than hiding them.

---

## The method in one page

1. **Losses** — what is unacceptable, in stakeholder terms.
2. **Hazards** — **system states** that lead to losses. *An attacker steals a token* is not a hazard. *The system accepts a token that no longer reflects the holder's entitlements* is.
3. **Control structure** — controllers (including humans and pipelines), control actions, feedback, and each controller's **process model**.
4. **Unsafe control actions** — every control action × four types:

   | Type | Question | Catches |
   |---|---|---|
   | Not provided | does skipping it cause a hazard? | missing authz check, revocation that never propagates, audit event never written |
   | Provided | is there a context where doing it is hazardous? | IDOR, cross-tenant reads, double refunds, deploy of unreviewed code |
   | Wrong timing/order | too early, too late, out of sequence? | TOCTOU, check-then-use races, deploy-before-migration |
   | Too long / stopped too soon | wrong duration? | sessions that never expire, privilege not dropped, credentials with unbounded TTL |

5. **Loss scenarios** — why the UCA occurs, and why a *correct* action might fail to land.
6. **Constraints** — invert each finding; attach a probe.

**The central lens:** *process-model inconsistency is the general form of the authorization bug.* A controller acts on what it **believes**; when belief and reality diverge and it acts anyway, you get a vulnerability. IDOR, tenant leakage, stale permissions, confused deputy, JWT confusion, webhook spoofing, and TOCTOU are all that one bug wearing different clothes. Asking *"what does this controller believe, and who can influence that belief?"* finds them faster than any technique list.

**The adversary is a context selector**, not a new actor. Attackers do not add control actions — they choose the context in which a legitimate one becomes hazardous. Young & Leveson put the adversary in step 4, and so does this toolkit.

---

## Parallelizing a large analysis

A big system is analyzed plane by plane, often by several people or agents at once. Two rules, both enforced in code because both were learned by getting them wrong:

1. **Write the expected set before you dispatch.** `manifest.json` lists every plane and its control actions. Coverage is computed over cells *present*, not cells *expected*, so merging "whatever came back" yields a healthy-looking number over a fraction of the system.
2. **Reconcile before you merge.**
   ```bash
   stpa merge .stpa --expect .stpa/manifest.json
   ```
   Exits **4** on any plane that produced nothing or any cell gap nobody declared. Declare gaps in `scope.deferred` so surface coverage falls to match reality — never merge past a silent hole.

Deliverables go to **files**, never returned as message payloads: a file exists or it doesn't, whereas a delegate that finishes and delivers nothing is indistinguishable from one that succeeded.

## Anti-gaming, on purpose

A coverage metric that counts any string certifies the shallow version of the work as complete. Two guards, both enforced in code:

- **Binding.** A finding counts toward coverage only if it references a process-model variable or feedback channel **declared for this specific system**. Generic vulnerability-class text binds to nothing and scores nothing. Verified: 16 generic findings filling a 16-cell grid → **0.0%**.
- **Concentration.** Citing the *same* element on every finding passes binding but is still boilerplate, so `stpa status` reports binding spread, stamps `** CONCENTRATED — NOT A CLEAN 100 **` onto the coverage line itself, and exits **3**.

Known limit, stated rather than hidden: alternating identical text across *two* declared elements at 50/50 passes both guards. Closing that needs semantic judgment of the text, which arithmetic cannot do. **These guards catch lazy gaming, not determined gaming — the backstop is a human reading the statements.**

---

## Repository layout

```
stpa                       CLI entry point
README.md                  this file
METHOD.md                  STPA/STPA-Sec theory, Handbook definitions, limitations, sources
SoftwareMapping.md         STPA vocabulary → software; UCA-type → vulnerability-class tables;
                           loss & hazard catalogues; per-stack entry-point recipes
AdversarialContext.md      adversary-as-context-selector; R0–R4 reachability; 12 context patterns
Workflows/                 the four steps + constraints, full analysis, and PR-scale triage
Tools/                     the four executables the CLI dispatches to
Examples/ledgerline/       a complete worked run against a design document with no code
Fixtures/                  a minimal model for smoke-testing
```

## Using it from Claude Code

This repo doubles as a Claude Code skill. Clone it into your skills directory and add a `SKILL.md` describing the workflow routing in `Workflows/` — `Workflows/Start.md` is written as an interactive intake that asks for a repo link, a scope, a depth and a set of losses, then runs the whole pipeline and hands back the HTML report.

The toolkit itself has no dependency on Claude Code, or on any agent. Everything under `Tools/` is a plain Bun executable and the `stpa` CLI drives all of it from a shell.

---

## Credits & licence

MIT — see `LICENSE`.

The method is Nancy Leveson and John Thomas's; the security framing is William Young and Nancy Leveson's. Full citations and the honest list of published limitations are in `METHOD.md`. This toolkit is an independent implementation and is not endorsed by MIT or the STPA authors.

## Field notes

[`FIELD-NOTES.md`](FIELD-NOTES.md) records the observed failure modes each gate exists to catch — read it before deciding a gate is not worth its friction.
