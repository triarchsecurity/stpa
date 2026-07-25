# Workflow: ModelControlStructure — STPA Step 2

Build the hierarchical control structure. This is the expensive step and the one that determines whether the rest of the analysis is worth anything. Two procedures follow — one for a codebase, one for a design document — because the evidence available is completely different in each case.

## Inputs

- The scope artifact from Step 1 (`01-scope.md`): boundary, losses, hazards.
- **Modality A**: a repository path.
- **Modality B**: a system design document (markdown, text, PDF, architecture diagram description, RFC, ADR set).

## Outputs

- `model.json` — machine-readable, consumed by `stpa init|status|grid`:
  ```json
  {
    "system": "name",
    "controllers": [{ "id": "C-1", "name": "AuthZ middleware", "type": "automated|human|organizational" }],
    "processes":   [{ "id": "P-1", "name": "tenant-data service" }],
    "controlActions": [
      { "id": "CA-1", "action": "grant access to a tenant-scoped record",
        "controller": "AuthZ middleware", "process": "tenant-data service",
        "hazards": ["H-1"] }
    ],
    "feedback": [{ "id": "F-1", "from": "P-1", "to": "C-1", "signal": "row-level query result" }],
    "processModels": [
      { "controller": "C-1", "variables": [
          { "id": "PM-1", "belief": "caller identity", "sourcedFrom": "session cookie", "staleness": "session TTL" },
          { "id": "PM-2", "belief": "caller tenant", "sourcedFrom": "request header", "staleness": "wrong at source, permanently" }
      ]}
    ]
  }
  ```

  **Every process-model variable and feedback channel needs a stable ID.** They are not decoration: Step 3 findings must bind to them, and `UcaGrid.ts` will not count a finding toward coverage unless it references a declared ID. A model with no declared elements is rejected outright — which is the analyst-confirmation gate, since raw scanner output has none.
- A **Mermaid control-structure diagram** (required — the diagram is what makes missing feedback loops visible at a glance).
- `<output>/02-control-structure.md` containing the diagram, the tables, and the assumptions log.

## Procedure A — from a codebase

1. **Run the candidate scan — and choose your lens deliberately.**
   ```bash
   stpa scan <repo> --list-focus                    # what lenses exist
   stpa scan <repo> --json > candidates.json        # everything, standard depth
   stpa scan <repo> --focus authz,tenancy           # authorization boundaries only
   stpa scan <repo> --focus api,webhook             # every externally reachable entry point
   stpa scan <repo> --focus cron,queue,async        # the unattended plane
   stpa scan <repo> --depth deep --focus authz      # no cap, tests included, every hit
   stpa scan <repo> --depth survey                  # counts + hot files only, for a huge repo
   stpa scan <repo> --include src/api --exclude legacy
   ```

   **Depth** controls how much you see: `survey` (counts and hot files — orientation on a repo too big to read), `standard` (capped per category, tests excluded), `deep` (no cap, tests included, every hit listed). **Focus** controls what you look at: any lens from `--list-focus`, matched against pattern tags.

   Pick the lens from the hazards you wrote in Step 1, not from habit. If your hazards are about tenant isolation, `--focus authz,tenancy` is the honest first pass; scanning everything and skimming is how the interesting half gets missed.

   This enumerates entry points, guards, data-access sites, and external-effect sites. It is a starting list, never an answer.

   **Read the truncation lines.** At `standard` depth the per-category cap drops matches, and the scan says exactly how many (`N MATCHES DROPPED by the 300-per-category cap`). On a large codebase that number is routinely in the thousands — a capped scan is a sample, and treating a sample as an inventory is how a control action disappears from an analysis without anyone deciding to drop it.

   **Check two things in the output before trusting it.** If `truncated` is true, the file budget was hit and parts of the repo were never read — slice by subdirectory. And if a category came back empty, decide which it means: the pattern is genuinely absent, or this stack's idioms are unrecognized. Pattern quality is best on web/service stacks; on embedded, ops, or an unfamiliar language, a clean scan is **no signal**, not a clean bill of health — model by hand.

2. **Add the controllers that leave no code trace.** This is the step that separates a real analysis from a grep. Every system has controllers the scanner cannot see: human operators and support staff with admin consoles, the on-call engineer with production database access, the CI/CD pipeline itself, third-party services acting on your data, the DNS registrar, the cloud IAM plane, the package registry your build trusts, and **shipped operator/debug tooling that rides inside the deployed or customer-side artifact** — web shells, CLI simulators, admin terminals, debug pages. Write them down. Historically these are where the interesting findings live, precisely because they are invisible to tooling.

   **Then, for every controller, ask what ambient credentials its runtime carries** — a cloud instance/task role, secrets in the process environment, a reachable credential/metadata endpoint — **and whether those credentials are portable beyond it.** A portable credential turns any shell or console in that runtime into an off-path control action over everything the credential can reach, exercised under the workload's identity and invisible to the application's authorization model. Model the shell/console as a controller, the ambient credentials as a controlled process, and *"my authority is confined to this process/host"* and *"privileged actions are attributable to a named human"* as process-model beliefs that are typically FALSE by construction (portable tokens; shared service identities). This class defeats every guard modeled in the application planes, because no unsafe control action occurs on the guarded path — the credential simply leaves the box.

3. **Group entry points into control actions, not endpoints.** `POST /orders`, `POST /orders/bulk`, and the order-import worker are three entry points and one control action (*create an order*). Model the action; the entry points become the paths by which it can be issued, which matters in Step 4.

4. **Identify the controlled process for each action.** What state actually changes? Storage, an external service, a human's belief, a deployed artifact.

   **Then invert it: for each controlled process, list *every* controller that can affect it** — other services, background jobs, operators, shipped tooling, direct datastore access, a second account or role. Two or more controllers over one process with no shared coordination and no shared process model is the *multiple-controller conflict* that canonical STPA Step 3 exists to find, and it is the structural source of the bypass class (Step 4 Part B). If a controlled process has exactly one controller and one path, say so explicitly — single-writer is a strong safety property worth recording. If it has several, that process is a priority for Step 4.

5. **Trace feedback.** For every control action, ask: how does the controller learn the result? Audit log, return value, error response, metric, webhook callback, nothing at all. **Record the absent ones explicitly** — a control action with no feedback path is a finding waiting to happen in Step 4, and it is invisible unless you write the absence down. **But an absence is a claim about code, so verify it before you write `NONE`.** Grep for the channel you are about to declare missing — `grep -rn "audit\|emit\|log\." <the module>` — and read the hits. A run that wrote `F-4: NONE — no post-deploy attestation` was refuted by a reviewer who found a 2-of-N signature verifier with anti-rollback in the same repository. If you cannot cite the negative search, write `NOT VERIFIED` rather than `NONE`; the two are different claims and only one of them is free.

6. **Write the process model for each controller.** The highest-value part of Step 2, and the step the whole method's yield depends on. For each controller, give every belief an ID and record: what it *believes* about system state, *where that belief comes from*, and *how stale it can be*. A guard that believes `role=admin` because a 15-minute JWT said so has a process model that can be wrong for 15 minutes. That interval is a finding generator.

   **Every variable must also name a `trustRoot`, and `stpa evidence` fails without one.** A belief is
   only as good as the origin its evidence bottoms out in, so record which of these it is:
   `database` · `iam` · `network` · `human` · `attacker-input` · `unverified`. **"the session", "the
   token", "config" are hops, not roots** — expand the chain until it terminates. A token bottoms out in
   whatever verifies it and whichever key does so; if the adversary can obtain that key, the root is
   `attacker-input` and every control built on that belief is a placebo. This is not bookkeeping: a run
   credited "roles are re-read from the database every request" as a working control, when two of the
   three authority helpers actually decrypted the role out of the caller's own token — which invalidated
   six remediations that all said "gate this on an operator role". `unverified` is a legitimate and useful
   answer; it forces the dependent band to be provisional instead of silently confident.

      **`staleness` is the field where unverified absence claims hide, so hold it to evidence.** Writing *"FALSE BY CONSTRUCTION — nothing checks this"* is the highest-severity sentence in the whole model and it is frequently wrong. Before writing it: read the **declaration and default**, not only the use (`x ?? true` inverts what "not passed" means); follow the **mount**, not only the handler (Express guards usually live at `app.use(prefix, guard, router)`, far from the route that looks bare); and grep the whole module for the control you say is missing. Cite the `file:line` that establishes the absence. In one run, four `staleness` entries asserting a missing control were all false, and the worst of them was promoted to a band-1 R0 finding and recorded as CONFIRMED.

   Skipping or thinning this step is the single most common way an STPA run degrades into a checklist — which is why the tooling refuses to score a grid whose findings do not bind back to these IDs. If Step 2 is thin, Step 3 cannot score, by construction.

7. **Layer the structure.** STPA's control structure is hierarchical: operations sits above the running service, the deploy pipeline sits above the runtime, governance sits above operations. Draw at least two layers. Single-layer models miss the entire class of "the system was configured into a hazardous state by a legitimate operator."

   **Then, before any finding is rated, pin the deployment topology and trust zones — this is not optional, and it is what reachability and blast radius are rated against.** Gather it from the infrastructure, not the application code: terraform / IaC (is it deployed single-tenant-per-customer, multi-tenant, or with a central control plane? what runs once, centrally, vs once per deployment?), network config (which entry points are internet-facing vs on an internal private-DNS segment?), and IAM / broker ACLs / WAF (which boundaries are enforced *outside* the code?). Record the **trust zones** explicitly — per-tenant deployment, central/shared plane, the customer's cloud account, the vendor's cloud account, staff vs customer — and treat the boundaries between them as first-class. Two consequences bind the rest of the analysis: (a) **the same defect is a different finding in a different zone** — "no tenant scope" is latent design-debt inside a single-tenant deployment but a live cross-tenant breach on a shared central plane, so a per-tenant-plus-central architecture *requires* a dedicated "shared substrate & central control plane" slice or the real cross-tenant surface is never modeled; and (b) **non-code controls are controllers** — IAM on a bucket, a private network segment, a broker ACL either close a hazard (tombstone it, naming the control) or are assumed-but-unverified (the dependent finding rates provisional). A model that shows only application components, on one flat trust plane, will systematically over-rate internal foothold-required paths as external ones and miss the central plane entirely.

8. **Draw the Mermaid diagram.** Solid arrows down for control actions, dashed arrows up for feedback. Missing dashed arrows are the point of the exercise.
   ```mermaid
   flowchart TB
     OPS[Operator / admin console]
     CI[CI-CD pipeline]
     GW[API gateway + authz middleware]
     SVC[Tenant data service]
     DB[(Primary datastore)]
     OPS -->|revoke role| GW
     CI -->|deploy build| SVC
     GW -->|grant access| SVC
     SVC -->|read/write record| DB
     DB -.->|query result| SVC
     SVC -.->|audit event| OPS
     GW -.->|no feedback on denied-but-valid access| OPS
   ```

## Procedure B — from a system design document

1. **Extract nouns that act and nouns that are acted upon.** Services, gateways, workers, humans, roles, third parties → candidate controllers. Stores, queues, external systems, records, deployed environments → candidate controlled processes.

2. **Extract verbs crossing a boundary.** Every "X calls Y", "X authorizes Y", "X writes Y", "on receipt of Z, the service does W" is a candidate control action. Sequence diagrams are the richest source; each arrow is a control action or a feedback signal.

3. **Mine the document for implicit process models.** Design documents state beliefs constantly and rarely flag them: *"the gateway validates the token and forwards the tenant id"*, *"the worker trusts the message envelope"*, *"we cache permissions for performance"*. Each is a process model with a source and a staleness. Extract them verbatim with a document reference.

4. **Enumerate what the document does not say.** Design documents describe the intended path. For each control action ask: does the document say what happens on failure? on retry? on concurrent invocation? on revocation? who can invoke this besides the described caller? Unanswered questions become **assumptions**, logged explicitly.

5. **Maintain an assumptions log.** Every element you inferred rather than read gets a row: `assumption | basis | what breaks if wrong`. In design-document mode the assumptions log is a first-class deliverable — it is the list of questions to put to the system's authors, and it is often more valuable than the findings.

6. **Same outputs as Procedure A** — model.json, Mermaid diagram, process-model table.

## Steps common to both modalities

7. **Validate the model before proceeding.** Every control action has exactly one controller and ≥1 controlled process. Every controller has ≥1 process model entry. Every control action links to ≥1 hazard from Step 1 — an action that cannot contribute to any hazard is out of scope, and saying so explicitly is how the analysis stays finite.

8. **Record the scope — how much of the system you are actually modeling.** Fill `scope` in `model.json`:

   ```json
   "scope": {
     "candidateControlActions": 47,
     "selectionCriteria": "why THESE and not the others",
     "deferred": [{ "name": "the reporting API", "reason": "read-only over already-authorized data" }]
   }
   ```

   **This is not bookkeeping.** Grid coverage answers *"did we finish the analysis we scoped"*. Surface coverage answers *"how much of the system did we scope"*. They are different numbers, and reporting the first without the second is how "100% coverage" becomes a false assurance. `stpa status` prints both, the report shows both, and an undeclared scope is called out rather than quietly assumed to be complete.

   Count candidates honestly — group entry points into control actions first, then count the groups. Every deferred item needs a written reason; a deferral with a reason is scoping, one without is an omission.

9. **Freeze control-action IDs.** Step 3's grid is keyed on them.

## Handoff

`model.json` feeds `stpa init model.json -o grid.json`, which produces the Step 3 work list.
