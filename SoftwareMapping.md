# Software Mapping — translating STPA's vocabulary to code and architecture

STPA was built for aircraft, nuclear plants, and medical devices. Its vocabulary is physical: actuators, sensors, controlled processes. The translation to software is not decorative — done badly, you get a control structure that is just a boxes-and-arrows redraw of your service diagram, and the analysis produces nothing you did not already know.

This file is the translation layer. It is a toolkit extension; the Handbook does not contain it.

---

## The five elements in software

### Controller — anything that decides

A controller is anything that makes a decision affecting system state. The mistake is to model only services. Controllers include:

| Controller | What it decides |
|-----------|-----------------|
| **Authorization middleware / policy engine** | whether a request proceeds |
| **API gateway / reverse proxy / WAF** | what reaches the backend, with what identity attached |
| **Application service** | what business state changes |
| **ORM / data-access layer** | what query actually runs, with what scoping applied |
| **Message-queue consumer** | what work executes, on whose behalf |
| **CI/CD pipeline** | what code becomes the running system |
| **Cloud IAM plane** | what any workload is permitted to do |
| **Feature-flag service** | which code path is live, changeable without a deploy |
| **Human operator / support agent** | manual overrides, impersonation, escalation, refunds |
| **On-call engineer with production access** | direct state change bypassing every application control |
| **Shipped operator/debug tooling (web shell, CLI console, admin terminal, debug page) inside a deployed or customer-side artifact** | grants a human ambient access to everything the deployment's *own* identity can reach — frequently the widest authority in the system, and it leaves only a thin code trace (a PTY spawn, a metadata fetch) that no scanner flags as authority-bearing |
| **Third-party service acting on your data** | processing you authorized but do not observe |
| **Package registry / dependency resolver** | what code your build trusts |
| **The scheduler (cron, workflow engine)** | what runs unattended, usually with elevated authority |

**Rule: if it can change system state and it makes a choice, it is a controller — including if it is a person.** The controllers with no code trace are the ones tooling never finds and analyses most often miss.

### Controlled process — what is acted upon

| Controlled process | Notes |
|--------------------|-------|
| **Primary datastore / a specific table or collection** | model at the granularity where authority differs |
| **Object storage / file store** | often has an independent access path (signed URLs, direct bucket access) |
| **Session / identity store** | both a controlled process and a feedback source |
| **Cache layer** | a controlled process that is *also* a process-model source — dangerous combination |
| **Deployed runtime / cluster** | the process the pipeline controls |
| **External service state (payments, email, IAM)** | changes here are usually irreversible |
| **The workload's own ambient credentials** | cloud instance/task-role credentials, env secrets, and any reachable credential/metadata endpoint (e.g. the link-local metadata IP) — a controlled process because anything in the runtime can read it, and *portable*: a token lifted here is usable from anywhere, under the workload's identity, until it expires |
| **Another team's service** | your control action, their controlled process, no shared model |

### Control action — the decision, not the endpoint

Model the *action*, not the route. `POST /orders`, `POST /orders/bulk`, and the order-import worker are one control action issued through three paths.

Typical software control actions: authenticate a system owner · issue a credential or session · grant or deny access to a resource · assign or revoke a role · create, modify, or delete a record · move money · send a message to a user · publish an event · execute a job · deploy or roll back · change a feature flag · rotate or revoke a secret · export data · impersonate a user · escalate privilege · quarantine or ban an account · read the instance/task credential or metadata endpoint · extract or export ambient credentials · act on a downstream account off the application path.

### Feedback — how the controller learns the result

| Feedback | Notes |
|----------|-------|
| **Return value / status code** | the tightest loop; also the one adversaries read for oracles |
| **Audit log / event stream** | the primary feedback to human controllers — and frequently absent, delayed, or forgeable |
| **Metrics and alerts** | feedback to operators; the alert *is* the control loop closure |
| **Webhook callback from a third party** | feedback crossing a trust boundary, often unauthenticated |
| **Read-after-write / consistency check** | feedback that the write landed — frequently assumed rather than performed |
| **User-visible state** | the user is a controller and the UI is their feedback; a stale UI gives them a wrong process model |

**Absent feedback is a first-class modeling result.** Write down the loops that do not close.

### Process model — what the controller believes

The highest-yield element in software STPA. For every controller record three things: **what it believes**, **where the belief came from**, and **how stale the belief can be**.

| Belief | Typical source | Typical staleness |
|--------|----------------|-------------------|
| caller identity | JWT claims, session cookie | token TTL |
| caller role / permissions | token claim, cached ACL, DB lookup | cache TTL, or TTL of the token |
| caller's tenant / org | header, subdomain, token claim, session | permanent if wrong at source |
| resource ownership | DB row, denormalized copy | replication lag |
| entitlement / plan tier | billing webhook, cached flag | webhook delivery delay |
| feature flag state | flag service, local cache | poll interval |
| "this request is internal" | network position, header, absent | permanently wrong under SSRF |
| idempotency state | key store | window length |
| account status (banned, locked) | DB, cached | cache TTL |
| my authority is confined to this process/host | ambient credentials in the runtime env | FALSE by construction — cloud STS/instance/task tokens are portable and usable off-box until TTL |
| a privileged action is attributable to a named human | a shared service/role identity, a generic session name | FALSE — off-box use surfaces the *operator's own* network identity, and a shared identity names no one |

---

## Process-model inconsistency — the general form of the authorization bug

This is the central claim of the software mapping, and it is what makes STPA worth the effort on code.

**Almost every real authorization vulnerability is a process-model inconsistency: the controller's belief about system state diverges from actual system state, and it acts on the belief.** The vulnerability taxonomies name the symptoms; this names the mechanism.

| Vulnerability class | The inconsistency |
|---------------------|-------------------|
| **IDOR / broken object-level authz** | the controller believes the requested object belongs to the caller, because the caller said which object — it never checked ownership |
| **Broken tenant isolation** | the controller believes tenant identity is a fact, sourced from a value the caller controls |
| **Credential / authority exfiltration (off-path use)** | the controller — and everyone with shell/console access to its runtime — believes authority is bounded by the application path, but the runtime's ambient credentials are portable; lifted and used off-box they carry the full authority of the workload's identity, non-attributably, and the guarded path is never involved |
| **Mass assignment** | the controller believes the request body contains only fields the caller may set |
| **Stale-permission window** | the controller believes the role held at token issue is the role now |
| **Confused deputy / SSRF** | the controller believes the request originated internally, because it arrived from an internal address |
| **TOCTOU** | the belief was true when read and false when acted on; the model was correct and became wrong |
| **Cache poisoning** | the belief's source was writable by the adversary |
| **JWT algorithm confusion** | the controller believes the token was signed by the issuer, because the token said which algorithm to verify with |
| **Webhook spoofing** | the controller believes an external event occurred, because something asserted it |
| **Replay** | the controller believes each presentation of a credential is a distinct authorized event |
| **Race-condition double-spend** | the controller believes it holds the only in-flight view of the balance |

The practical consequence: **when you model a controller, the question "what does it believe and who can influence that belief?" finds more real bugs per minute than any technique-enumeration checklist.** It also generalizes — it finds the class the checklist has not been updated for yet.

**Where this lens is allowed to appear — a Handbook rule, not a preference.** Process-model flaws are **causes of UCAs**, so they belong in Step 2 (recording what each controller believes) and Step 4 (explaining why the UCA occurs). They must **not** appear in a Step 3 UCA context, which has to state the *actual, true* state of the world. The Handbook's own example: ✓ *"provides Brake command during normal takeoff"*; ✗ *"provides Brake command when it incorrectly believes the aircraft is landing."*

Translated here: the UCA says *"grants access when the record belongs to a different tenant"* (true state). The scenario says *"…because the middleware derives tenant identity from a client-supplied header"* (the belief, and its bad source). Same bug, two steps, and keeping them separate is what makes the finding survive review — the UCA is a fact about the design, the scenario is a claim about the implementation.

---

## UCA type → vulnerability class

The four types, mapped to what they surface in software. Use this as a prompt when working the grid, never as a checklist to tick.

### Type 1 — Not providing the control action causes a hazard

- Authorization check omitted on a route, an internal caller path, or a newly added endpoint
- Revocation issued but never propagated to running sessions, caches, or downstream services
- Audit event not written, so a detection control has no input
- Rate limiting applied to the public path but not the API-key path
- Input validation skipped for callers assumed trusted
- Encryption or redaction not applied on a secondary path (exports, backups, logs, support tooling)
- Idempotency key not applied to a retryable money-moving operation
- MFA not required for a step-up-worthy action (role change, key rotation, export)

### Type 2 — Providing the control action causes a hazard

- Access granted when entitlement was assumed rather than established (the IDOR family)
- Data returned across a tenant, org, or classification boundary
- Refund, payout, or credit issued more than once, or to the wrong party
- Deploy executed on code that did not pass review, or to the wrong environment
- Role assigned by a system owner not authorized to assign it (privilege escalation via a legitimate feature)
- Password reset or account recovery issued to an address the adversary controls
- Export or bulk read served at a volume no legitimate use requires
- Impersonation invoked outside a support context, or without the impersonated party's visibility

### Type 3 — Wrong timing or order

- TOCTOU: entitlement checked, then the resource fetched by a re-supplied identifier
- Token validated before the revocation list refreshes
- Two concurrent requests each pass a balance check before either writes
- Deploy runs before the migration it depends on, or after a rollback that reverted it
- Idempotency key recorded after the side effect rather than before
- Webhook processed out of order, so a `subscription.cancelled` is overwritten by a late `subscription.created`
- Session established before device or risk checks complete
- Log written after the action rather than before, so a crash erases the evidence

### Type 4 — Applied too long or stopped too soon

- Session or refresh token with no expiry, or with an expiry longer than the review cycle
- Elevated privilege granted for a task and never dropped (JIT access that never expires)
- Lock or transaction held past its scope, enabling denial or a wider race window
- Break-glass credential still valid after the incident
- Rate-limit or lockout window ends too early, making brute force feasible
- Incident containment lifted before eradication completes
- Cached authorization decision outliving the authorization
- Retention exceeded — data kept past the point where holding it is itself the loss
- Log retention *too short* — the feedback loop stops before the investigation needs it

---

## Loss catalogue (starting menu — cut and adapt)

- L: Personal or customer data is disclosed to an unauthorized party
- L: Customer funds or assets are moved without the owner's authorization
- L: Records relied upon for business or legal purposes are altered undetectably
- L: A customer cannot access the service when they need it
- L: A regulatory or contractual obligation is breached
- L: One customer's data or actions become visible to another customer
- L: The organization loses control of its production environment
- L: The organization cannot determine what happened after an incident
- L: Credentials or keys enabling any of the above are disclosed
- L: Reputation or customer trust is damaged by a publicly visible failure

## Hazard catalogue (system states — cut and adapt)

Each phrased as a **state of the system**, not an attacker action and not a component failure.

- H: The system serves a resource to a system owner whose entitlement to it has not been established
- H: The system accepts a credential that no longer reflects the holder's current entitlements
- H: The system derives an authority-relevant attribute (identity, tenant, role) from input the requester controls
- H: The system permits a state change through a path that does not apply the constraints its primary path applies
- H: The system executes an irreversible external effect more than once for a single authorized request
- H: The system operates with authority exceeding what the current task requires
- H: The system retains data or credentials beyond the period for which their retention is justified
- H: The system performs a security-relevant action without producing a record sufficient to reconstruct it
- H: The system's authorization decision is based on state that has changed since the decision input was read
- H: The system trusts an assertion from an external party without establishing that party's identity
- H: The system exposes an internal control interface to a system owner outside the intended trust boundary
- H: The system runs code that did not pass the controls its release process requires

---

## Entry-point discovery by stack

Hints, not preconditions. `stpa scan` automates the first pass; these are for reading the results and for stacks the scanner does not know.

| Paradigm | Where control enters |
|----------|---------------------|
| **Node / Express / Fastify** | `app.get/post/...`, mounted routers, `app.use` middleware chains, socket handlers |
| **Next.js App Router** | `route.ts` exported `GET`/`POST`, server actions (`"use server"`), `middleware.ts`, API routes |
| **Python / Django / Flask / FastAPI** | `urls.py` / `@app.route` / `@router.*`, DRF viewsets, Celery tasks, management commands |
| **Java / Spring** | `@RestController` + `@*Mapping`, `@KafkaListener`, `@Scheduled`, filter chain, `SecurityConfig` |
| **Go** | `http.HandleFunc`, mux registration, gRPC service registration, interceptors |
| **Ruby / Rails** | `config/routes.rb`, `before_action` filters, ActiveJob, rake tasks |
| **Serverless** | function triggers (HTTP, queue, storage, schedule), IAM role per function |
| **Any** | queue/topic consumers, cron and scheduler entries, webhook receivers, CLI/admin tools, GraphQL resolvers, database triggers, CI workflow triggers (`on:` blocks) |
| **RPC / server actions** | Next.js `"use server"` modules, TanStack `createServerFn`, Astro `defineAction`, Qwik `server$`, tRPC procedures, Blitz resolvers |

**Server actions are entry points that are not routes, and counting routes will miss them entirely.** On a real analysis, 53 API routes were enumerated and 100% surface coverage declared while **19 `"use server"` modules** wrote the same tables from a parallel surface that was never modeled. If the framework has an RPC mechanism, enumerate it alongside the routes or the denominator is wrong before you start.

**Do not stop at HTTP.** Queue consumers, scheduled jobs, and CI triggers routinely carry more authority than any user-facing route and receive a fraction of the review.

---

## Design-document extraction recipe

Distinct from codebase extraction because the evidence is intent, not behavior.

1. **Sequence diagrams first.** Every arrow is a control action or a feedback signal. They are the densest source of control structure in any design document.
2. **Nouns that act** → controllers. **Nouns acted upon** → controlled processes. Roles and personas are controllers; treat them as such.
3. **Verbs at boundaries** → control actions. "The gateway forwards", "the worker consumes", "the operator approves".
4. **Mine for stated beliefs** — the language of process models is distinctive: *"validates and forwards"*, *"trusts"*, *"assumes"*, *"we cache … for performance"*, *"the token contains"*. Extract them verbatim with a section reference; these are the process models the authors did not know they were specifying.
5. **Mine for what is unsaid.** Per control action: failure behavior? retry semantics? concurrency? revocation? who else can invoke this? Each unanswered question is an assumption to log.
6. **Keep an assumptions log** — `assumption | basis | what breaks if wrong`. In design-document mode this log is a primary deliverable: it is the question list for the system's authors, and it is often worth more than the findings.
7. **If both code and document are available, diff them.** The document states intent; the code states reality. Every divergence is either a documentation defect or a security finding, and you cannot tell which without asking — which is exactly the conversation worth having.
