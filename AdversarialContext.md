# Adversarial Context — what makes this *active* threat modeling

Safety STPA assumes the environment is indifferent. Security cannot. This file is the adaptation that turns hazard analysis into threat modeling, and it is where the "active" part of active threat modeling lives.

This is a toolkit extension built on STPA-Sec's framing (Young & Leveson). Where it goes beyond the published method, it says so.

---

## The core move: the adversary is a context selector

The instinct when adding an adversary to a model is to give them new powers — new control actions, new capabilities, an attack tree. That instinct produces a threat model whose completeness depends on your imagination about attacker techniques, which is exactly the property that makes checklist threat modeling age badly.

STPA's framing is stronger and stranger:

> **The adversary does not add control actions. The adversary chooses the context.**

Every UCA already has the shape *"this control action is hazardous when \<context\>"*. In safety analysis you ask how likely that context is. In security analysis you ask a different question:

> **Can an adversary bring the context about, or wait for it, or find a path into it?**

This has three consequences worth stating plainly:

1. **Safety findings and security findings come from the same grid.** You do not run two analyses. The security question is a second pass over the same cells with a hostile answer to "how would we get into that context?"
2. **You stop needing to enumerate attacker techniques to be complete.** Techniques are *how* a context is reached — they belong in Step 4 scenarios, not in the definition of what is unsafe. New techniques appear constantly; the set of hazardous contexts changes only when the design changes.
3. **A control action that is safe in every reachable context is genuinely safe**, and you can say so with a reason instead of a shrug. That is what a tombstone with a reason is.

---

## Context reachability

For each UCA context, rate how an adversary gets there. This replaces likelihood — it is about **access**, which is a property of your design, not a guess about the world.

| Rating | Meaning | Examples |
|--------|---------|----------|
| **R0 — Adversary creates it directly** | The context is a function of adversary-controlled input | Supplying a tenant id in a header; choosing an object id; setting a field in a request body; picking the algorithm in a JWT header |
| **R1 — Adversary induces it** | Reachable through legitimate interaction, timing, or volume | Racing two requests; triggering a retry; filling a cache; forcing an error path; registering an account with a chosen attribute |
| **R2 — Adversary waits for it** | It arises on its own; the adversary only needs to be present | Stale-permission window after a role change; replication lag; a scheduled job's execution moment; a deploy window |
| **R3 — Requires a prior foothold** | Needs another compromise first | Access to an internal network segment; a valid low-privilege account; a compromised CI secret; SSRF as a stepping stone |
| **R4 — Requires an insider or supply chain** | Needs a trusted party to act | Operator with production database access; a malicious dependency; a compromised third-party integration |

**R0 and R1 are the ones people underrate.** They require no compromise at all: the adversary simply exercises the system as designed, in a context its designers did not consider. That is where most real breaches live.

### Reachability is a property of the DEPLOYMENT, not the code — this is where ratings quietly go wrong

The R0–R4 band is meaningful only against the *deployed* system. The **same missing check** gets a completely different band depending on facts the code does not contain:

- **Where does the entry point live?** An unauthenticated route on an internet-facing service is R0; the identical route on an internal, private-network service is R3 (a foothold is needed first). A zero-auth message bus is R0 if the broker is externally reachable, R3 if it runs on a per-deployment private network.
- **What is the tenancy topology?** "No tenant scope" is a *live cross-tenant read* in a shared multi-tenant store, but merely *latent design-debt* in a single-tenant-per-customer deployment — there is no second tenant to leak to. In that case the live cross-tenant surface is wherever tenants are actually pooled: a central archive, a shared bucket, a shared identity, the deploy pipeline. That is a distinct **trust zone** and must be modeled as its own slice, or the real cross-tenant finding is missed while the latent one is over-rated.
- **Which non-code controls are in force?** IAM on a bucket, a network segment, a broker ACL, a WAF — these are controllers. One can *close* a finding (tombstone it, naming the control) or be *assumed but unverified* (rate it provisional).

Two disciplines follow. **(1) Locate every finding in a trust zone and state its blast radius** — one tenant / all tenants / one deployment / the fleet / one cloud account / all accounts. Topology decides both, and blast radius is what separates a P0 from a P3. **(2) When a band depends on an environment fact you have not confirmed, mark it provisional and tag the assumption** — a provisional band must never be ranked as if it were confirmed. The failure this prevents: rating internal, foothold-required, within-one-tenant paths as external, zero-foothold, cross-tenant ones, while the genuinely cross-tenant central plane goes unmodeled. Deployment topology lives in terraform/IaC, network config and IAM — never in the application code — so it is a mandatory hand-gathered input, read *before* bands are assigned.

---

## Generic adversary-reachable context patterns

Run these against every grid cell before concluding "no hazard". They are the questions that convert a safety pass into a security pass.

1. **The value came from the requester.** Any authority-relevant attribute sourced from a header, body, query parameter, cookie, subdomain, or filename. R0.
2. **Two things happen at once.** Any check-then-act sequence without a lock, a transaction, or a compare-and-swap. R1.
3. **Something is cached.** Any belief with a TTL is wrong for up to that TTL, and the adversary can often choose when to act within it. R1–R2.
4. **The error path differs from the success path.** Exception handlers, fallbacks, and retries that skip a control the main path applies. R1.
5. **There is a second way in.** Admin console, support tool, migration script, direct database access, a sibling service, a bulk endpoint, an internal API. R1–R4.
6. **The caller is assumed internal.** Any control that depends on network position rather than on an authenticated identity. R3 — and R0 the moment SSRF exists anywhere.
7. **State changed after the check.** Permission revoked, account banned, plan downgraded, resource reassigned — between the decision and the effect. R2.
8. **The action is retried.** Any non-idempotent effect behind a retry, a queue redelivery, or an impatient user. R1.
9. **The volume is unusual.** Controls that hold for one request and fail for ten thousand: enumeration, exhaustion, timing oracles, rate-limit boundaries. R1.
10. **An external party asserted it.** Webhooks, callbacks, OAuth responses, federated identity claims, third-party data. R0 if unauthenticated.
11. **A default applied.** Any path where a value was absent and a default was used: unset flag, missing config, new tenant, empty list treated as "allow all". R0–R1.
12. **The clock matters.** Expiry comparisons, skew tolerance, scheduled windows, retention boundaries, TOTP drift. R1–R2.
13. **The runtime carries credentials.** Any controller whose process environment holds ambient cloud/instance/task credentials, secrets, or a reachable credential/metadata endpoint — those tokens are *portable*: anything running in that runtime (a shipped shell, a debug console, an injected process) can lift them and use them off the application path, under the workload's identity, on everything that identity can reach. R3 when it needs shell/console access; R1 if that console is broadly reachable. The application's authorization model never sees the use, and downstream logs show the operator's own network identity — or a shared service identity — not the system.

---

## The four scenario surfaces, adversarially

Step 4's causal categories, read as attack surfaces.

### Feedback manipulation — making the controller's information wrong

- **Log injection** — newline or field-separator injection makes the audit trail describe a different event than occurred
- **Alert flooding** — the human controller's feedback channel is saturated, so the real signal is not acted on
- **Suppressed feedback** — the adversary's actions produce no event because that path was never instrumented
- **Forged callbacks** — an unauthenticated webhook asserts an event that did not happen
- **Oracle abuse** — feedback intended for the legitimate caller (timing, error text, status-code differences) is read by the adversary to build a model of your system
- **Log deletion / retention gaming** — act, then wait out the retention window

### Process-model poisoning — making the controller believe something false

- Setting an authority-relevant field the controller reads without validating (tenant, role, `isAdmin`, price, quantity)
- Poisoning a cache the controller trusts, then acting during its TTL
- Registering an account whose attributes place it on a privileged code path
- Exploiting the gap between two stores holding the same fact (auth service says revoked, session store does not yet)
- Supplying an algorithm, content type, or encoding that changes how the controller interprets its own input
- Triggering a default: omit the field and let the fallback decide

### Control-path compromise — the instruction is intercepted or forged

- Unauthenticated internal service calls — anyone who reaches the network can issue control actions
- Message queues without message-level authentication: publish directly, bypass the producer's checks
- SSRF that reaches an internal control plane (metadata service, admin API, cluster endpoint)
- Replay of a valid, captured request
- Request smuggling or parser differential between proxy and origin — two components disagree about what the request is
- Compromised CI secrets: the deploy control action is legitimate, the issuer is not

### Independent modification of the controlled process — the bypass class

**The highest-yield category in real systems, and the one component-oriented threat modeling structurally cannot see**, because no component is broken.

- A second service writing the same table without the scoping the first applies
- Direct database access held by operators, migration jobs, or analytics pipelines
- An admin console that calls the data layer directly instead of the API
- Object storage reachable by signed URL, bypassing the application entirely
- Backups, exports, replicas, and search indexes with weaker controls than the primary
- A support impersonation tool with no equivalent of the user-facing constraints
- A cron job running as root because it was easier
- A shipped shell/console (web terminal, CLI simulator, debug page) whose environment carries the workload's own credentials — an operator lifts *portable* credentials and acts on the downstream account directly from off-box, under a shared workload identity; the guarded application path is never involved, and the only trace is the operator's own network identity in the downstream logs, not the system's. (This is a real incident pattern, not a hypothetical: it is how "I was just troubleshooting" becomes an unattributable change in a customer's account.)

---

## Prioritisation heuristic

**This is a toolkit extension, not STPA doctrine.** STPA deliberately does not rank findings by probability, and the reasoning is sound: probability estimates in security are usually a way of dismissing findings you do not want to fix. But an unranked list of forty findings does not get acted on either.

The compromise: rank by **loss severity × context reachability**. Neither term is a probability. Severity comes from your own loss list; reachability is a property of your design that you can read off the model.

| | R0 create | R1 induce | R2 wait | R3 foothold | R4 insider/supply |
|---|---|---|---|---|---|
| **Catastrophic loss** | **1** | **1** | **2** | 2 | 3 |
| **Severe loss** | **1** | **2** | 2 | 3 | 3 |
| **Moderate loss** | 2 | 3 | 3 | 4 | 4 |
| **Minor loss** | 3 | 4 | 4 | 4 | 4 |

Band 1: fix before ship. Band 2: fix this cycle. Band 3: constrain and schedule. Band 4: accept explicitly, in writing, in `## Decisions`.

**What this is not:** it is not a probability, not a CVSS score, and not comparable across systems. It orders *this* analysis's findings for *this* team. Reporting it as a risk score to anyone outside that context misrepresents it.

**Read the R4 column carefully before dismissing it.** Requiring an insider or a supply-chain compromise is not the same as being unlikely — it is the same as saying "this is exactly what happens in the incidents that make the news." A catastrophic-loss R4 finding at band 3 deserves a conversation, not a backlog row.
