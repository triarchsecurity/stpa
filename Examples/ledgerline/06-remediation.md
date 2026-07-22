# 06 — Engineering plan

**8 findings → 4 root causes.** 1 band-1, 4 band-2. 2 quick wins (band ≤2, hours of work). Wave 1 is 3 items and closes 60% of everything band-2-or-worse.

> Band is severity × reachability, a toolkit extension — **not a probability, not CVSS-comparable.** It orders this analysis's findings for this team and nothing else.

## Highest-leverage move

**Entitlement is decided from a claim, never from current state** — one change closes **3 of 8** findings (effort: M, days).

The gateway mints orgId at login and never re-reads it, and the invoice service trusts the header the gateway attaches. Neither component owns the belief, so neither refreshes it. The design note 'existing sessions are not revoked' is the same defect stated as a fact.

**Do this:** Derive org membership at the point of use, from the membership table, with a short cache. Make the gateway header advisory rather than authoritative.

## Root causes, by leverage

| cluster | closes | worst band | effort | the one change |
|---|---|---|---|---|
| **Entitlement is decided from a claim, never from current state** | 3 findings | 2 | M · days | Derive org membership at the point of use, from the membership table, with a short cache. Make the gateway header advisory rather than authoritative. |
| **Possession of a long-lived token is treated as entitlement** | 2 findings | 2 | S · hours | Bind pay-link validity to invoice state: expire at payment, rotate on dispute, and require a second factor the customer already holds. |
| **Three of four feedback channels do not exist** | 2 findings | 3 | L · weeks | Log the pay-link fetch, expose an org-readable impersonation trail, and record webhook egress destinations. |
| **Org-supplied input reaches the network without an egress control** | 1 finding | 1 | M · days | Route all webhook egress through a proxy that resolves and refuses non-public addresses at connect time. |

## Wave 1 — start here (3)

| id | band | effort | where | do this | verify with |
|---|---|---|---|---|---|
| `CA-8.provided` | 1 | M | `DESIGN.md — 'the webhook URL is whatever the org typed'` | Egress proxy that resolves at connect time and refuses non-public addresses. | `Configure a host resolving to 169.254.169.254 → connection refused and logged.` |
| `CA-3.provided` | 2 | S | `DESIGN.md — 'pay-link token is a UUIDv4 ... never rotates'` | Expire the token on payment or void; rotate on dispute. | `Pay an invoice, re-fetch by token → expect 410.` |
| `CA-3.duration` | 2 | S | `DESIGN.md — pay-link section` | Give the token a TTL independent of invoice state as a backstop. | `Fetch a token older than the TTL → expect 410.` |

## Wave 2 — this cycle (2)

| id | band | effort | where | do this | verify with |
|---|---|---|---|---|---|
| `CA-2.provided` | 2 | M | `DESIGN.md — 'Invoice service — scoped by the orgId the gateway attached'` | Look up current membership at the point of use instead of trusting the claim. | `Remove a member, call an invoice route with the pre-removal token → expect 403.` |
| `CA-6.duration` | 2 | M | `DESIGN.md — 'existing sessions are not revoked'` | Sweep and invalidate sessions on membership removal. | `Remove a member with a live session; assert the session is rejected within 60s.` |

## Wave 3 — scheduled (2)

| id | band | effort | where | do this | verify with |
|---|---|---|---|---|---|
| `CA-1.timing-order` | 3 | S | `DESIGN.md — 'attaches orgId from the token'` | Stop treating the login-time claim as an entitlement; carry identity, derive authority. | `Assert no route reads orgId from the token without a membership lookup.` |
| `CA-5.provided` | 3 | M | `DESIGN.md — support console section` | Require a recorded reason, and expose the impersonation trail to the organisation. | `Assert an org-readable audit row exists for every staff:true session.` |

## Backlog — accept explicitly, in writing (1)

| id | band | effort | where | do this | verify with |
|---|---|---|---|---|---|
| `CA-7.provided` | 4 | S | `DESIGN.md — reminder job section` | Resolve the recipient at send time and log which contact was used. | `Change the org contact, trigger a reminder, assert the new contact received it.` |

## Reachability legend

- **R0** — adversary creates the context directly
- **R1** — adversary induces it through normal interaction
- **R2** — adversary waits for it to arise
- **R3** — requires a prior foothold
- **R4** — requires an insider or supply-chain compromise

## Plan quality

| measure | value | why it matters |
|---|---|---|
| Findings with a file location | 100% | an unlocated finding costs an engineer an hour before work starts |
| Findings with a runnable probe | 100% | without one, "fixed" is an opinion |
| Root-cause concentration | 38% | share of findings the single biggest fix closes |