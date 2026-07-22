# UCA Grid — Ledgerline — multi-tenant invoicing API (fictional; design document only, no code)

Coverage: **100.0%** (32/32 cells) — 8 control actions x 4 UCA types. Counted: findings bound to a declared control-structure element, plus reasoned tombstones.

## CA-1 — API gateway → issue a session for a member

| type | state | statement / reason | binds to | links to |
|------|-------|--------------------|----------|----------|
| not-provided | n/a | Failing to provide this action withholds service from a legitimate party. That is an availability loss, and this run is bounded to the confidentiality and integrity losses named in 01-scope.md. Recorded as out of hazard, not unexamined — re-run with an availability loss declared to resolve it. |  |  |
| provided | n/a | No context of this action places one org's data in another org's response or in an unintended channel. The action operates within a single org scope that the design derives from the caller, and the derivation itself is examined at CA-2.provided rather than repeated here. |  |  |
| timing-order | **UCA** | The API gateway mints a session carrying an orgId before membership is confirmed current, leading to H-1 for the token's lifetime. | PM-1 |  |
| duration | n/a | This action is request-scoped in the design: it completes within one request and establishes no standing grant, so there is no interval over which it can run too long or stop too soon. The two standing grants in this system are the session (CA-6.duration) and the pay link (CA-3.duration), both resolved. |  |  |

## CA-2 — Invoice service → serve an invoice to a session

| type | state | statement / reason | binds to | links to |
|------|-------|--------------------|----------|----------|
| not-provided | n/a | Failing to provide this action withholds service from a legitimate party. That is an availability loss, and this run is bounded to the confidentiality and integrity losses named in 01-scope.md. Recorded as out of hazard, not unexamined — re-run with an availability loss declared to resolve it. |  |  |
| provided | **UCA** | The invoice service serves an invoice to a session when the session's orgId claim no longer matches the caller's current membership, leading to H-1 (a former member reads an org's invoices). | PM-1, PM-4 |  |
| timing-order | n/a | No ordering dependency in this action reaches a hazard state — it neither opens nor consumes a window in which another controller's belief about entitlement is stale. The stale-entitlement window in this design is the session claim, resolved once at CA-1.timing-order. |  |  |
| duration | n/a | This action is request-scoped in the design: it completes within one request and establishes no standing grant, so there is no interval over which it can run too long or stop too soon. The two standing grants in this system are the session (CA-6.duration) and the pay link (CA-3.duration), both resolved. |  |  |

## CA-3 — Pay-link service → serve an invoice by pay-link token

| type | state | statement / reason | binds to | links to |
|------|-------|--------------------|----------|----------|
| not-provided | n/a | Failing to provide this action withholds service from a legitimate party. That is an availability loss, and this run is bounded to the confidentiality and integrity losses named in 01-scope.md. Recorded as out of hazard, not unexamined — re-run with an availability loss declared to resolve it. |  |  |
| provided | **UCA** | The pay-link service serves an invoice when the presenter is anyone who has ever seen the link, including after the customer relationship ends, leading to H-1 (invoice contents disclosed to a non-customer). | PM-2, F-1 |  |
| timing-order | n/a | No ordering dependency in this action reaches a hazard state — it neither opens nor consumes a window in which another controller's belief about entitlement is stale. The stale-entitlement window in this design is the session claim, resolved once at CA-1.timing-order. |  |  |
| duration | **UCA** | The pay-link service keeps honouring a pay-link token indefinitely after the invoice is paid, leading to H-1. | PM-2 |  |

## CA-4 — Invoice service → modify or void an invoice

| type | state | statement / reason | binds to | links to |
|------|-------|--------------------|----------|----------|
| not-provided | n/a | Failing to provide this action withholds service from a legitimate party. That is an availability loss, and this run is bounded to the confidentiality and integrity losses named in 01-scope.md. Recorded as out of hazard, not unexamined — re-run with an availability loss declared to resolve it. |  |  |
| provided | n/a | No context of this action places one org's data in another org's response or in an unintended channel. The action operates within a single org scope that the design derives from the caller, and the derivation itself is examined at CA-2.provided rather than repeated here. |  |  |
| timing-order | n/a | No ordering dependency in this action reaches a hazard state — it neither opens nor consumes a window in which another controller's belief about entitlement is stale. The stale-entitlement window in this design is the session claim, resolved once at CA-1.timing-order. |  |  |
| duration | n/a | This action is request-scoped in the design: it completes within one request and establishes no standing grant, so there is no interval over which it can run too long or stop too soon. The two standing grants in this system are the session (CA-6.duration) and the pay link (CA-3.duration), both resolved. |  |  |

## CA-5 — Support console → grant a staff member an impersonation session

| type | state | statement / reason | binds to | links to |
|------|-------|--------------------|----------|----------|
| not-provided | n/a | Failing to provide this action withholds service from a legitimate party. That is an availability loss, and this run is bounded to the confidentiality and integrity losses named in 01-scope.md. Recorded as out of hazard, not unexamined — re-run with an availability loss declared to resolve it. |  |  |
| provided | **UCA** | The support console grants an impersonation session when the staff member has no ticket or consent tying them to that org, leading to H-2 (staff read customer data without a business reason). | PM-3, F-2 |  |
| timing-order | n/a | No ordering dependency in this action reaches a hazard state — it neither opens nor consumes a window in which another controller's belief about entitlement is stale. The stale-entitlement window in this design is the session claim, resolved once at CA-1.timing-order. |  |  |
| duration | n/a | This action is request-scoped in the design: it completes within one request and establishes no standing grant, so there is no interval over which it can run too long or stop too soon. The two standing grants in this system are the session (CA-6.duration) and the pay link (CA-3.duration), both resolved. |  |  |

## CA-6 — API gateway → remove a member from an org

| type | state | statement / reason | binds to | links to |
|------|-------|--------------------|----------|----------|
| not-provided | n/a | Failing to provide this action withholds service from a legitimate party. That is an availability loss, and this run is bounded to the confidentiality and integrity losses named in 01-scope.md. Recorded as out of hazard, not unexamined — re-run with an availability loss declared to resolve it. |  |  |
| provided | n/a | No context of this action places one org's data in another org's response or in an unintended channel. The action operates within a single org scope that the design derives from the caller, and the derivation itself is examined at CA-2.provided rather than repeated here. |  |  |
| timing-order | n/a | No ordering dependency in this action reaches a hazard state — it neither opens nor consumes a window in which another controller's belief about entitlement is stale. The stale-entitlement window in this design is the session claim, resolved once at CA-1.timing-order. |  |  |
| duration | **UCA** | The API gateway continues to honour sessions minted before a member was removed, for the remainder of the token lifetime, leading to H-1. | PM-1 |  |

## CA-7 — Reminder job → send an overdue reminder email

| type | state | statement / reason | binds to | links to |
|------|-------|--------------------|----------|----------|
| not-provided | n/a | Failing to provide this action withholds service from a legitimate party. That is an availability loss, and this run is bounded to the confidentiality and integrity losses named in 01-scope.md. Recorded as out of hazard, not unexamined — re-run with an availability loss declared to resolve it. |  |  |
| provided | **UCA** | The reminder job emails an overdue invoice to the address captured at issue time when that address is no longer the customer's, leading to H-1. | PM-5 |  |
| timing-order | n/a | No ordering dependency in this action reaches a hazard state — it neither opens nor consumes a window in which another controller's belief about entitlement is stale. The stale-entitlement window in this design is the session claim, resolved once at CA-1.timing-order. |  |  |
| duration | n/a | This action is request-scoped in the design: it completes within one request and establishes no standing grant, so there is no interval over which it can run too long or stop too soon. The two standing grants in this system are the session (CA-6.duration) and the pay link (CA-3.duration), both resolved. |  |  |

## CA-8 — Webhook dispatcher → dispatch a payment webhook

| type | state | statement / reason | binds to | links to |
|------|-------|--------------------|----------|----------|
| not-provided | n/a | Failing to provide this action withholds service from a legitimate party. That is an availability loss, and this run is bounded to the confidentiality and integrity losses named in 01-scope.md. Recorded as out of hazard, not unexamined — re-run with an availability loss declared to resolve it. |  |  |
| provided | **UCA** | The webhook dispatcher POSTs a payment event when the configured URL points at an internal address, leading to H-3 (internal endpoints reached from inside the trust boundary, and event contents delivered to an unintended host). | PM-6, F-3 |  |
| timing-order | n/a | No ordering dependency in this action reaches a hazard state — it neither opens nor consumes a window in which another controller's belief about entitlement is stale. The stale-entitlement window in this design is the session claim, resolved once at CA-1.timing-order. |  |  |
| duration | n/a | This action is request-scoped in the design: it completes within one request and establishes no standing grant, so there is no interval over which it can run too long or stop too soon. The two standing grants in this system are the session (CA-6.duration) and the pay link (CA-3.duration), both resolved. |  |  |
