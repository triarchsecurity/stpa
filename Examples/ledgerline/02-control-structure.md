# Control structure

Read entirely off `DESIGN.md`. Six controllers, eight control actions, four feedback channels — three of which do not exist.

## Process models — the highest-yield table in the analysis

Six of eight findings trace to a row here. Note how each belief was extracted: the document never writes "the gateway *trusts* the orgId claim", it writes that the gateway *attaches* orgId *from* the token. Same sentence, read as `believes / sourced from / staleness`.

| ID | Controller believes | Sourced from | Staleness |
|---|---|---|---|
| **PM-1** | the `orgId` in the token is the caller's current org | the JWT claim, minted at login, never re-read | token lifetime — and the review notes say removal does not revoke sessions, so it is wrong for exactly that long |
| **PM-2** | the presenter of a pay-link token is the invoice's customer | possession of a UUIDv4 that never rotates | **permanent** — the token outlives the payment, the relationship and any dispute |
| **PM-3** | an impersonation session is distinguishable from the member's own | a `staff: true` claim no service is documented to read | asserted, never checked |
| **PM-4** | the `orgId` attached by the gateway is authoritative | a header set upstream, trusted without re-derivation | per request, and only ever as good as PM-1 |
| **PM-5** | the email on an overdue invoice is still the right recipient | the invoice row as written at issue time | unbounded — an invoice stays overdue for months |
| **PM-6** | the configured webhook URL is an external endpoint the org controls | a free-text settings field, no validation described | whatever was last typed |

## Feedback

| ID | Channel | State |
|---|---|---|
| **F-1** | pay-link service → org | **ABSENT.** No record of who fetched an invoice by token, so scraping is indistinguishable from a customer opening their bill |
| **F-2** | support console → impersonated member | **ABSENT.** The member is never told, and has no audit surface to read |
| **F-3** | webhook dispatcher → security review | **ABSENT.** No allow-list check and no egress log on an org-supplied URL |
| **F-4** | invoice service → org | Present (invoice audit trail) |

Three of four channels do not exist. That is a Step-2 finding on its own: no unsafe control action is required for it to hurt you, because it is what makes every other finding silent.
