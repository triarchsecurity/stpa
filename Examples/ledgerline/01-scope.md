# Scope, losses and hazards

**Target:** Ledgerline — multi-tenant invoicing API. **Modality B**: the design document is the only input; no code exists. Surface 100% (8/8 control actions described by the document).

## Losses

- **L-1** — one organisation's invoice data is disclosed to a party outside that organisation.
- **L-2** — Ledgerline staff read customer data without a business reason, and the customer cannot tell.

Availability losses are deliberately **not** declared. Tombstones that cite "out of hazard" name which loss they fall outside, so the boundary is legible rather than implied.

## Hazards — system states, never attacker actions

- **H-1** — the system serves invoice data to a principal whose entitlement to that organisation is not current. *(→ L-1)*
- **H-2** — the system grants a staff principal access to an organisation's data with no record the organisation can read. *(→ L-2)*
- **H-3** — the system delivers organisation event data to a network endpoint it has not established is external and org-controlled. *(→ L-1)*

Note the shape. "An attacker guesses a pay-link token" is not a hazard — it is an attacker action. The hazard is the state the system is in: *serving invoice data to a principal whose entitlement is not current*. Guessing the token is one way to reach that state; so is a forwarded email, a browser-history export, and a support agent pasting the link into a ticket. Writing the state instead of the action is what makes the finding survive techniques nobody has thought of yet.

## Assumptions log

Modality B produces one every time, and on a real review it is often the most valuable artifact — each line is a question for the document's author.

| # | Assumed | Because the document does not say | Ask |
|---|---|---|---|
| A-1 | Session tokens are bearer JWTs with a lifetime measured in hours | "validates the session JWT" | What is the TTL, and is there a revocation list? |
| A-2 | The gateway sets an internal header the invoice service trusts | "attaches `orgId` from the token" | Can a client set that header directly? Is the gateway the only ingress? |
| A-3 | Downstream services do not read the `staff: true` claim | It is described as carried, never as consumed | Which services branch on it? What do they do differently? |
| A-4 | Pay-link tokens appear in emails sent to customers | "a public pay link lets a customer view and pay" | How is the link delivered, and to how many recipients? |
| A-5 | The webhook dispatcher runs inside the production network | It is listed as a component with no isolation note | Does it egress through a proxy? Is there an allow-list? |
| A-6 | Removal from an org is a database update with no session sweep | "existing sessions are not revoked" | Is that a decision or an omission? |

**A-6 is the highest-value line in the table.** The document states it as a fact in a review note, and it is the direct cause of two of the eight findings. In a real review this is the moment to ask whether anyone realised they were writing down a vulnerability.
