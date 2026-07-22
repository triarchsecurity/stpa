# Loss scenarios

**Part A** — why the unsafe control action occurs. **Part B** — why a *correct* control action fails to land. Part B is the bypass class, and Step 3 structurally cannot reach it, because in Part B nothing unsafe was ever commanded.

---

## S-1 — A removed member keeps reading invoices · CA-2.provided, CA-6.duration, CA-1.timing-order · PM-1, PM-4

**Part A.** The gateway mints `orgId` into the token at login and never re-reads it. The invoice service then trusts the header the gateway attaches, so the belief is laundered through two components without either one owning it. Remove a member and the row changes; the token does not. For the rest of the token's lifetime the system serves that member their former org's invoices, and every component involved is behaving exactly as designed.

**Part B.** Re-reading membership on every request fixes the API and does not fix the loss, because **the session is not the only credential that outlives the relationship**. That member has pay links in their inbox (S-2), an export they downloaded last week, and possibly a webhook URL they configured that still points at a host they control (S-3). Revocation that reaches only the session boundary leaves three other paths open — and the design document describes no inventory of what a departing member holds, so nobody can enumerate them.

---

## S-2 — The pay link is permanent · CA-3.provided, CA-3.duration · PM-2, F-1

**Part A.** Entitlement is possession of a UUIDv4 that never rotates and never expires. UUIDv4 is unguessable, so this is not a brute-force finding — it is a **distribution** finding. The token is emailed, which means it lands in a mailbox, a mail archive, a forwarded thread, a shared inbox, a helpdesk ticket, and a browser history. Every one of those is a copy that outlives the payment.

**Part B — the cleanest bypass in this example.** Suppose the token check is perfect. It is *still* correct to serve the invoice to whoever presents it, because the design defines entitlement as possession. No authorization logic can distinguish the customer from the person the customer forwarded the mail to; the control loop is working exactly as specified and the data leaves anyway. The fix is therefore not in the check — it is in the **lifetime and the binding**: expire the token at payment, rotate on dispute, and require a second factor the customer already has. And with **F-1 absent**, nobody can even measure how often this happens, so there is no evidence to motivate the change.

---

## S-3 — The webhook URL is an SSRF primitive · CA-8.provided · PM-6, F-3

**Part A.** The org types a URL into a settings field and the dispatcher POSTs to it from inside the production network. PM-6 believes the URL is an external endpoint the org controls; nothing establishes either half of that belief. `http://169.254.169.254/`, `http://localhost:6379/`, and an internal admin host are all valid strings.

**Part B.** An allow-list on save is the obvious control and it is bypassable without any incorrect control action occurring: **the name resolves at dispatch, not at save.** A hostname that validated cleanly on Tuesday can point at a link-local address on Wednesday — DNS rebinding needs nothing in the request path to malfunction. Validation and use are separated by an interval the design does not close, which is a TOCTOU with a network in the middle. The control has to live at egress — a proxy that resolves and refuses — not at the form.

---

## S-4 — Impersonation is invisible · CA-5.provided · PM-3, F-2

**Part A.** Staff select a member and receive a session acting as them. The document describes no ticket requirement, no consent step, and no scope limit. PM-3 asserts the `staff: true` claim makes the session distinguishable, but the document names no service that reads it — an assertion with no consumer.

**Part B.** Add the ticket requirement and the loss survives, because **the record is written where the affected party cannot read it**. F-2 does not exist: the member is never notified, and there is no audit surface exposed to the organisation. Internal logging satisfies the auditor and does nothing for the customer — and the customer is the only party with both the motive and the context to spot an impersonation that had a plausible ticket attached to it. Accountability that only points inward is not accountability to the person whose data was read.

---

## S-5 — The reminder emails the wrong person · CA-7.provided · PM-5

**Part A.** The recipient is snapshotted onto the invoice at issue time. An invoice can be overdue for months; contacts change, people leave, addresses get reassigned. The job faithfully mails invoice contents to an address that was correct once.

**Part B.** Reading the current contact at send time fixes the common case and introduces its own: the *current* contact may be a person who was not party to the original transaction. There is no single correct answer here, which is exactly why it belongs in the design review rather than in a ticket. The finding's real output is a question for the author — **whose invoice is it, the org's or the individual's?** — and the document does not say.
