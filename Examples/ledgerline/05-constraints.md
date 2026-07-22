# Security constraints

| ID | Constraint | Probe |
|---|---|---|
| **SC-1** | An authorization decision MUST NOT rely on an `orgId` claim without confirming current membership. | Test: remove a member, then call an invoice route with their pre-removal token → 403. |
| **SC-2** | A pay-link token MUST NOT remain valid after the invoice is paid or voided. | Test: pay an invoice, re-fetch by token → 410. |
| **SC-3** | The invoice service MUST NOT trust an `orgId` header that a client could set. | Test: send the header directly, bypassing the gateway → rejected. |
| **SC-4** | A staff impersonation session MUST NOT be established without a recorded reason visible to the impersonated organisation. | Assert an org-readable audit row exists for every session with `staff: true`. |
| **SC-5** | The webhook dispatcher MUST NOT connect to an address outside the public-internet ranges, resolved **at dispatch time**. | Test: configure a hostname that resolves to 169.254.169.254 at dispatch → connection refused and logged. |
| **SC-6** | Pay-link fetches MUST be recorded with source and timestamp. | Assert a row exists per fetch; alert on N fetches from distinct sources for one invoice. |
