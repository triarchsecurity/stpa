# Ledgerline — design document (fictional)

Multi-tenant invoicing API. This document is the *only* input to the worked
example in this directory: there is no Ledgerline codebase. It exists to show
what STPA finds from prose alone (Modality B), before a line is written.

## Overview

Organisations sign up, invite members, and issue invoices to their customers.
A public "pay link" lets a customer view and pay an invoice without an account.
A support console lets Ledgerline staff impersonate an org member to reproduce
issues. A nightly job emails overdue reminders. Webhooks notify orgs of payment.

## Components

- **API gateway** — validates the session JWT and attaches `orgId` from the token.
- **Invoice service** — CRUD over invoices, scoped by the `orgId` the gateway attached.
- **Pay-link service** — serves an invoice by its public token, no session required.
- **Support console** — staff select an org member and receive a session acting as them.
- **Reminder job** — nightly, iterates overdue invoices and sends email.
- **Webhook dispatcher** — POSTs payment events to a per-org URL configured by the org.

## Notes from the design review

- The pay-link token is a UUIDv4 stored on the invoice row and never rotates.
- Impersonation sessions carry the target member's `orgId` and a `staff: true` claim.
- Members can be removed from an org; existing sessions are not revoked.
- The webhook URL is whatever the org typed into settings.
