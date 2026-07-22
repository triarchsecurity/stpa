# Worked example — Ledgerline

A complete run against a **design document with no code** (`DESIGN.md`), which is
the modality most teams never try and the one where findings are cheapest to fix.

Everything here was produced by the pipeline in `Tools/`, not hand-written:

```bash
stpa init model.json            # 8 control actions -> 32 cells
stpa status                     # coverage arithmetic
stpa plan                       # findings -> bands, root causes, waves
stpa report                     # REPORT.html
```

## What to look at first

**The process-model table in `model.json`.** Six of the eight findings trace to a
row in it. The design document never says "the gateway trusts the `orgId` in the
token" — but it says the gateway *attaches* `orgId` *from* the token, and that is
the same sentence read as a belief with a source and a staleness.

**The tombstones.** 24 of 32 cells are resolved as "no hazard, because —". A
tombstone with a written reason is a result. Silence is not, and the coverage
figure only counts cells that got one.

**`04-scenarios.md`, Part B.** The impersonation finding and the webhook finding
are both bypass-class: no unsafe control action occurs, so Step 3 cannot reach
them. Part B is the only place in the method where they surface.

## The assumptions log

Modality B always produces one, and on a real review it is often worth more than
the findings — every entry is a question the document did not answer, addressed
to the person who wrote it. See the bottom of `01-scope.md`.
