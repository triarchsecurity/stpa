# Security policy

## Reporting a vulnerability in this toolkit

Email **security@triarchsecurity.com**. Please do not open a public issue for a vulnerability in the toolkit itself.

The attack surface is small on purpose: the tools read JSON and markdown from a directory you point them at, and write HTML and JSON back. There are no network calls, no API keys, and no telemetry. The most plausible issues are (a) HTML injection through analysis content into the rendered report, and (b) path handling in the CLI. Both are worth reporting.

## Reporting findings you produced *with* this toolkit

Those belong to the owner of the system you analysed, not here. Do not open an issue containing them.

## Scope note

This is an analysis tool. It reads files you give it and never contacts the system under analysis, so running it cannot affect a production system. It also means it cannot confirm exploitability — a finding here is a hypothesis with a control-theoretic argument behind it, and confirming it is a separate job.
