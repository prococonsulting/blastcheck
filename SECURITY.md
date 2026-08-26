# Security policy

## Reporting a vulnerability

Email **kproffitt@prococonsulting.com**. Please do not open a public issue for a
security report.

Include what you did, what happened, and what you expected. A plan fixture that
reproduces the behaviour is worth more than a paragraph describing it.

You will get an acknowledgement within 72 hours. This is maintained by one
person, so that is a real commitment rather than an aspirational SLA.

## What counts as a vulnerability here

blastcheck reads a file and writes a file. It takes no credentials, opens no
network connections, and has no runtime dependencies, so the usual categories
mostly do not apply.

The security-relevant failure mode is different and specific: **a manifest that
understates risk.** Concretely —

- A plan that should produce `blocked` or `unknown` and instead produces
  `caution` or `informational`.
- Any input that causes a plan-only run to emit `verdict.decision: safe`. That
  is structurally impossible by design; if you find one, it is the highest
  severity report this project can receive.
- A dimension returning a benign value (`none`, `reversible`, `no_data_loss`,
  `unchanged`) for a change that is not actually benign — particularly where the
  cause is a field the tool could not read and did not say so.
- A crafted plan that makes `--verify` accept a manifest whose payload was
  altered, or that makes two logically identical manifests produce different
  digests.

Crashes and unhandled exceptions are bugs, not vulnerabilities — a tool that
fails loudly has not endangered anyone. Please file those as normal issues.

## Scope

This policy covers the `blastcheck` package and the schema it vendors. The
Impact Manifest specification lives in a separate repository and has its own
policy.
