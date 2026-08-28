# blastcheck

**blastcheck** reads a `terraform show -json` plan and emits an **[Impact Manifest](https://github.com/prococonsulting/impact-manifest)** — a machine-readable change-safety assertion. It is the reference producer of that open format.

```
terraform plan -out plan.tfplan
terraform show -json plan.tfplan | blastcheck > manifest.json
```

`terraform plan` tells you *what* will change. blastcheck adds the layer the plan can't: for each change, is it reversible, does anything become unrecoverable, does exposure widen, and — honestly — what could it *not* determine.

## What it does, and what it deliberately doesn't

blastcheck is **offline by default**: no credentials, no network, no hosted service. It reasons from the plan artifact alone. Wherever a verdict genuinely requires live cloud state — "is this disk attached to something serving traffic?", "does a backup exist?" — it emits `unknown` / `not_verified` **with a stated reason**, rather than guessing.

A direct consequence, and the point of the format: **a plan-only run can never emit `safe`.** It never verified live state, so it says `caution`, `blocked`, or `unknown` — never `safe`. Certifying `safe` requires `--live` (below). blastcheck is honest about the ceiling of what a plan alone can prove.

What it derives from the plan alone is still substantial:

- **Irreversibility** — e.g. a managed-disk *grow* is one-way (Azure can't shrink), visible in the plan diff.
- **Widened exposure** — an inbound NSG rule opening `0.0.0.0/0` to a sensitive port; a storage account turning on public access or lowering TLS.
- **Data-loss risk** — deleting a data-bearing resource flags the primary copy as removed and recoverability as *unverified*, not *safe*.
- **Cost direction** and **action semantics**.
- **Drift** — see below. This is the one place an *offline* run reaches a real state determination rather than an `unknown`, because Terraform already did the live read for you.

## Drift, without asking you for credentials

`terraform plan` refreshes by default: before computing a diff it reads live reality for every managed resource, and records anything that moved in a top-level `resource_drift` array. That is a live-state observation already sitting inside the offline artifact. blastcheck did not perform the read — Terraform did — but the fact is no less true for it.

A resource appearing in **both** `resource_drift` and `resource_changes` is the most dangerous shape blastcheck can find, and it is graded `blocking`:

```
azurerm_managed_disk.sql_data   severity: blocking
  state_confidence: drift_detected  (recorded 512 -> live 1024)
```

The plan is internally consistent. It reads as routine. It was computed against a description of that resource which had already stopped being true, and every other verdict for it was derived from that same stale state.

Two limits, stated rather than papered over:

- An **empty** `resource_drift` is ambiguous. It means either "refresh found nothing" or "refresh did not run" (`-refresh=false`), and the plan does not record which. So absence never earns `state_matches_reality`; it stays `not_verified`.
- Refresh only sees resources Terraform manages. Anything created outside Terraform is not in state, so nothing refreshes it. Shadow-IT discovery needs a direct cloud query and is out of scope here.

Drift on a resource this plan does not touch is recorded under `extensions.drift_outside_this_plan` rather than invented into a change.

blastcheck is a **producer, not a gate**. By default it emits the manifest and exits `0` whatever the verdict. `--fail-on` (below) lets you state your own threshold — that is the operator declaring a policy, not the tool deciding one.

## Coverage: every provider, in three layers

Every change in a plan is assessed. Nothing is skipped for being an unfamiliar type.

| Layer | Applies to | Confidence |
|---|---|---|
| **0 — structural** | any provider ever written | high |
| **1 — heuristic** | any provider, by name and value patterns | low, tagged `heuristic` |
| **2 — precise** | types with an exact rule | high |

**Layer 0** reads what Terraform states regardless of provider: action semantics (a `delete` is a delete, a `replace` implies a destroy), `action_reason`, `replace_paths`, `resource_drift`, unreadable fields, and plan-level `errored` / `complete`.

**Layer 1** matches on resource-type names (`*_disk`, `*_bucket`, `*_database`) and attribute names and values (`publicly_accessible`, `storage_encrypted: false`, `acl: public-read`, an inbound `0.0.0.0/0`). On a real 55-change AWS plan, with zero AWS-specific code, this finds a publicly accessible unencrypted RDS instance, a public-read S3 bucket, and a security group open to the internet.

These findings are graded **`caution`, never `blocking`**, carry `confidence: low`, and their evidence is tagged `source: heuristic`. They are leads, not determinations, and saying so is the difference between a tool people read and a tool people mute. In the same spirit, an open **egress** rule and a default route are not flagged: they are `0.0.0.0/0` by definition, and firing on them would trip on nearly every plan ever written.

**Layer 2** is the precise set — 110 resource types across AWS and Azure today. Where a precise rule exists it wins, and a heuristic never overrides it.

Layer 2 is **data, not code**. A provider pack is a JSON file declaring which types are data-bearing, which are stateless, which attributes only grow in one direction, and which attribute values widen exposure. Adding a resource type is an edit to a data file plus a test, not a change to the analyzer — which is the only version of this a community can realistically contribute to. Run `blastcheck rules` to see exactly what your build knows; the number in this README is not the one to trust.

`extensions.assessment` records which layer produced each verdict.

## Install & use

```
pip install blastcheck                  # or: brew install prococonsulting/tap/blastcheck
                                        # or: download a single binary from Releases

blastcheck plan.json                    # readable summary
blastcheck tfplan                       # a saved plan, converted for you
terraform show -json tfplan | blastcheck
blastcheck plan.json > manifest.json    # the manifest, as JSON
blastcheck rules                        # what this build actually knows
```

**On a terminal you get a summary; redirected or piped you get the manifest.** No flag needed either way, and `--json` / `--text` force it.

```
blastcheck 0.7.0 — 20 change(s) assessed, plan-only

  BLOCKED  azurerm_network_security_group.web_tier
           security      inline rule 'allow-ssh-temp': inbound Allow from ['*'] to
                         port(s) ['22'] — opens sensitive access to the internet

  UNKNOWN  azurerm_managed_disk.sql_data
           reversibility `disk_size_gb` 512 -> 1024 cannot be reduced; permanent

  6 further change(s) are undetermined only because live state was not queried.
  3 change(s) had nothing to flag.

verdict: blocked
  4 change(s) report a catastrophic effect: ...

  · state was never verified against reality — re-run with --live to certify
```

The baseline unknowns every plan-only change shares are summarised once rather than repeated per change, and a low-confidence finding is labelled `(pattern match, not a determination)` so a guess never looks like a determination in a terminal.

## Configuration

Drop a `.blastcheck.json` anywhere above your working directory:

```json
{
  "fail_on": "blocked",
  "live": "azure",
  "ignore": ["module.sandbox.*", "aws_s3_bucket.scratch"]
}
```

Command-line flags always win over the file.

**An ignore does not delete a finding.** It lowers that change's severity to `informational` so it stops gating a pipeline, and everything else stays exactly as it was — the concerns, the rationale, the evidence. The manifest records which pattern suppressed it under `extensions.ignored`, with the severity it originally had. A config file that could make a finding *vanish* would be the most effective way yet invented to produce a false `safe`, and it would be invisible to whoever reads the manifest afterwards.

## Gating

```
blastcheck --plan plan.json --fail-on blocked
```

| exit | meaning |
|---|---|
| 0 | ran fine, and the verdict did not trip your threshold |
| 1 | **blastcheck could not run** — bad input, unreadable file |
| 2 | **the verdict tripped `--fail-on`** |

1 and 2 are deliberately distinct: a pipeline must be able to tell "this plan is dangerous" from "the tool is broken", because those call for opposite responses.

`--fail-on` defaults to `never`. blastcheck stays a producer — what a verdict should do to your pipeline is your policy, not its decision. The flag just means you no longer have to parse JSON in shell to express a decision you already made.

No hosted service, no network, no runtime dependencies — a default run works entirely against the plan file.

## Live checks: earning a `safe` verdict

```
blastcheck --plan plan.json --live > manifest.json
```

`--live` verifies recorded state against live cloud reality. **It is the only mode in which a `safe` verdict is reachable.**

**blastcheck never handles a credential.** It shells out to the provider's own CLI and uses the session you already have — `az login`, SSO, managed identity, whatever your environment provides. Nothing is read from a config file, nothing is accepted as a flag, nothing is stored. A tool that asks you to hand it cloud credentials so it can tell you whether a change is safe has an obvious problem.

It also never writes. Every command is built from a fixed template with a read-only verb, and a test asserts that no mutating verb can reach a subprocess call.

| | plan-only | with `--live` |
|---|---|---|
| `state_confidence` | `not_verified`, or `drift_detected` from Terraform's refresh | **`state_matches_reality`**, or drift blastcheck found itself |
| `availability_impact` | `unknown` for anything that already exists | `interrupts` when something is attached to it |
| `data_durability` | a delete is *unverified* loss | `unrecoverable_loss` when no recovery point exists — checked, not assumed |
| verdict | never `safe` | `safe` only when every change was verified and none is dangerous |

The recovery-point check is the one that changes how a delete reads. Plan-only, deleting a database says *this removes the primary copy and I could not verify a backup*. With `--live`, blastcheck asks whether a restore point actually exists: if one does the change becomes `reversible_with_data_loss`, and if none does it becomes `unrecoverable_loss` at high confidence — a determination rather than a caveat.

A failed probe — no CLI, not logged in, no permission, a timeout — does **not** degrade to a guess. The dimension stays `unknown`, the reason appears in the rationale, and `producer.access.live_state` records `unavailable` rather than `queried`. Asking and being refused is a different fact from never asking, and a reader interpreting an `unknown` needs to know which one happened.

Two things `--live` deliberately does not do. It does not average: **one unverified change denies `safe` to the whole plan**, because a plan is only as trustworthy as its least verified change. And existence alone is not a match — a resource that is present but shares no comparable attribute with recorded state stays `not_verified`.

Azure (`az`) and AWS (`aws cloudcontrol`) today, selected with `--live azure` / `--live aws`. Both probe generically rather than per resource type, so a new resource type needs no prober work. The prober is an interface; adding a provider is about a hundred lines.

## In CI

```yaml
- run: terraform show -json tfplan > plan.json

- uses: prococonsulting/blastcheck@v0
  with:
    plan: plan.json
```

The manifest is uploaded as a build artifact and the verdict is posted on the pull request. The action **does not fail the build** — blastcheck is a producer, not a gate, and what a `blocked` verdict should do to a pipeline is a policy question that belongs to you. To gate on it:

```yaml
- uses: prococonsulting/blastcheck@v0
  with:
    plan: plan.json
    fail-on: blocked
```

Note what you *cannot* write on a plan-only run: there is no `verdict == 'safe'` to gate on, because a plan-only run never emits one. A pipeline that proceeds only on a positive safety claim needs `--live`, and the credentials that implies. That is the honest ceiling of what a plan by itself can prove.

## Tests

The suite's primary job is to prove every emitted manifest **validates against the vendored schema** (`blastcheck/schema/impact-manifest.schema.json`) on realistic plan fixtures — that is how a schema shape error surfaces.

```
pip install -e ".[test]"
pytest
```

## Relationship to the spec

blastcheck implements the [Impact Manifest specification](https://github.com/prococonsulting/impact-manifest) and vendors a pinned copy of its schema at `blastcheck/schema/`, which ships inside the wheel. The format is open and vendor-neutral; blastcheck is *a* reference implementation of it, not its owner.

## Status

v0.7 — draft, and evolving alongside the spec (which does not freeze at 1.0 until this tool has run against real Terraform plans).

## Contributing and contact

The bar for a change, and how to add a rule: [CONTRIBUTING.md](./CONTRIBUTING.md).
Security reports: [SECURITY.md](./SECURITY.md).

If you are implementing the Impact Manifest format in another tool, open an
issue on [the specification repository](https://github.com/prococonsulting/impact-manifest) —
ambiguities in the spec are the most useful feedback it can get while it is
still v0.1 draft.

Anything else: kproffitt@prococonsulting.com

## License

Apache-2.0. See [LICENSE](./LICENSE).
