# blastcheck

**blastcheck** reads a `terraform show -json` plan and emits an **[Impact Manifest](https://github.com/prococonsulting/impact-manifest)** — a machine-readable change-safety assertion. It is the reference producer of that open format.

```
terraform plan -out plan.tfplan
terraform show -json plan.tfplan | blastcheck > manifest.json
```

`terraform plan` tells you *what* will change. blastcheck adds the layer the plan can't: for each change, is it reversible, does anything become unrecoverable, does exposure widen, and — honestly — what could it *not* determine.

## What it does, and what it deliberately doesn't

blastcheck is **offline**: no credentials, no network, no hosted service. It reasons from the plan artifact alone. Wherever a verdict genuinely requires live cloud state — "is this disk attached to something serving traffic?", "does a backup exist?" — it emits `unknown` / `not_verified` **with a stated reason**, rather than guessing.

A direct consequence, and the point of the format: **a plan-only run can never emit `safe`.** It never verified live state, so it says `caution`, `blocked`, or `unknown` — never `safe`. Certifying `safe` requires the live-state enrichment that a later version (or a paid consumer) layers on. blastcheck is honest about the ceiling of what a plan alone can prove.

What it derives from the plan alone is still substantial:

- **Irreversibility** — e.g. a managed-disk *grow* is one-way (Azure can't shrink), visible in the plan diff.
- **Widened exposure** — an inbound NSG rule opening `0.0.0.0/0` to a sensitive port; a storage account turning on public access or lowering TLS.
- **Data-loss risk** — deleting a data-bearing resource flags the primary copy as removed and recoverability as *unverified*, not *safe*.
- **Cost direction** and **action semantics**.
- **Drift** — see below. This is the one place blastcheck reaches a real state determination rather than an `unknown`.

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

blastcheck is a **producer, not a gate**. It emits the manifest and exits `0`; turning that into pass/fail is a separate policy layer (a CI gate). Exit codes reflect execution, not the verdict.

## Scope (v0.1, intentionally narrow)

Azure: managed disks, virtual machines, network security groups (+ rules), storage accounts, SQL databases. Anything else in the plan is recorded under `extensions.skipped` — never silently dropped. The narrow surface is a choice: the job of this version is to exercise the Impact Manifest schema against real plans and find its shape errors, not to be a finished product.

## Install & use

```
pip install blastcheck
terraform show -json plan.tfplan | blastcheck            # stdin
blastcheck --plan plan.json > manifest.json              # from a file
blastcheck --compact                                     # single-line JSON
```

No hosted service, no cloud credentials, no network, no runtime dependencies — it runs entirely against the plan file.

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
  id: bc
  with:
    plan: plan.json

- if: steps.bc.outputs.verdict == 'blocked'
  run: exit 1
```

Note what you *cannot* write: there is no `verdict == 'safe'` gate to pass on a plan-only run, because a plan-only run never emits `safe`. A pipeline that proceeds only on a positive safety claim needs the live-state enrichment. That is the honest ceiling of what a plan by itself can prove.

## Tests

The suite's primary job is to prove every emitted manifest **validates against the vendored schema** (`blastcheck/schema/impact-manifest.schema.json`) on realistic plan fixtures — that is how a schema shape error surfaces.

```
pip install -e ".[test]"
pytest
```

## Relationship to the spec

blastcheck implements the [Impact Manifest specification](https://github.com/prococonsulting/impact-manifest) and vendors a pinned copy of its schema at `blastcheck/schema/`, which ships inside the wheel. The format is open and vendor-neutral; blastcheck is *a* reference implementation of it, not its owner.

## Status

v0.2 — draft, narrow, and evolving alongside the spec (which does not freeze at 1.0 until this tool has run against real Terraform plans).

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
