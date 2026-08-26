# blastcheck

**blastcheck** reads a `terraform show -json` plan and emits an **Impact Manifest** (the sibling `impact-manifest` spec repo) — a machine-readable change-safety assertion. It is the reference producer of that open format.

```
terraform plan -out plan.tfplan
terraform show -json plan.tfplan | blastcheck > manifest.json
```

`terraform plan` tells you *what* will change. blastcheck adds the layer the plan can't: for each change, is it reversible, does anything become unrecoverable, does exposure widen, and — honestly — what could it *not* determine.

## What it does, and what it deliberately doesn't

blastcheck v0.1 is **offline and plan-only**. It reasons from the plan artifact alone. Wherever a verdict genuinely requires live cloud state — "is this disk attached to something serving traffic?", "does a backup exist?" — it emits `unknown` / `not_verified` **with a stated reason**, rather than guessing.

A direct consequence, and the point of the format: **a plan-only run can never emit `safe`.** It never verified live state, so it says `caution`, `blocked`, or `unknown` — never `safe`. Certifying `safe` requires the live-state enrichment that a later version (or a paid consumer) layers on. blastcheck is honest about the ceiling of what a plan alone can prove.

What it derives from the plan alone is still substantial:

- **Irreversibility** — e.g. a managed-disk *grow* is one-way (Azure can't shrink), visible in the plan diff.
- **Widened exposure** — an inbound NSG rule opening `0.0.0.0/0` to a sensitive port; a storage account turning on public access or lowering TLS.
- **Data-loss risk** — deleting a data-bearing resource flags the primary copy as removed and recoverability as *unverified*, not *safe*.
- **Cost direction**, **action semantics**, and a `not_verified` state-confidence stamp on every change.

blastcheck is a **producer, not a gate**. It emits the manifest and exits `0`; turning that into pass/fail is a separate policy layer (a CI gate). Exit codes reflect execution, not the verdict.

## Scope (v0.1, intentionally narrow)

Azure: managed disks, virtual machines, network security groups (+ rules), storage accounts, SQL databases. Anything else in the plan is recorded under `extensions.skipped` — never silently dropped. The narrow surface is a choice: the job of this version is to exercise the Impact Manifest schema against real plans and find its shape errors, not to be a finished product.

## Install & use

```
pip install .
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

The suite's primary job is to prove every emitted manifest **validates against the vendored schema** (`schema/impact-manifest.schema.json`) on realistic plan fixtures — that is how a schema shape error surfaces.

```
pip install -e ".[test]"
pytest
```

## Relationship to the spec

blastcheck implements the Impact Manifest specification (the sibling `impact-manifest` repo) and vendors a pinned copy of its schema under `schema/`. The format is open and vendor-neutral; blastcheck is *a* reference implementation of it, not its owner.

## Status

v0.1 — draft, narrow, and evolving alongside the spec (which does not freeze at 1.0 until this tool has run against real Terraform plans).

## License

Apache-2.0. See [LICENSE](./LICENSE).
