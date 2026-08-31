# Design note: provider_id on the change object

Status: PROPOSAL, not implemented. Covers a spec change in the
impact-manifest repo and a producer change in this repo. Downstream
(blastcheck-mcp) is noted but deliberately untouched.

## Problem

A manifest identifies a change only by Terraform address. No cloud API
speaks Terraform addresses, so any downstream system joining a manifest
to live state (cost, dependencies, tenancy) must guess by resource type
and name. On a multi-tenant estate that guess can be confidently wrong,
which is the one failure mode this format exists to prevent.

## Spec change (impact-manifest repo)

Add ONE optional field to `$defs.change`:

```
"provider_id": {
  "type": "string",
  "minLength": 1,
  "description": "The provider's own canonical identifier for the
    resource this change operates on, as recorded by the change tool -
    e.g. an Azure resource ID, an AWS ARN or resource id, a GCP
    resource name. Cloud-neutral: the format imposes no syntax, and
    the value is NOT guaranteed to be globally unique on its own (a
    bare AWS instance id can exist in two accounts). Interpret it
    together with `provider`, which a producer SHOULD emit alongside
    it. Absent on a pure create (no identifier exists yet); absent on
    an update/delete/replace means the producer could not resolve it -
    see the absence rule in the specification text."
}
```

Why an inline field and not a sibling map (e.g. an
extensions.resource_ids address-to-id table): a separate structure can
disagree with the changes it describes - stale keys, missing keys,
typos in addresses - and forces every consumer to implement a join.
A field on the change object cannot disagree with its own change.
(blastcheck-mcp's remote-tier design sketched the map variant; this
supersedes it, noted in Downstream below.)

### Interpretability: pair with the EXISTING `provider` field

`before.id` verbatim is right as the extraction rule, but the value
alone is not always interpretable: on AWS it is often a bare instance
id, which is not globally unique - two accounts can each hold
`i-0abc123`. That is the exact collision this field exists to
eliminate, so a consumer must know what KIND of identifier it holds.

No new field is needed: `$defs.change` ALREADY has an optional
`provider` string ("Provider address the resource belongs to"), and
blastcheck already populates it from the plan's `provider_name`
(e.g. `registry.terraform.io/hashicorp/azurerm`). The revision makes
the pairing normative rather than incidental:

- Spec: a producer emitting `provider_id` SHOULD also emit `provider`;
  a consumer MUST NOT treat `provider_id` as a join key across
  providers or accounts without consulting `provider`. The `provider`
  description gains this cross-reference.
- blastcheck: BOTH-OR-NEITHER. Under the flag, `provider_id` is
  emitted only when `provider` is also known (provider_name is present
  on effectively every managed resource in real plan JSON; if it is
  somehow absent, the id is withheld and the evidence entry says
  "provider unknown; identifier would be uninterpretable"). Still
  Layer 0: both values verbatim from the plan, no heuristics.

The prefer-`before.arn` heuristic remains rejected.

### Schema enforces what the prose promises: open the extensible objects

`additionalProperties: false` on every core object contradicts the
spec's own must-ignore rule: a consumer that vendors schemas (the
normal, network-free case) mechanically rejects any newer-minor
document. The prose fix alone does not help a validator. So the schema
becomes the mechanism:

- `additionalProperties: true` on every object the spec intends to be
  additively extensible: the ROOT object, `change`, all six dimension
  objects (and the nested `concerns` item and `estimate` objects),
  `producer` (and `access`), `source`, `evidence`, `precondition`,
  `planVerdict` (and `policy`). A 0.1.0 validator then accepts a 0.2.0
  document carrying `provider_id`, and every future minor addition,
  by construction.
- STAYS CLOSED (`additionalProperties: false`): `integrity` and its
  children (`digest`, `signature`, `envelope`). Two reasons. First,
  it is the tamper-evidence surface: the signature covers the document
  WITH `integrity` REMOVED, so an unknown field anywhere else is still
  covered by the signature, but an unknown field INSIDE `integrity`
  would alter verification semantics while itself being unsigned -
  exactly where smuggled data would live. A verifier must fail loudly
  on fields it does not understand there, not ignore them. Second, its
  evolution is deliberately deferred to the v1.0 attestation layering
  (DSSE/in-toto/Sigstore); it should not grow fields casually.
- `extensions` is already open; no change.

The Compatibility prose sentence stays as well (belt and braces):

> Schema validation against an older minor version is not a
> conformance test of the document: a consumer whose schema is older
> than the document's `schema_version` minor MUST NOT reject the
> document for unknown fields alone.

Producer self-validation strictness stays, relocated to where it
belongs: a producer emits only fields it knows, so it self-validates
against a STRICT variant of its own vendored schema. Concretely,
blastcheck's test suite derives the strict variant mechanically
(walk the vendored schema, set `additionalProperties: false` on every
object except `extensions`) and validates every emitted manifest
against it - typo-shaped producer bugs still surface, while the
published schema stays permissive for consumers.

One adjacent wrinkle, noted but out of scope: ENUM values (e.g.
`source.type`) remain closed by nature - a future enum addition will
still be rejected by older validators, and the spec already says new
sources arrive "in a future schema_version". provider_id adds no enum
values, so nothing here turns on it.

### Version bump: 0.1.0 -> 0.2.0 (minor), and why

- Not a patch: the document surface changes; patch is for editorial
  and bugfix-level corrections.
- Not a major: the spec's own compatibility rule says a consumer
  "within a major version it implements ... MUST accept the fields it
  knows and MUST ignore fields it does not." An optional additive
  field breaks no conformant consumer, and no existing field changes
  meaning. Major stays 0, so the consumer refusal rule does not
  trigger.
- Minor is also consistent with the spec's draft status ("expect
  breaking changes" pre-1.0): this is not even a breaking change.

Mechanical edits: schema `$id` becomes `.../v0.2.0/...`, the spec
README status line moves to v0.2.0, and worked example
`02-irreversible-delete.json` gains a `provider_id` so the field has a
demonstrated use.

## Absence semantics: no new field needed

The disambiguating fact is whether the resource already exists, and
`actions` - carried verbatim from the plan precisely so the manifest
cannot disagree with it - already encodes that. Proposed normative rule
for the spec text:

- `actions` is exactly `["create"]`: the resource does not exist yet,
  so no identifier CAN exist. Absence is inherent and carries no
  signal.
- `actions` operates on an existing resource (any `update`, `delete`,
  or `replace`, including the delete+create pair): absence means THE
  PRODUCER COULD NOT RESOLVE the identifier - a different fact - and
  the producer SHOULD record why in the evidence pool (e.g. source
  `terraform_plan`, observation "before.id absent from recorded
  state").
- `no-op` / `read`: no mutation; absence carries no signal.

A reader (human or machine) distinguishes the two cases from data the
manifest already carries; adding a status field would create a second
source of truth that could only agree with `actions` or contradict it.

## blastcheck changes

### Flag surface

`--include-provider-ids`, default OFF. CLI flag only - deliberately NOT
a `.blastcheck.json` key. The config file is discovered by walking
upward from the working directory, so a config key could enable
inclusion invisibly for everyone below that directory; an invisible
privacy downgrade is exactly the failure the default protects against.
(If CI needs it, the GitHub action can grow an explicit input later;
out of scope here.)

### Population

In `analyze_change` (core.py, where `before` is already in scope and
the change dict is built):

- Flag off: nothing changes. Not one byte of output differs.
- Flag on, actions exactly ["create"]: no field (inherent absence).
- Flag on, existing resource, `before.id` is a non-empty string AND
  the provider is known (both-or-neither, see the pairing rule above):
  emit `provider_id` with that value VERBATIM. No normalization, no
  per-provider parsing - Layer 0 philosophy, works for every provider
  ever written, deterministic. `provider` is already emitted from
  `provider_name`; nothing new there.
- Flag on, existing resource, `before.id` missing / not a string /
  marked sensitive in `before_sensitive` / provider unknown: no field,
  plus an evidence entry recording why resolution failed (per the
  absence rule).

Terraform's `id` is not always what a cloud's own APIs canonicalize on
(Azure: full ARM ID; `aws_instance`: `i-0abc...`, with the ARN in a
separate attribute). That is handled by the pairing rule, not by
extraction heuristics: the value stays verbatim and `provider` says
what kind of identifier it is. Prefer-`before.arn` remains rejected -
a per-attribute preference varies by provider and resource type, and a
wrong-but-plausible join key is worse than a plain one.

### Versions

- `SCHEMA_VERSION` "0.1.0" -> "0.2.0"; the vendored schema copy in
  `blastcheck/schema/` is refreshed from the spec repo in the same
  commit (single source of truth for tests and downstream).
- `PRODUCER_VERSION` 0.7.0 -> 0.8.0: new emitting capability, minor
  bump.

### Privacy (the point of the flag)

README gets a plain statement, roughly:

> `--include-provider-ids` embeds each cloud's own resource
> identifiers in the manifest. These identifiers carry account and
> grouping information: an Azure resource ID contains the subscription
> GUID and resource group name; an AWS ARN contains the account id; a
> GCP resource name contains the project id. Without the flag a
> manifest is safe to paste into a PR comment or CI log; with it, it
> is not. Do not post an ID-bearing manifest to public PR comments,
> public CI logs, issue trackers, or any channel wider than the people
> allowed to know your account layout. Default off.

### Tests

- Privacy regression (the flag's contract): a default run over the
  fixture plans produces a serialized manifest containing no
  `provider_id` key and none of the `before.id` values present in the
  fixtures. This test is the "no provider_id without the flag"
  assertion and should be treated like the schema-validation tests:
  never weakened to make a change pass.
- Flag on: delete/update/replace changes carry exactly the fixture's
  `before.id`; create changes carry no field.
- Flag on, existing resource with `before.id` absent: no field, and an
  evidence entry states why.
- Pairing: no change in any fixture ever carries `provider_id` without
  `provider` (both-or-neither).
- Every emitted manifest (both modes) validates against the NEW
  vendored 0.2.0 schema AND against the strict variant derived from it
  (the producer self-validation mechanism above); `schema_version` is
  `0.2.0` in both modes.

## Downstream (noted, not touched now)

blastcheck-mcp is affected in three ways, all deferred to that repo's
own stop-for-review process:

1. Its projection allowlist (`project.py`) would gain
   `change.provider_id` - that boundary is stop-ship-tested
   (test_project.py pins the exact recursive key set), so the change
   is loud by design and goes through review there before any edit.
2. Its reserved `extensions.resource_ids` lookup is superseded by the
   inline field and comes out.
3. Its dependency pin `blastcheck>=0.7,<0.8` excludes blastcheck
   0.8.0 on purpose; bumping the pin is the deliberate, CI-tested act
   its plan prescribes. Its validator accepts schema major 0, so
   0.2.0 documents pass unchanged.

docs/remote-tier.md in that repo gets updated to reflect all three
when this lands. Not being done now.

## Order of work (after approval)

1. impact-manifest: schema + compatibility sentence + absence rule +
   example + version bump.
2. blastcheck: vendored schema refresh, SCHEMA_VERSION, flag plumbing,
   population in analyze_change, README privacy section, tests,
   PRODUCER_VERSION 0.8.0.
3. (Separate task, separate review) blastcheck-mcp pin bump +
   allowlist + remote-tier.md.
