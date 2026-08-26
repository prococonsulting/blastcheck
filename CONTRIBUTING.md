# Contributing

## The bar for a change

blastcheck exists to be wrong loudly rather than wrong quietly. A false `safe`
is catastrophic; a false `unknown` is annoying. Those are not symmetrical, and
every contribution is judged against that asymmetry.

In practice that means:

**A rule may only return a benign value when it actually checked.** If a field a
rule depends on is missing, computed (`after_unknown`), or redacted
(`after_sensitive`), the rule must return `unknown` with a rationale naming the
field that defeated it. Falling through to `none` / `reversible` /
`no_data_loss` / `unchanged` because a lookup returned `None` is the specific
bug class this project cares most about. Two shipped examples of getting this
wrong are in the git history; both were caught by review rather than by tests,
which is why the rule is written down here.

**Every verdict carries a rationale a human can defend out loud.** Comment the
reasoning, not the syntax.

**Widening resource scope is worth less than correctness on existing scope.** A
tool that covers five resource types accurately is more useful than one that
covers fifty and is confidently wrong about three.

## Adding a rule

1. Write the fixture first, in `tests/fixtures/`, as realistic
   `terraform show -json` output. Include `after_unknown` and `after_sensitive`
   even when empty — real plans always have them.
2. Assert the dimension value, the severity, and the plan verdict.
3. Add the negative case. A rule that flags an open NSG rule must also have a
   test proving it does *not* flag a closed one, and does not re-flag something
   that was already open before this change.
4. Run `pytest`. Every emitted manifest must validate against
   `blastcheck/schema/impact-manifest.schema.json` — that check is the point of
   the suite, and a failure means the tool and the specification have drifted
   apart.

## Implementing the format in your own tool

You do not need this codebase to produce an Impact Manifest, and the format is
better off if more than one tool does. The specification and schema are at
[prococonsulting/impact-manifest](https://github.com/prococonsulting/impact-manifest),
Apache-2.0, with no coupling to this implementation. If you are building a
producer or a consumer, open an issue there — cases where the spec is ambiguous
are the most valuable feedback it can get, and the format is still v0.1 draft
precisely so that they can be fixed.

## Development

```
pip install -e ".[test]"
pytest
```

No runtime dependencies, and it should stay that way. `jsonschema` and `pytest`
are test-only.
