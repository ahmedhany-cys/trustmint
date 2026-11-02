# Contributing

```bash
python -m venv .venv && source .venv/bin/activate
make install
make lint test selfcheck
```

## Adding a platform

1. Add a model in `src/trustmint/platforms/` that subclasses `Platform`: the subject
   grammar, the fillers that produce structurally valid subjects, and the classification of
   each candidate into a `Reach`.
2. Recognize its issuer in `platforms/__init__.py`.
3. Add scenarios with known answers to `src/trustmint/scenarios/` and unit tests.
4. Document the token format and its source in `docs/how-it-works.md`.

## Rules for findings

- A reach finding needs a witness token that the trust's own evaluator accepts. The test
  suite checks this for every witness.
- If something cannot be modeled, return *undecided* (`Unknown`), never a guess.
- State assumptions in the finding.
