# Contributing

1. **Contract first.** A behavior change starts in `docs/SPEC_LombokAuth_v0.1.0.md` and `scripts/gen-vectors.mjs`, not in the code.
2. **Tests first.** Add golden cases whose expectation is written by hand, copied from an RFC (4226, 6238, 4648), or built with `node:crypto` in the vector generator.
3. **Every port must pass.** Run:

```bash
cd typescript && npm ci && npm test        # build + TypeScript tests
node ../scripts/gen-vectors.mjs            # after changing vectors; record the new sha256 in SPEC
cd ../rust && cargo test && cargo build --no-default-features
node ../scripts/mutation-test.mjs          # every mutant must be killed
```

4. A vector change changes the hash in `SPEC_`; update `SPEC_`, `vectors/README.md`, `CHANGELOG.md` and `API_` in the same pull request.
5. Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`) and describe the change functionally.
6. Do not include real data, client names or real organization domains in examples, tests or commit messages; use synthetic data and `example.com`.
7. Documents are written in formal English without emoji. English is the default language of every Lombok repository.
