# Tech Debt LombokAuth

Format: ID, finding, priority, fix, status. Priority P0 blocks the tag 0.1.0; P1 blocks a minor release.

| ID | Finding | Priority | Fix | Status |
|---|---|---|---|---|
| TD-01 | `ci.yml` had not been run on GitHub Actions yet; actions are not pinned to SHAs | P0 | Run it in the repository, pin SHAs, enable Dependabot (see LombokSQL for the pattern) | OPEN |
| TD-02 | `lombok doctor docs/privacy/style` does not exist yet (ecosystem TD-P0-08); automatic checks are limited to `docs.test.ts` | P0 | Run it once `codinglombok/.github` exists | OPEN |
| TD-03 | Coverage not measured; target 90% | P1 | Add Rust and TS coverage jobs | OPEN |
| TD-04 | Fuzzing is not `cargo-fuzz`; no Rust fuzzing | P1 | A `cargo-fuzz` target for `call` | OPEN |
| TD-05 | Only Rust and TypeScript; Python, Go and PHP ports NOT YET | P1 | Planned for 0.2.0 | OPEN |
| TD-06 | Copies of `LICENSE-*` in `rust/` | P3 | Automate the copy at release time | OPEN |
| TD-07 | The 170 regression cases take their expectations from TypeScript (confirmed by the Rust port); only the 211 golden cases are independent | P3 | Manually review a sample of the regression cases | OPEN |
| TD-08 | The cryptography module has not been audited by a third party | P1 | Audit before 1.0 | OPEN |
| TD-09 | PBKDF2 with 600000 iterations in pure TypeScript: performance not measured | P2 | Benchmark; consider optional WebCrypto | OPEN |

Closed in 0.1.0: `no_std` is proven by a `thumbv7em-none-eabi` build, and clippy/rustfmt run with `-D warnings` (locally; CI runs the same).
