# Map LombokAuth v0.1.0

## 1. Dependency position

L0. The cluster position and catalog number follow the ecosystem parent document v3.6 (not committed, ADR-024). No required Lombok dependencies.

## 2. Example dependents in the ecosystem

This section is the only place where application or framework names may appear (ADR-019). It is an illustration, not ownership; anyone can use LombokAuth.

| Dependent | Kind | Integration status | Notes |
|---|---|---|---|
| LombokClarion v3 | Framework | planned (F7) | Replaces TokenIssuer and complements Gate in the internal v2 auth package |
| LombokServer | L4 library | planned | JWT authentication middleware |
| LombokDocFlow | Application | planned | Login, 2FA and user roles |

Optional integration with LombokSecurity (password policy), LombokSQL (storage) and LombokCache (revoked-token list) is not implemented.

## 3. Depends on

Nothing.

## 4. Normative contract path

`docs/SPEC_LombokAuth_v0.1.0.md` -> `vectors/lombokauth-vectors-v1.json` (sha256 in SPEC) -> runners `rust/tests/vectors.rs` and `typescript/test/vectors.test.ts`.

## 5. Folder map

See `structure_repo_LombokAuth_v0.1.0.md`.
