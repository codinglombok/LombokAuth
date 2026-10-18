# How To Dist LombokAuth v0.1.0

## 1. First upload (bootstrap)

The repository `codinglombok/LombokAuth` already exists. From a local folder containing this project:

```powershell
git init -b main
git add -A
git status            # check: docs/*architecture*, docs/*masterplan*, node_modules, target must NOT appear; no *.bak files
git commit -m "feat: LombokAuth v0.1.0"
git remote add origin https://github.com/codinglombok/LombokAuth.git
git push -u origin main
gh repo edit codinglombok/LombokAuth --add-topic lombok-ecosystem --add-topic level-l0 --add-topic auth --add-topic jwt --add-topic totp --add-topic rust --add-topic typescript --description "Authentication core: JWT HS256, PBKDF2 password hashes in PHC format, HOTP and TOTP, and role-based access control with wildcards. Part of the Lombok Ecosystem."
```

Do not create a release tag at this stage; see the conditions in `TECH_DEBT.md`.

## 2. Regular release flow

Target (ADR-011): release-please opens a release PR; merging the PR creates the tag `vX.Y.Z`; publishing reads the version from the tag. The reusable workflow `codinglombok/.github` does not exist yet (TD-P0-08), so `ci.yml` in this repository is self-contained for now.

## 3. Publishing per registry

| Registry | Package | Pre-publish check |
|---|---|---|
| npm | `lombokauth` | `cd typescript && npm pack --dry-run` (passes locally); publish with `--provenance` |
| crates.io | `lombokauth` | `cd rust && cargo publish --dry-run` (passes locally) |
| PyPI, Packagist, Go, Maven, NuGet | no port yet | - |

Order: tag, green CI, `npm publish --provenance --access public`, `cargo publish`.

## 4-7. Server, Docker, shared hosting, local

A library is not deployed. Local use: `npm install ./typescript` or `cargo add --path rust`.

## 8. Verification

`lombok doctor docs` is not available yet. Equivalent manual checks (also run automatically by `typescript/test/docs.test.ts`):

```powershell
(Get-FileHash vectors\lombokauth-vectors-v1.json -Algorithm SHA256).Hash   # must equal the hash in SPEC_
git ls-files | Select-String 'architecture|masterplan'   # must be empty (ADR-024)
git ls-files | Select-String '\.bak$'                    # must be empty
```
