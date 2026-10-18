# Security Policy

## Supported versions

| Version | Support |
|---|---|
| 0.1.x | Security fixes |

## Reporting a vulnerability

Use **GitHub Private Vulnerability Reporting** on this repository (Security tab, "Report a vulnerability"). Do not open a public issue for a vulnerability.

- Initial response: within 48 hours.
- Fix for critical findings: 7 days (target).
- Disclosure is coordinated with the reporter.

## Scope

In scope: every exported function, in particular the acceptance of an invalid JWT (algorithm `none`, a wrong signature, expired claims), timing leaks in verification, RBAC mistakes that grant excessive permissions, and panics or unbounded execution time.

Out of scope: user, session and randomness storage supplied by the application; JWT algorithms other than HS256.

## Short threat model

See section 6 of `docs/SPEC_LombokAuth_v0.1.0.md`.
