# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**
(<https://github.com/patrickbdevaney/aegis/security/advisories/new>). Do not open a public issue for a security
problem.

Please include:

- the build (floor or cmvp), the commit or release, and the release's `SHA256SUMS` line if you used one;
- the profile and configuration;
- steps to reproduce, and the impact you saw.

Do not include personal data of third parties.

## What to expect

Monban is maintained by one person, so these are targets, not guarantees:

| step | target |
|---|---|
| acknowledgement | within 7 days |
| triage (in scope or not, severity) | within 14 days |
| fix or mitigation | depends on severity; actively exploited issues come first |
| public advisory | a GitHub security advisory (and a CVE where warranted), coordinated with you |
| credit | in the advisory, if you want it |

The default embargo is 90 days from the report, or the release date of the fix if that is earlier. If a
vulnerability is being exploited, we may publish sooner, after telling you.

## Scope

In scope:

- `monban-bin` (floor and cmvp builds) and its released artifacts;
- any claim in [SECURITY_CLAIMS.md](SECURITY_CLAIMS.md) "What is claimed", at the rung that claim states. A
  counterexample to a model theorem, a checker disagreement, or a bypass of a fail-closed path is in scope;
- the release pipeline: signatures, TUF metadata, provenance and SBOM.

Out of scope, or to be reported upstream:

- components Monban trusts but does not verify (listed in SECURITY_CLAIMS.md): hyper, h2, tokio, rustls, the AWS-LC
  C code, the Rust compiler, SQLite, the kernel and libc. Report those to their projects; we will track the advisory
  and say whether Monban builds are affected;
- third-party adapters, modules and handlers, and forked or modified binaries;
- volumetric denial of service. Monban does rate limiting and resource budgeting; it is not a network filter.

## Supported versions

There is no release yet. Until the first release, only the latest commit on `main` receives security fixes. A
support period will be stated with the first release.

## Safe harbour

We will not pursue legal action against good-faith research that follows this policy: test only against systems
you own or are allowed to test, avoid harming other people's data or service, and give us a chance to fix the
problem before you disclose it.
