# Security policy

## Reporting a vulnerability

Do not report security vulnerabilities through public issues, pull requests or discussions.

While this repository is private, report privately to the maintainers through the repository host's access channels
(collaborators only). When the repository becomes public, GitHub private vulnerability reporting ("Report a
vulnerability" under the Security tab) will be enabled and becomes the reporting channel. Include the affected commit or version, a description of the issue, reproduction steps or a
proof of concept, and the impact you expect. If you believe a third-party component is affected (hyper, h2, tokio,
rustls, AWS-LC, Cedar, the Rust toolchain), report it to that project as well; see `SECURITY_CLAIMS.md` for the
components AEGIS trusts.

| step | target |
|---|---|
| acknowledgement of a report | 3 business days |
| initial assessment | 10 business days |
| coordinated disclosure | 90 days from report, or earlier when a fix is released |

## Supported versions

AEGIS is pre-release. Only the `main` branch receives fixes. There are no released versions yet; this section will
list supported release lines once releases begin.

## Scope

In scope: code in this repository, its frozen interfaces (`interfaces/`), its specifications (`spec/`) and its
verification oracles (`oracles/`), including incorrect assurance claims (a claim in `SECURITY_CLAIMS.md` that the
evidence does not support is treated as a vulnerability).

Out of scope: third-party extensions, adapters or applications that are not part of the golden reference build, and
deployments that modify or fork the code (see the responsibility boundary in `SECURITY_BY_DESIGN.md`).
