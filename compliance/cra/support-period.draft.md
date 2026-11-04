Status: DRAFT, not published

# Support period statement (draft)

CRA Art 13(8) requires a support period that reflects the time the product is expected to be in use, at least five
years unless the expected use is shorter, stated at the time of placing on the market.

Support period: `<operator to supply>` (proposed: 5 years from the first release of each major version).

| item | draft content |
|---|---|
| start | release date of version `<operator to supply>` |
| end | `<operator to supply>` (date, month and year) |
| what support covers | security updates for the golden reference build (floor and cmvp), CSAF/VEX advisories, SBOM per release |
| how updates are delivered | signed releases with TUF metadata (monotonic versions, anti-rollback); security updates separate from feature updates where technically feasible |
| cmvp build | supported only while a CMVP-validated AWS-LC module matching the cmvp lock is available; a certificate move to AWS-LC 4/5 is a new cmvp lock |
| after the end | the last release stays available for at least 10 years after placing on the market, or for the support period if longer (Art 13(9)) |

Not committed: no date in this file is a commitment until the operator publishes the set (PREFLIGHT §P4 item 1).
