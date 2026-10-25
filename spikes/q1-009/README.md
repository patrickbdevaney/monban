# q1-009: AI-found vs human-found exploitation, and time-to-exploit for middle-tier servers

**Verdict: keep the R-THR-2 scope** (the AI reverse condition does not fire). **Tighten one row** on speed
evidence that does not depend on AI: a critical, pre-auth-reachable Tier-S dependency fix should reach a signed
golden rebuild in ≤48 h, not ≤7 d. Grade B. Date 2026-10-25. Machine-readable verdict: `verdict.json`.

## Question and flip condition
ARCHITECTURE §2.3: "q1-009 shows AI-found bugs are exploited above the base rate (then the ≤24 h SLA becomes a
rule for all TCB code)". §3.14 SLO table: ≤24 h for our attacker-reachable code, ≤7 d for Tier-S dependency
rebuilds, and ≤6 h advisory → TUF release as the best-case drill target.

## Method
1. **Literature and vendor data (primary first).** VulnCheck 1H 2026 and the 2026 Exploit Intelligence Report
   (PDFs read in full); Mandiant M-Trends 2026; GTIG 2025 zero-day review and the GTIG AI Threat Tracker
   (2026-05-11); the Anthropic threat report (Sept 2026); DARPA AIxCC results; Google Big Sleep; CVE-Genie
   (arXiv 2509.01835); press on Glasswing attribution.
2. **Own measurement.** We took the CISA KEV catalog (version 2026.10.23) and kept entries added from
   2025-01-01 whose products are middle-tier: proxies, ADCs and gateways (including AI gateways), web/app
   servers, and app frameworks. For each, the CVE `datePublished` and finder credits come from
   CVEProject/cvelistV5. Lag = KEV dateAdded − CVE datePublished. Script: `raw/kevmid.py`. Output:
   `raw/kev_middle_tier_2025_2026.json` (41 rows).

## Results

### Share found or weaponized by AI
| measure | value | grade |
|---|---|---|
| AI-attributed CVEs confirmed exploited | 14 / 1,061 = **1.3%** (95% CI 0.8–2.2%) | B |
| all-CVE exploitation base rate | KEV/CVE 1.4% (1H 2026); ~1% of 2025 CVEs exploited by year end | B |
| Glasswing | >23,000 findings → 126 CVEs → **1 exploited** (Ghost SQLi CVE-2026-26980); later 225 linked CVEs, still 1 exploited | B |
| AI-found share of exploited, all KEV (floor) | 14 / 495 1H-2026 KEVs ≈ **2.8%** (1.7–4.7%) | B (windows misaligned) |
| AI-found share of exploited, middle tier (floor) | 1 / 35 (Tomcat CVE-2026-34486, finder at striga.ai, an AI code-audit firm) = **2.9%** (0.5–14.5%) | B floor / D ceiling |
| AI-weaponized share | **not measurable.** Documented cases: Erlang/OTP SSH PoC written with GPT-4 from the patch diff in about 1 day; GTIG's first in-the-wild exploit assessed as AI-developed (2FA logic bypass, stopped before mass use); APT45 LLM-driven CVE→PoC pipeline; Anthropic GTG-10007 firmware hunting (>12 possible zero-days/month, self-reported) | C |
| lab ceiling | CVE-Genie reproduces 51% of 841 recent CVEs at $2.77 each; Auto Exploit made 14 OSS exploits in 10–15 min; AIxCC: 54/70 synthetic bugs found, 43 patched, 18 real zero-days found | B |
| counter-signal | public AI PoCs are often non-functional ("ensloppification"). The first React2Shell PoC never touched the vulnerable path (VulnCheck) | B |

**Reading.** AI discovery raises the *volume* of findings and the noise in PoCs. It does not raise the *per-CVE
exploitation rate* (1.3% vs 1.4%). The flip condition, "exploited above the base rate", is not met.

### Speed (disclosure → exploitation)
| measure | value | grade |
|---|---|---|
| KEVs exploited on/before CVE publication day | 28.96% (2025, n=884); 23.43% (1H 2026, n=495) | A/B |
| median CVE → KEV | 120 d (2025) → 80 d (1H 2026) | B |
| mean time-to-exploit (Mandiant, 2025 incidents) | **−7 days** | B |
| exploited zero-days 2025 (GTIG) | 90; 43 (48%) enterprise; 21 security/networking; 14 edge | A |

**Own measurement: middle-tier KEV, CVEs published in 2025 or later (n = 35)**

| bucket | count | share (95% CI) |
|---|---|---|
| day 0 (KEV the same day as the CVE) | 12 | 34% (21–51%) |
| ≤2 d | 15 | 43% (28–59%) |
| ≤7 d | 18 | 51% (36–67%) |
| ≤30 d | 23 | 66% (49–79%) |
| median | 7 d | |

- Appliance/commercial (n=25): median 1 d, 11 at day 0. These are mostly state or criminal zero-days in
  Citrix NetScaler, FortiWeb/FortiOS, Ivanti Connect Secure, Check Point and F5. None has a public finder
  credit.
- OSS (n=10): median 42.5 d by KEV date, but KEV is a lagging upper bound. First exploitation was reported
  within hours of disclosure for React2Shell CVE-2025-55182 (AWS MadPot; KEV +2 d), about 30 h for Tomcat
  CVE-2025-24813 (Wallarm; KEV +22 d), and 36 h after GHSA indexing for LiteLLM CVE-2026-42208 (Sysdig). The
  Erlang/OTP SSH CVE-2025-32433 PoC (AI-assisted) was public within about 1 day; KEV came at +54 d.
- AI gateways are now a KEV category: 3 LiteLLM entries in 2026, one of them the fail-open CVE-2026-59822
  (see P-3).

## Effect on R-THR-2 (§3.14 table)
| row | before | after | why |
|---|---|---|---|
| own attacker-reachable code | ≤24 h | **keep ≤24 h** | n-day exploitation lands in hours to about 2 days; buyers must patch internet-facing critical bugs within 48 h (ASD ISM-1877) |
| Tier-S dependency, critical or pre-auth reachable via AEGIS, or KEV-listed | ≤7 d | **≤48 h** | a 7-day rebuild lands after the 7-day middle-tier median; OSS first exploitation at 30–48 h |
| Tier-S dependency, other | ≤7 d | keep ≤7 d | — |
| any TCB, best case drill | ≤6 h (E) | **keep as drill target** | still unmeasured; the release-drill spike sets the real number |
| kill-switch per feature | B | keep | about 34% of middle-tier exploitation is at or before disclosure, where no rebuild SLA helps |
| all TCB ≤24 h (AI reverse) | not adopted | **not adopted** | AI-found exploitation rate = base rate |

## Reproduction
```
curl -sL -o kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
python3 -I spikes/q1-009/raw/kevmid.py kev.json out.json
```
Catalog 2026.10.23 output: `all KEV-added 2025+ n 41 median 22 …; CVE published 2025+ n 35 median 7 day0 12
<=2d 15 <=7d 18 <=30d 23; OSS n 10 median 42.5; appliance n 25 median 1`. The KEV feed is downloaded on
demand and not stored here (1.8 MB). A later catalog adds rows.

## Honest limits
- AI attribution comes from public credits only. Attacker-side AI use is invisible, so the AI share of
  exploited bugs has only a floor.
- KEV date is an upper bound on first exploitation. CVE publication can trail the GHSA or vendor advisory
  (LiteLLM shows lag 0 but was exploited earlier).
- The middle-tier filter is a manual vendor/product list.
- OSS first-exploitation times are vendor anecdotes, not a systematic dataset.
- Glasswing and Anthropic figures are partly self-reported.
- The picture may change fast as frontier cyber models spread. Re-run when each VulnCheck half-year report
  comes out.

## Sources (all accessed 2026-10-25)
| source | grade | URL |
|---|---|---|
| VulnCheck State of Exploitation 1H 2026 (2026-07-28) | B | https://www.vulncheck.com/blog/state-of-exploitation-1h-2026 · https://wwv.vulncheck.com/hubfs/Research/State-of-Exploitation-1H-2026.pdf |
| VulnCheck 2026 Exploit Intelligence Report (2025 data) | B | https://wwv.vulncheck.com/hubfs/Research/2026-VulnCheck-Exploit-Intelligence-Report.pdf |
| CISA KEV catalog 2026.10.23 | A | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| CVE List v5 (dates, credits) | A | https://github.com/CVEProject/cvelistV5 |
| Mandiant M-Trends 2026 (2026-03-23) | B | https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026 |
| GTIG 2025 zero-day review (2026-03-05) | A | https://cloud.google.com/blog/topics/threat-intelligence/2025-zero-day-review/ |
| GTIG AI Threat Tracker (2026-05-11) | B | https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access |
| Anthropic threat intelligence report (Sept 2026) | C (self-reported) | https://www.anthropic.com/threat-intelligence-report-september-2026 |
| The Register / CSO on Glasswing CVE attribution | B | https://www.theregister.com/2026/04/15/project_glasswing_cves/ · https://www.csoonline.com/article/4159617/behind-the-mythos-hype-glasswing-has-just-one-confirmed-cve.html |
| Ghost CVE-2026-26980 exploitation | B | https://aviatrix.ai/threat-research-center/ghost-cms-cve-2026-26980-exploited-to-hijack-700-sites-for-clickfix-attacks |
| DARPA AIxCC results (2025-08) | A | https://www.darpa.mil/news/2025/aixcc-results |
| Google Big Sleep / SQLite CVE-2025-6965 | B | https://thehackernews.com/2025/07/google-ai-big-sleep-stops-exploitation.html |
| CVE-Genie (arXiv 2509.01835; CCS 2026) | B | https://arxiv.org/abs/2509.01835v1 |
| Auto Exploit (15-minute PoCs) | C | https://www.darkreading.com/vulnerabilities-threats/proof-concept-15-minutes-ai-turbocharges-exploitation |
| AWS: China-nexus exploitation of React2Shell within hours | B | https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182 |
| Tomcat CVE-2025-24813 exploited ~30 h after disclosure | B | https://thehackernews.com/2025/03/apache-tomcat-vulnerability-comes-under.html |
| LiteLLM CVE-2026-42208 exploited 36 h after disclosure | B | https://thehackernews.com/2026/04/litellm-cve-2026-42208-sql-injection.html |
| Erlang/OTP CVE-2025-32433 AI-written PoC | B | https://www.helpnetsecurity.com/2025/04/22/working-poc-exploit-for-critical-erlang-otp-ssh-bug-is-public-cve-2025-32433/ |
| striga.ai (AI code auditing; Tomcat CVE-2026-34486 finder) | B | https://striga.ai · https://cveawg.mitre.org/api/cve/CVE-2026-34486 |
| ASD ISM-1876/1877 48 h patch windows | A | https://github.com/AustralianCyberSecurityCentre/ism-oscal/releases/tag/v2026.09.4 |
