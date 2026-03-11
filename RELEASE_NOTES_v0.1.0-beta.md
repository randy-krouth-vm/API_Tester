# API Security Tester v0.1.0-beta

## Release Type
Beta

## Overview
`v0.1.0-beta` is the first broad public beta of API Security Tester, focused on standards-driven API security checks, dynamic route coverage, and CVE correlation workflows.

## Highlights
- Added extensive standards and framework-aligned checks (OWASP, NIST, ISO, PCI, and related mappings).
- Added advanced defensive probe coverage across injection, auth, JWT/OAuth/OIDC, protocol, smuggling, business logic, and resilience scenarios.
- Added spider route discovery and route-level execution support.
- Added run scope control:
  - `Single Target Only`
  - `Spider Routes (All Discovered)`
- Added separate top-level run paths:
  - `Run All Standards Categories`
  - `Run Everything (Standards + Suites + Advanced)`
  - `Run Maximum Static + Dynamic Coverage`
- Added CVE corpus workflows:
  - sync corpus from NVD
  - build CVE -> function map
  - summary, lookup, paging/filtering
- Added log export (`Save Log`) to `cache/logs`.
- Improved runtime resilience:
  - concise per-test error reporting
  - reduced crash propagation from individual probe failures

## UX / Output Improvements
- Results log expanded to avoid clipping of long outputs.
- Route discovery output now includes full endpoint listing (no sample cap) and unique route-path counts.
- Added clearer status behavior around failures and route scope.

## Security / Safety Notes
- Intended for authorized defensive testing only.
- Some checks are heuristic and may produce false positives/false negatives.
- Route discovery depth/coverage depends on server behavior and chosen run scope.

## Known Limitations (Beta)
- Full “everything + spider routes” runs can be long on large APIs.
- Discovery may include non-business URLs depending on what the target exposes.
- Framework mapping and CVE correlation are heuristic, not exploit proof.

## Suggested Tag
`v0.1.0-beta`

## Suggested Release Title
`API Security Tester v0.1.0-beta`

## Suggested Follow-up for v0.1.1
- Add fast/balanced/exhaustive run profile selector.
- Add optional per-suite/per-probe concurrency controls.
- Add route include/exclude patterns for finer crawl scope.
- Add CI workflow template and artifact publishing.

---
Built by Codex.
