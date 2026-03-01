# API Security Tester (Beta)

> Status: **Beta**

API Security Tester is a .NET MAUI app built by Codex for authorized API security validation across standards, suites, and route-aware dynamic probes.

## Authorized Use Only
Use this tool only on systems you own or are explicitly authorized to test.

<img width="1460" height="898" alt="image" src="https://github.com/user-attachments/assets/9050dd4c-f917-4913-82f0-5d45c3548978" />

## Features
- Standards-aligned test packs (OWASP, NIST, ISO, PCI DSS, etc.)
- Domain security suites (authz, injection, identity, protocol, hardening, resilience)
- Dynamic spider-based route discovery and per-route probing
- CVE corpus sync, mapping, paging, and lookup
- Log export to repo cache

## Run Scope
- `Single Target Only`: tests run only on the URL you enter.
- `Spider Routes (All Discovered)`: tests run against spider-discovered routes.

## Run Buttons: What Is Different
- `Run Maximum Static + Dynamic Coverage`
  - Coverage-oriented workflow.
  - Combines static analysis (catalog/OpenAPI posture), spider discovery, dynamic probes, and adaptive endpoint sweep.
  - Best when you want a consolidated coverage report.

- `Run All Standards Categories`
  - Runs standards category packs (OWASP/NIST/ISO/PCI/etc.).
  - Focuses on framework/compliance-aligned execution.
  - With spider scope enabled, also includes route discovery/hit/sweep sections.

- `Run Everything (Standards + Suites + Advanced)`
  - Broadest execution set.
  - Runs standards packs + domain suites + remaining advanced probes (deduped) and route-level sections when spider scope is enabled.
  - Use this for the widest practical test pass.

## Are These The Same On Single Target?
No. Even in `Single Target Only` scope, `Run Everything` remains broader than `Run Maximum Static + Dynamic Coverage` because it includes standards + suites + advanced grouped execution.

## Quick Start
```powershell
dotnet build API_Tester.slnx -nologo
dotnet run --project API_Tester/API_Tester.csproj -f net10.0-windows10.0.19041.0
```

## Logs and Cache
- Cache root: `cache/`
- Saved logs: `cache/logs/`

## CI Extras (Optional)
Set `API_TESTER_CI_EXTRAS=true` to enable additional guessed-route candidates during crawling in CI pipelines.

## Limitations
- Heuristic testing can produce false positives/negatives.
- Dynamic route coverage depends on discoverability and chosen run scope.

---
Built by Codex.
