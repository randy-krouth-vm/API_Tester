---

<div align="center">

### API Security Tester

### Standards-Aligned • Route-Aware • Protocol-Level API Security Validation

![Status](https://img.shields.io/badge/status-beta-orange)
![Platform](https://img.shields.io/badge/.NET-MAUI-blue)
![Coverage](https://img.shields.io/badge/Coverage-Standards%20%2B%20Suites%20%2B%20Advanced-success)

</div>

---

### ⚠️ Authorized Use Only

Use this tool only on systems you own or have explicit permission to test. You are responsible for complying with all applicable local, state, and federal laws. The developers assume no liability and are not responsible for misuse or damage.

---

<img width="1288" height="916" alt="image" src="https://github.com/user-attachments/assets/477b96dc-4f74-46f6-b05c-1dbac14c0262" />


---

## 📖 What This Is

**API Security Tester** is a .NET MAUI application built by Codex for structured, standards-aligned API security validation.

It combines:
- 📚 Compliance framework execution
- 📦 Route-aware dynamic probing
- 🔎 Modern attack-surface checks
- 🧬 CVE corpus correlation
- ▶ Protocol abuse detection

This is not just a scanner. It is a multi-domain API validation framework.

---

## 🏛 Standards Coverage

### 🔹 Application & API Standards
- OWASP API Security Top 10
- OWASP ASVS
- OWASP MASVS
- OWASP Testing Guide (WSTG)
- OWASP SAMM

### 🌐 U.S. Federal
- NIST SP 800-53
- NIST SP 800-61
- NIST SP 800-63
- NIST SP 800-115
- NIST SP 800-171
- NIST SP 800-190
- NIST SP 800-207 (Zero Trust)
- FedRAMP
- DISA STIG / SRG

### 🌍 International
- ISO 27001 / 27002
- ISO 27017
- ISO 27018

### 🏦 Industry & Regulatory
- PCI DSS
- FFIEC
- HIPAA
- GDPR
- CCPA
- CMMC 2.0
- SOC 2
- COBIT
- CREST

### ☁ Cloud & Infrastructure
- Cloud Security Alliance (CSA)
- CIS Controls
- MITRE ATT&CK mappings

---

## 🧩 Domain Security Suites

Grouped execution suites include:
- 🔐 Authorization & Access Control
- 🪪 Injection & Input Validation
- 🧬 Identity & Token Security
- 🌐 API Infrastructure & Protocol
- 🛡 HTTP & Server Hardening
- ♻ Resilience & Information Disclosure

---

## 🛠 Advanced Technical Probes

Examples include:
- JWT checks (`alg=none`, `kid`, `jku`, `x5u`, confusion variants)
- OAuth/OIDC redirect and token abuse checks
- HTTP desync/smuggling signal checks
- GraphQL / gRPC / WebSocket checks
- SSRF and cloud metadata exposure checks
- Path traversal, upload validation, and parser abuse checks
- Race-condition and workflow abuse signal checks
- Mobile deep-link and client-side storage signal checks

Safety note: placeholder external domains use `example.invalid`.

---

## 🧬 CVE Integration

- Full local corpus support (NVD-backed)
- Local index + function mapping
- CVE paging / lookup views
- Priority filtering

---

## 🚀 Execution Modes

### 🟢 Maximum Static + Dynamic Coverage
- Static posture checks
- Route discovery/spidering
- Adaptive endpoint probing
- Consolidated report output

### 🔵 Standards Category Runs
- Framework-aligned control-driven execution

### 🔴 Everything
- Standards + suites + advanced probes

---

## 🎯 Run Scope

| Mode | Description |
|---|---|
| `Single Target Only` | Test only the exact entered URL |
| `Spider Routes (All Discovered)` | Test same-origin discovered routes |
| `OpenAPI Routes (From Spec)` | Test routes parsed from OpenAPI spec |

---

## 🌐 OpenAPI Input

GUI supports:
- OpenAPI URL/path input
- File picker for loading OpenAPI JSON

Headless supports:
- `--scope openapi`
- `--openapi <path-or-url>`

---

## ⚡ Quick Start (GUI)

```powershell
dotnet build API_Tester.slnx -nologo
dotnet run --project API_Tester/API_Tester.csproj -f net10.0-windows10.0.19041.0
```

## ⚡ Quick Start (Headless)

```powershell
dotnet run --project API_Tester.Headless -- --target http://127.0.0.1:5006 --scope single
dotnet run --project API_Tester.Headless -- --target http://127.0.0.1:5006 --scope openapi --openapi ./openapi.json
```

---

## 📂 Logs & Cache

- Cache root: `cache/`
- Saved logs: `cache/logs/`
- CVE corpus + function map artifacts supported

---

## 🤖 CI Support

Enable extra guessed-route discovery in CI:

```powershell
API_TESTER_CI_EXTRAS=true
```

---

## ⚠ Limitations

- Heuristic testing can produce false positives/negatives
- Dynamic coverage depends on route discoverability/spec quality
- Not a replacement for manual security review or full compliance audit evidence

---

<div align="center">
Built with Codex </br>
.NET MAUI • API Security • Compliance Validation • Modern Attack Surface Modeling
</div>
