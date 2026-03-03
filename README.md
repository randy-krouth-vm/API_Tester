---

<div align="center">

### 🔐 API Security Tester

### Standards-Aligned • Route-Aware • Protocol-Level API Security Validation

![Status](https://img.shields.io/badge/status-beta-orange)
![Platform](https://img.shields.io/badge/.NET-MAUI-blue)
![Coverage](https://img.shields.io/badge/Coverage-Standards%20%2B%20Suites%20%2B%20Advanced-success)

</div>

---

> ⚠️ **Authorized Use Only**  
> Use this tool only on systems you own or are explicitly authorized to test.
> It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

<img width="1460" height="898" alt="image" src="https://github.com/user-attachments/assets/ae978bc8-9a2a-47bd-98b7-e7de38056736"/>

---

## 🧠 What This Is

**API Security Tester** is a .NET MAUI application built by Codex for structured, standards-aligned API security validation.

It combines:

- 📚 Compliance framework execution  
- 🕷 Route-aware dynamic probing  
- 🔎 Modern attack surface modeling  
- 🧬 CVE corpus correlation  
- 🧪 Advanced protocol abuse detection  

This is not just a scanner. It is a multi-domain API validation framework.

---

## 🏛 Standards Coverage

### 🔹 Application & API Standards
- OWASP API Security Top 10  
- OWASP ASVS  
- OWASP MASVS  
- OWASP Testing Guide  
- OWASP SAMM  

### 🌐 U.S. Federal
- NIST SP 800-53  
- NIST SP 800-61  
- NIST SP 800-63  
- NIST SP 800-207 (Zero Trust)  
- NIST SP 800-190  

### 🌍 International
- ISO 27001  
- ISO 27002  
- ISO 27017  
- ISO 27018  
- ISO 27701  

### 🏦 Industry & Regulatory
- PCI DSS  
- FFIEC  
- HIPAA  
- GDPR  
- CCPA  
- CMMC  
- COBIT  

### ☁ Cloud & Infrastructure
- Cloud Security Alliance (CSA)  
- CSA Cloud Controls Matrix  
- CIS Critical Security Controls  
- CIS Kubernetes Benchmark  
- MITRE ATT&CK  

---

## 🧩 Domain Security Suites

Grouped execution modes:

- 🔐 Authorization & Access Control  
- 💉 Injection & Input Validation  
- 🪪 Identity & Token Security  
- 🌐 API Infrastructure & Protocol  
- 🛡 HTTP & Server Hardening  
- ♻ Resilience & Information Disclosure  

---

## 🛠 Advanced Technical Probes (90+)

Modern attack surface validation including:

- JWT none-alg, kid injection, RS256↔HS256 confusion  
- OAuth / OIDC state & nonce replay  
- HTTP request desync (CL.TE / TE.CL / dual-length)  
- GraphQL depth & complexity abuse  
- gRPC reflection & metadata abuse  
- mTLS enforcement validation  
- DNS rebinding probe  
- JWKS poisoning  
- Cloud metadata (IMDSv2) exposure  
- File upload & mass assignment abuse  
- XXE & entity expansion  
- WebSocket injection & fragmentation  
- Side-channel timing signals  
- Docker API exposure  
- Subdomain takeover detection  
- CSP / Clickjacking posture  
- Mobile deep-link & storage checks  
- LLM prompt injection probe  

Designed to reflect modern API threat models.

---

## 🧬 CVE Integration

- Full NVD corpus sync  
- Local indexing  
- Function-to-CVE mapping  
- Paging & filtering  
- Priority-based view  

Supports defensive correlation workflows.

---

## 🚀 Execution Modes

### 🟢 Run Maximum Static + Dynamic Coverage
Coverage-focused execution:
- Static posture analysis  
- Spider discovery  
- Adaptive endpoint sweep  
- Consolidated reporting  

### 🔵 Run All Standards Categories
Framework-aligned compliance execution.

### 🔴 Run Everything (Standards + Suites + Advanced)
Broadest execution set:
- Standards  
- Domain suites  
- Advanced probes  
- Deduplicated execution  
- Route-level testing (if spider enabled)

---

## 🎯 Run Scope

| Mode | Description |
|------|------------|
| `Single Target Only` | Tests run only on the entered URL |
| `Spider Routes (All Discovered)` | Tests run against spider-discovered endpoints |

---

## ⚡ Quick Start

```powershell
dotnet build API_Tester.slnx -nologo
dotnet run --project API_Tester/API_Tester.csproj -f net10.0-windows10.0.19041.0
```

---

## 📂 Logs & Cache

- Cache root: `cache/`  
- Saved logs: `cache/logs/`  
- CVE corpus + function mapping supported  

---

## 🤖 CI Support

Enable additional guessed-route discovery during CI:

```powershell
API_TESTER_CI_EXTRAS=true
```

---

## ⚠ Limitations

- Heuristic testing may produce false positives/negatives  
- Dynamic coverage depends on route discoverability  
- Not a replacement for manual security review  

---

<div align="center">

Built with Codex  
.NET MAUI • API Security • Compliance Validation • Modern Attack Surface Modeling

</div>
