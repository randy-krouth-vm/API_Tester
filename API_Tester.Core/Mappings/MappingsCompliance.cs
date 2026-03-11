namespace ApiTester.Core;

public static partial class Mappings
{
    public static List<string> GetComplianceMappings(string frameworkName, string testKey)
    {
        return frameworkName switch
        {
            "OWASP API Security Top 10" => GetOwaspApiTop10Compliance(testKey),
            "NIST SP 800-53" => GetNist80053Compliance(testKey),
            "NIST SP 800-61" => GetNist80061Compliance(testKey),
            "NIST SP 800-63" => GetNist80063Compliance(testKey),
            "NIST SP 800-207" => GetNist800207Compliance(testKey),
            "NIST Zero Trust (SP 800-207)" => GetNistZeroTrustCompliance(testKey),
            "NIST SP 800-190" => GetNist800190Compliance(testKey),
            "NIST SP 800-171" => GetNist800171Compliance(testKey),
            "FedRAMP" => GetFedRampCompliance(testKey),
            "DISA STIG/SRG" => GetStigCompliance(testKey),
            "ISO 27001" => GetIso27001Compliance(testKey),
            "ISO 27002" => GetIso27002Compliance(testKey),
            "ISO 27017" => GetIso27017Compliance(testKey),
            "ISO 27018" => GetIso27018Compliance(testKey),
            "ISO 27701" => GetIso27701Compliance(testKey),
            "PCI DSS" => GetPciDssCompliance(testKey),
            "FFIEC guidance" => GetFfiecCompliance(testKey),
            "HIPAA Security Rule" => GetHipaaCompliance(testKey),
            "GDPR" => GetGdprCompliance(testKey),
            "CCPA" => GetCcpaCompliance(testKey),
            "CMMC" => GetCmmcCompliance(testKey),
            "SOC 2" => GetSoc2Compliance(testKey),
            "OWASP ASVS" => GetOwaspAsvsCompliance(testKey),
            "OWASP MASVS" => GetOwaspMasvsCompliance(testKey),
            "OWASP Testing Guide" => GetOwaspWstgCompliance(testKey),
            "NIST SP 800-115" => GetNist800115Compliance(testKey),
            "Cloud Security Alliance API Security guidance" => GetCsaApiCompliance(testKey),
            "Cloud Security Alliance CCM" => GetCsaCcmCompliance(testKey),
            "CIS Critical Security Controls" => GetCisControlsCompliance(testKey),
            "Center for Internet Security Kubernetes Benchmark" => GetCisKubernetesCompliance(testKey),
            "Cloud Security Alliance Zero Trust Guidance" => GetCsaZeroTrustCompliance(testKey),
            "Gartner CARTA model" => GetCartaCompliance(testKey),
            "MITRE ATT&CK Framework" => GetMitreCompliance(testKey),
            "ISACA COBIT" => GetCobitCompliance(testKey),
            "OWASP SAMM" => GetSammCompliance(testKey),
            "BSI Secure Development models" => GetBsiCompliance(testKey),
            "Microsoft SDL" => GetMicrosoftSdlCompliance(testKey),
            "Advanced API Checks" => GetAdvancedApiChecksCompliance(testKey),
            _ => new List<string>()
        };
    }

    private static List<string> GetOwaspApiTop10Compliance(string testKey) => testKey switch
    {
        "API1" => ["OWASP API1:2023 Broken Object Level Authorization", "CWE-639"],
        "API2" => ["OWASP API2:2023 Broken Authentication", "CWE-287"],
        "API3" => ["OWASP API3:2023 Broken Object Property Level Authorization", "CWE-285"],
        "API4" => ["OWASP API4:2023 Unrestricted Resource Consumption", "CWE-770"],
        "API5" => ["OWASP API5:2023 Broken Function Level Authorization", "CWE-285"],
        "API6" => ["OWASP API6:2023 Unrestricted Access to Sensitive Business Flows", "CWE-841"],
        "API7" => ["OWASP API7:2023 SSRF", "CWE-918"],
        "API8" => ["OWASP API8:2023 Security Misconfiguration", "CWE-16"],
        "API9" => ["OWASP API9:2023 Improper Inventory Management", "CWE-200"],
        "API10" => ["OWASP API10:2023 Unsafe Consumption of APIs", "CWE-20"],
        _ => []
    };

    private static List<string> GetNist80053Compliance(string testKey) => testKey switch
    {
        "N53AC2" => ["NIST SP 800-53 Rev5: AC-2 Account Management"],
        "N53AC3" => ["NIST SP 800-53 Rev5: AC-3 Access Enforcement"],
        "N53AC6" => ["NIST SP 800-53 Rev5: AC-6 Least Privilege"],
        "N53IA2" => ["NIST SP 800-53 Rev5: IA-2 Identification and Authentication"],
        "N53IA5" => ["NIST SP 800-53 Rev5: IA-5 Authenticator Management"],
        "N53AU2" => ["NIST SP 800-53 Rev5: AU-2 Event Logging"],
        "N53AU9" => ["NIST SP 800-53 Rev5: AU-9 Protection of Audit Information"],
        "N53AU12" => ["NIST SP 800-53 Rev5: AU-12 Audit Record Generation"],
        "N53CM6" => ["NIST SP 800-53 Rev5: CM-6 Configuration Settings"],
        "N53CM7" => ["NIST SP 800-53 Rev5: CM-7 Least Functionality"],
        "N53SA11" => ["NIST SP 800-53 Rev5: SA-11 Developer Testing and Evaluation"],
        "N53IR6" => ["NIST SP 800-53 Rev5: IR-6 Incident Reporting"],
        "N53RA5" => ["NIST SP 800-53 Rev5: RA-5 Vulnerability Monitoring and Scanning"],
        "N53SC5" => ["NIST SP 800-53 Rev5: SC-5 Denial of Service Protection"],
        "N53SC7" => ["NIST SP 800-53 Rev5: SC-7 Boundary Protection"],
        "N53SC8" => ["NIST SP 800-53 Rev5: SC-8 Transmission Confidentiality and Integrity"],
        "N53SC23" => ["NIST SP 800-53 Rev5: SC-23 Session Authenticity"],
        "N53SC28" => ["NIST SP 800-53 Rev5: SC-28 Protection of Information at Rest"],
        "N53SI10" => ["NIST SP 800-53 Rev5: SI-10 Information Input Validation"],
        "N53SI11" => ["NIST SP 800-53 Rev5: SI-11 Error Handling"],
        _ => []
    };

    private static List<string> GetNist80061Compliance(string testKey) => testKey switch
    {
        "N61DETECT" => ["NIST SP 800-61r2: Detection and Analysis"],
        "N61CONTAIN" => ["NIST SP 800-61r2: Containment, Eradication, and Recovery"],
        "N61ERADICATE" => ["NIST SP 800-61r2: Containment, Eradication, and Recovery"],
        "N61RECOVER" => ["NIST SP 800-61r2: Post-Incident Activity/Recovery"],
        _ => []
    };

    private static List<string> GetNist80063Compliance(string testKey) => testKey switch
    {
        "N63AAL" => ["NIST SP 800-63B: Authenticator Assurance Level requirements"],
        "N63REPLAY" => ["NIST SP 800-63B: Replay Resistance"],
        "N63SESSION" => ["NIST SP 800-63B: Session Management Requirements"],
        _ => []
    };

    private static List<string> GetNist800207Compliance(string testKey) => testKey switch
    {
        "N207VERIFY" => ["NIST SP 800-207: Continuous Diagnostics and Verification"],
        "N207LEAST" => ["NIST SP 800-207: Least-Privilege Access"],
        "N207POLICY" => ["NIST SP 800-207: Policy Decision/Enforcement Point Controls"],
        _ => ["NIST SP 800-207: Zero Trust Architecture"]
    };

    private static List<string> GetNistZeroTrustCompliance(string testKey) => testKey switch
    {
        "ZT207PDP" => ["NIST SP 800-207: Policy Decision Point responsibilities"],
        "ZT207PEP" => ["NIST SP 800-207: Policy Enforcement Point responsibilities"],
        "ZT207CDM" => ["NIST SP 800-207: Continuous diagnostics and risk evaluation"],
        _ => ["NIST SP 800-207: Zero Trust Architecture"]
    };

    private static List<string> GetNist800190Compliance(string testKey) => testKey switch
    {
        "N190NETWORK" => ["NIST SP 800-190: Container Network Traffic Controls"],
        "N190RUNTIME" => ["NIST SP 800-190: Runtime Protection and Monitoring"],
        "N190SECRETS" => ["NIST SP 800-190: Secrets and Sensitive Data Protection"],
        _ => ["NIST SP 800-190: Application Container Security Guide"]
    };

    private static List<string> GetNist800171Compliance(string testKey) => testKey switch
    {
        "N171AC" => ["NIST SP 800-171 Rev2: 3.1 Access Control"],
        "N171AT" => ["NIST SP 800-171 Rev2: 3.2 Awareness and Training"],
        "N171AU" => ["NIST SP 800-171 Rev2: 3.3 Audit and Accountability"],
        "N171CM" => ["NIST SP 800-171 Rev2: 3.4 Configuration Management"],
        "N171IA" => ["NIST SP 800-171 Rev2: 3.5 Identification and Authentication"],
        "N171IR" => ["NIST SP 800-171 Rev2: 3.6 Incident Response"],
        "N171MA" => ["NIST SP 800-171 Rev2: 3.7 Maintenance"],
        "N171MP" => ["NIST SP 800-171 Rev2: 3.8 Media Protection"],
        "N171PS" => ["NIST SP 800-171 Rev2: 3.9 Personnel Security"],
        "N171PE" => ["NIST SP 800-171 Rev2: 3.10 Physical Protection"],
        "N171RA" => ["NIST SP 800-171 Rev2: 3.11 Risk Assessment"],
        "N171CA" => ["NIST SP 800-171 Rev2: 3.12 Security Assessment"],
        "N171SC" => ["NIST SP 800-171 Rev2: 3.13 System and Communications Protection"],
        "N171SI" => ["NIST SP 800-171 Rev2: 3.14 System and Information Integrity"],
        _ => ["NIST SP 800-171 CUI protection mappings"]
    };

    private static List<string> GetFedRampCompliance(string testKey) => testKey switch
    {
        "FEDRAMPAC" => ["FedRAMP Baseline: AC Access Control family"],
        "FEDRAMPAU" => ["FedRAMP Baseline: AU Audit and Accountability family"],
        "FEDRAMPCM" => ["FedRAMP Baseline: CM Configuration Management family"],
        "FEDRAMPIR" => ["FedRAMP Baseline: IR Incident Response family"],
        "FEDRAMPRA" => ["FedRAMP Baseline: RA Risk Assessment family"],
        "FEDRAMPSC" => ["FedRAMP Baseline: SC System and Communications Protection family"],
        "FEDRAMPSI" => ["FedRAMP Baseline: SI System and Information Integrity family"],
        "FEDRAMPCA" => ["FedRAMP Baseline: CA Security Assessment and Authorization family"],
        _ => ["FedRAMP Low/Moderate/High baseline mappings"]
    };

    private static List<string> GetStigCompliance(string testKey) => testKey switch
    {
        "STIGAUTH" => ["DISA STIG/SRG authentication and account management controls"],
        "STIGNET" => ["DISA STIG/SRG network boundary and communications controls"],
        "STIGAUD" => ["DISA STIG/SRG audit generation and retention controls"],
        "STIGCONF" => ["DISA STIG/SRG secure configuration baseline controls"],
        "STIGASD" => ["DISA Application Security and Development STIG controls"],
        "STIGWSRG" => ["DISA Web Server SRG hardening controls"],
        _ => ["DISA STIG/SRG hardening mappings"]
    };

    private static List<string> GetIso27001Compliance(string testKey) => testKey switch
    {
        "ISO27001A5" => ["ISO/IEC 27001:2022 Annex A.5 Organizational controls"],
        "ISO27001A8" => ["ISO/IEC 27001:2022 Annex A.8 Technological controls"],
        _ => ["ISO/IEC 27001:2022 Annex A controls"]
    };

    private static List<string> GetIso27002Compliance(string testKey) => testKey switch
    {
        "ISO27002820" => ["ISO/IEC 27002:2022 8.20 Network security"],
        "ISO27002816" => ["ISO/IEC 27002:2022 8.16 Monitoring activities"],
        "ISO27002822" => ["ISO/IEC 27002:2022 8.22 Segregation of networks"],
        "ISO27002824" => ["ISO/IEC 27002:2022 8.24 Use of cryptography"],
        "ISO27002825" => ["ISO/IEC 27002:2022 8.25 Secure development lifecycle"],
        "ISO27002826" => ["ISO/IEC 27002:2022 8.26 Application security requirements"],
        _ => ["ISO/IEC 27002:2022 guidance"]
    };

    private static List<string> GetIso27017Compliance(string testKey) => testKey switch
    {
        "ISO27017SHARED" => ["ISO/IEC 27017 control set: shared roles and responsibilities"],
        "ISO27017NETWORK" => ["ISO/IEC 27017 cloud network/virtual environment controls"],
        _ => ["ISO/IEC 27017 cloud controls"]
    };

    private static List<string> GetIso27018Compliance(string testKey) => testKey switch
    {
        "ISO27018PII" => ["ISO/IEC 27018 PII protection controls"],
        "ISO27018PROCESS" => ["ISO/IEC 27018 PII processing transparency controls"],
        _ => ["ISO/IEC 27018 cloud PII protection"]
    };

    private static List<string> GetIso27701Compliance(string testKey) => testKey switch
    {
        "ISO27701CTRL" => ["ISO/IEC 27701 controller-related controls"],
        "ISO27701PROC" => ["ISO/IEC 27701 processor-related controls"],
        _ => ["ISO/IEC 27701 PIMS extension controls"]
    };

    private static List<string> GetPciDssCompliance(string testKey) => testKey switch
    {
        "PCIDSS4" => ["PCI DSS v4.0 Req 4: Protect account data with strong cryptography during transmission"],
        "PCIDSS6" => ["PCI DSS v4.0 Req 6: Develop and maintain secure systems and software"],
        "PCIDSS8" => ["PCI DSS v4.0 Req 8: Identify users and authenticate access"],
        "PCIDSS10" => ["PCI DSS v4.0 Req 10: Log and monitor all access"],
        "PCIDSS11" => ["PCI DSS v4.0 Req 11: Test security of systems and networks regularly"],
        _ => ["PCI DSS v4.0 control family mapping"]
    };

    private static List<string> GetFfiecCompliance(string testKey) => testKey switch
    {
        "FFIECAUTH" => ["FFIEC CAT Domain: Cyber Risk Management and Oversight (authentication controls)"],
        "FFIECDDOS" => ["FFIEC Architecture, Infrastructure and Operations Resilience controls"],
        "FFIECLOG" => ["FFIEC Detect and Respond / monitoring controls"],
        _ => ["FFIEC cybersecurity guidance mapping"]
    };

    private static List<string> GetHipaaCompliance(string testKey) => testKey switch
    {
        "HIPAA312A" => ["45 CFR 164.312(a): Access Control"],
        "HIPAA312C" => ["45 CFR 164.312(c): Integrity"],
        "HIPAA312E" => ["45 CFR 164.312(e): Transmission Security"],
        _ => ["HIPAA 45 CFR 164.312 technical safeguards"]
    };

    private static List<string> GetGdprCompliance(string testKey) => testKey switch
    {
        "GDPRART5" => ["GDPR Article 5: Data minimization, integrity and confidentiality"],
        "GDPRART25" => ["GDPR Article 25: Data protection by design and by default"],
        "GDPRART32" => ["GDPR Article 32: Security of processing"],
        _ => ["GDPR security and privacy principles mapping"]
    };

    private static List<string> GetCcpaCompliance(string testKey) => testKey switch
    {
        "CCPA150" => ["CCPA 1798.150: Reasonable security procedures and practices"],
        "CCPAPRIV" => ["CCPA notice/disclosure and PI protection expectations"],
        _ => ["CCPA security expectations mapping"]
    };

    private static List<string> GetCmmcCompliance(string testKey) => testKey switch
    {
        "CMMCAC" => ["CMMC 2.0 Access Control (AC) practices"],
        "CMMCAT" => ["CMMC 2.0 Awareness and Training (AT) practices"],
        "CMMCAU" => ["CMMC 2.0 Audit and Accountability (AU) practices"],
        "CMMCCM" => ["CMMC 2.0 Configuration Management (CM) practices"],
        "CMMCIA" => ["CMMC 2.0 Identification and Authentication (IA) practices"],
        "CMMCIR" => ["CMMC 2.0 Incident Response (IR) practices"],
        "CMMCMA" => ["CMMC 2.0 Maintenance (MA) practices"],
        "CMMCMP" => ["CMMC 2.0 Media Protection (MP) practices"],
        "CMMCPE" => ["CMMC 2.0 Physical Protection (PE) practices"],
        "CMMCPS" => ["CMMC 2.0 Personnel Security (PS) practices"],
        "CMMCRA" => ["CMMC 2.0 Risk Assessment (RA) practices"],
        "CMMCCA" => ["CMMC 2.0 Security Assessment (CA) practices"],
        "CMMCSC" => ["CMMC 2.0 System and Communications Protection (SC) practices"],
        "CMMCSI" => ["CMMC 2.0 System and Information Integrity (SI) practices"],
        _ => ["CMMC control-domain mapping"]
    };

    private static List<string> GetSoc2Compliance(string testKey) => testKey switch
    {
        "SOC2CC6" => ["SOC 2 Trust Services Criteria: CC6 Logical and Physical Access Controls"],
        "SOC2CC7" => ["SOC 2 Trust Services Criteria: CC7 System Operations"],
        "SOC2CC8" => ["SOC 2 Trust Services Criteria: CC8 Change Management"],
        _ => ["SOC 2 trust services criteria mapping"]
    };

    private static List<string> GetOwaspAsvsCompliance(string testKey) => testKey switch
    {
        "ASVSV2" => ["OWASP ASVS v4: V2 Authentication Verification Requirements"],
        "ASVSV3" => ["OWASP ASVS v4: V3 Session Management Verification Requirements"],
        "ASVSV4" => ["OWASP ASVS v4: V4 Access Control Verification Requirements"],
        "CSRFPROTECT" => ["OWASP ASVS v4: V4 Access Control Verification (CSRF defenses for state-changing requests)"],
        "ASVSV5" => ["OWASP ASVS v4: V5 Validation, Sanitization and Encoding"],
        "ASVSV6" => ["OWASP ASVS v4: V6 Stored Cryptography Verification Requirements"],
        "ASVSV7" => ["OWASP ASVS v4: V7 Error Handling and Logging Verification Requirements"],
        "ASVSV8" => ["OWASP ASVS v4: V8 Data Protection Verification Requirements"],
        "ASVSV9" => ["OWASP ASVS v4: V9 Communication Verification Requirements"],
        "ASVSV13" => ["OWASP ASVS v4: V13 API and Web Service Verification Requirements"],
        "ASVSV14" => ["OWASP ASVS v4: V14 Config and HTTP Security Headers"],
        _ => ["OWASP ASVS v4 controls mapping"]
    };

    private static List<string> GetOwaspMasvsCompliance(string testKey) => testKey switch
    {
        "MASVSAUTH" => ["OWASP MASVS v2: Authentication and Session controls"],
        "MASVSNETWORK" => ["OWASP MASVS v2: Network Communication controls"],
        "MASVSSTORAGE" => ["OWASP MASVS v2: Storage and Privacy controls"],
        _ => ["OWASP MASVS v2 controls mapping"]
    };

    private static List<string> GetOwaspWstgCompliance(string testKey) => testKey switch
    {
        "WSTGATHN" => ["OWASP WSTG: Authentication Testing"],
        "WSTGINPV" => ["OWASP WSTG: Input Validation Testing"],
        "WSTGCONF" => ["OWASP WSTG: Configuration and Deployment Management Testing"],
        "WSTGBUSL" => ["OWASP WSTG: Business Logic Testing"],
        _ => ["OWASP WSTG test case alignment"]
    };

    private static List<string> GetNist800115Compliance(string testKey) => testKey switch
    {
        "N115PLAN" => ["NIST SP 800-115: Planning and Discovery phase"],
        "N115EXEC" => ["NIST SP 800-115: Execution and technical testing phase"],
        "N115REPORT" => ["NIST SP 800-115: Analysis and reporting phase"],
        _ => ["NIST SP 800-115 technical guide alignment"]
    };

    private static List<string> GetCsaApiCompliance(string testKey) => testKey switch
    {
        "CSAAPIIAM" => ["CSA API Security: Identity and Access controls"],
        "CSAAPIINJ" => ["CSA API Security: Input validation and injection controls"],
        "CSAAPITRANS" => ["CSA API Security: Transport and configuration controls"],
        _ => ["CSA API Security guidance mapping"]
    };

    private static List<string> GetCsaCcmCompliance(string testKey) => testKey switch
    {
        "CCMIAM" => ["CSA CCM: IAM domain controls"],
        "CCMIVS" => ["CSA CCM: IVS interface and endpoint security controls"],
        _ => ["CSA CCM control objective mapping"]
    };

    private static List<string> GetCisControlsCompliance(string testKey) => testKey switch
    {
        "CIS3" => ["CIS Controls v8: Control 3 Data Protection"],
        "CIS16" => ["CIS Controls v8: Control 16 Application Software Security"],
        _ => ["CIS Controls v8 mapping"]
    };

    private static List<string> GetCisKubernetesCompliance(string testKey) => testKey switch
    {
        "CISK8SAPI" => ["CIS Kubernetes Benchmark: API server hardening controls"],
        "CISK8SSECRETS" => ["CIS Kubernetes Benchmark: Secrets management controls"],
        _ => ["CIS Kubernetes benchmark mapping"]
    };

    private static List<string> GetCsaZeroTrustCompliance(string testKey) => testKey switch
    {
        "CSAZTIDENTITY" => ["CSA Zero Trust: Identity pillar controls"],
        "CSAZTWORKLOAD" => ["CSA Zero Trust: Device and workload pillar controls"],
        _ => ["CSA Zero Trust controls mapping"]
    };

    private static List<string> GetCartaCompliance(string testKey) => testKey switch
    {
        "CARTAADAPTIVE" => ["Gartner CARTA: adaptive trust assessment"],
        "CARTARISK" => ["Gartner CARTA: continuous risk validation"],
        _ => ["Gartner CARTA model mapping"]
    };

    private static List<string> GetMitreCompliance(string testKey) => testKey switch
    {
        "MITRET1190" => ["MITRE ATT&CK T1190 Exploit Public-Facing Application"],
        "MITRET1078" => ["MITRE ATT&CK T1078 Valid Accounts"],
        "MITRET1550001" => ["MITRE ATT&CK T1550.001 Use Alternate Authentication Material: Application Access Token"],
        "MITRET1110" => ["MITRE ATT&CK T1110 Brute Force"],
        "MITRET1059" => ["MITRE ATT&CK T1059 Command and Scripting Interpreter"],
        "MITRET1552001" => ["MITRE ATT&CK T1552.001 Unsecured Credentials: Credentials in Files"],
        "MITRET1071001" => ["MITRE ATT&CK T1071.001 Application Layer Protocol: Web Protocols"],
        "MITRET1195" => ["MITRE ATT&CK T1195 Supply Chain Compromise"],
        "MITRET1133" => ["MITRE ATT&CK T1133 External Remote Services"],
        "MITRET1078_004" => ["MITRE ATT&CK T1078.004 Valid Accounts: Cloud Accounts"],
        "MITRET1040" => ["MITRE ATT&CK T1040 Network Sniffing"],
        "MITRET1562" => ["MITRE ATT&CK T1562 Impair Defenses"],
        "MITRET1595" => ["MITRE ATT&CK T1595 Active Scanning"],
        _ => ["MITRE ATT&CK Initial Access/Exploitation technique mapping"]
    };

    private static List<string> GetCobitCompliance(string testKey) => testKey switch
    {
        "COBITDSS05" => ["COBIT DSS05 Managed Security Services"],
        "COBITMEA" => ["COBIT MEA domain Monitoring, Evaluation, and Assessment"],
        _ => ["COBIT governance/control objective mapping"]
    };

    private static List<string> GetSammCompliance(string testKey) => testKey switch
    {
        "SAMMVERIFY" => ["OWASP SAMM Verification practice"],
        "SAMMTHREAT" => ["OWASP SAMM Threat Assessment practice"],
        _ => ["OWASP SAMM practice maturity mapping"]
    };

    private static List<string> GetBsiCompliance(string testKey) => testKey switch
    {
        "BSICODE" => ["BSI secure development: secure coding controls"],
        "BSITEST" => ["BSI secure development: security testing controls"],
        _ => ["BSI secure development control mapping"]
    };

    private static List<string> GetMicrosoftSdlCompliance(string testKey) => testKey switch
    {
        "SDLTHREAT" => ["Microsoft SDL: Threat Modeling requirement"],
        "SDLVERIFY" => ["Microsoft SDL: Security Verification Testing requirement"],
        _ => ["Microsoft SDL verification activity mapping"]
    };

    private static List<string> GetAdvancedApiChecksCompliance(string testKey) => testKey switch
    {
        "OPENREDIRECT" => ["CWE-601 Open Redirect", "OWASP ASVS V5 Validation Controls"],
        "PATHTRAV" => ["CWE-22 Path Traversal", "OWASP WSTG Input Validation"],
        "FORCEDBROWSE" => ["CWE-285 Improper Authorization", "OWASP API1/API5 access control checks"],
        "HOSTHEADER" => ["CWE-346 Origin Validation Error", "OWASP Misconfiguration Controls"],
        "CACHE" => ["OWASP Session/Data Caching Controls", "NIST SC-23 Session Authenticity"],
        "COOKIEFLAGS" => ["OWASP Session Management", "CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"],
        "CSRFPROTECT" => ["OWASP ASVS V4 CSRF defenses", "NIST SP 800-53 SC-23 Session Authenticity"],
        "JWTNONE" => ["CWE-347 Improper Verification of Cryptographic Signature", "OWASP JWT Cheat Sheet"],
        "GRAPHQL" => ["OWASP GraphQL Security Testing", "API Surface Hardening"],
        "LARGEPAYLOAD" => ["OWASP API4 Resource Consumption", "NIST SC-5 DoS Protection"],
        "CONTENTTYPE" => ["CWE-20 Improper Input Validation", "OWASP Input Validation Controls"],
        "PARAMPOLLUTION" => ["CWE-20 Improper Input Validation", "OWASP WSTG Input Validation"],
        "TYPECONF" => ["CWE-1287 Improper Validation of Specified Type of Input", "OWASP Input Validation Controls"],
        "PARAMSHADOW" => ["CWE-20 Improper Input Validation", "Duplicate parameter shadowing consistency controls"],
        "JSONSMUGGLE" => ["CWE-436 Interpretation Conflict", "JSON key normalization and parser consistency controls"],
        "AUTHHEADEROVR" => ["CWE-285 Improper Authorization", "Header-based identity trust boundary controls"],
        "TENANTLEAK" => ["CWE-639 Authorization Bypass Through User-Controlled Key", "Multi-tenant isolation controls"],
        "ASYNCJOBINJ" => ["CWE-862 Missing Authorization", "Asynchronous task/job queue input hardening controls"],
        "FILEPARSERABUSE" => ["CWE-434 Unrestricted Upload of File with Dangerous Type", "ZIP/XML/SVG parser hardening controls"],
        "VERSIONFALLBACK" => ["OWASP API9 Improper Inventory Management", "Deprecated API version hardening controls"],
        "CACHEKEYCONF" => ["CWE-444 Inconsistent Interpretation of HTTP Requests", "Cache key poisoning resistance controls"],
        "NOSQLI" => ["CWE-943 Improper Neutralization of Special Elements in Data Query Logic", "OWASP API8/API10 injection and parser controls"],
        "REPLAY" => ["OWASP API6 Business Logic", "NIST IA/AC Replay Resistance Expectations"],
        "VERBTAMPER" => ["CWE-285 Improper Authorization", "OWASP Security Misconfiguration"],
        "JWTMALFORMED" => ["JWT Robustness Validation", "OWASP API2 Authentication"],
        "JWTEXPIRED" => ["OWASP API2 Authentication", "Token Lifetime Validation Controls"],
        "JWTNOEXP" => ["OWASP API2 Authentication", "Token Claims Validation Controls"],
        "TOKENQUERY" => ["OAuth 2.0 Security BCP", "Sensitive Token Handling Controls"],
        "TOKENFUZZ" => ["Parser Robustness", "DoS/Exception Handling Controls"],
        "OAUTHREDIRECT" => ["OAuth 2.0 Security BCP Redirect URI Validation", "OWASP API2 AuthN Controls"],
        "OAUTHPKCE" => ["OAuth 2.0 PKCE (RFC 7636)", "Public Client Protection Controls"],
        "OAUTHREFRESH" => ["OAuth 2.0 Token Refresh Security", "Token Revocation/Validation Controls"],
        "OAUTHGRANT" => ["OAuth 2.0 Grant-Type Hardening", "Legacy Grant Risk Controls"],
        "OAUTHSCOPE" => ["OAuth 2.0 Scope Restriction Controls", "Least Privilege Authorization"],
        "CRLFINJECT" => ["CWE-93 Improper Neutralization of CRLF Sequences", "OWASP ASVS V5 Input Validation"],
        "HEADEROVERRIDE" => ["CWE-285 Improper Authorization", "NIST SP 800-53 SC-7 Boundary Protection"],
        "DUPHEADER" => ["CWE-444 Inconsistent Interpretation of HTTP Requests", "HTTP Header Normalization Controls"],
        "METHODOVERRIDE" => ["CWE-285 Improper Authorization", "OWASP API5 Function-Level Authorization"],
        "RACE" => ["CWE-362 Concurrent Execution using Shared Resource", "OWASP API6 Sensitive Business Flows"],
        "DEEPJSON" => ["OWASP API4 Unrestricted Resource Consumption", "NIST SP 800-53 SC-5 DoS Protection"],
        "UNICODE" => ["CWE-176 Improper Handling of Unicode Encoding", "OWASP WSTG Input Validation Testing"],
        "VERSIONDISCOVERY" => ["OWASP API9 Improper Inventory Management", "Asset and endpoint enumeration controls"],
        "XXE" => ["CWE-611 Improper Restriction of XML External Entity Reference", "OWASP XML Security Testing"],
        "XMLENTITYDOS" => ["CWE-776 Improper Restriction of Recursive Entity References in DTDs", "Parser resource exhaustion controls"],
        "DESERIALJSON" => ["CWE-502 Deserialization of Untrusted Data", "OWASP deserialization hardening controls"],
        "MASSASSIGN" => ["CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes", "OWASP API3 BOPLA"],
        "SSTI" => ["CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine", "OWASP injection controls"],
        "SMUGGLESIGNAL" => ["CWE-444 Inconsistent Interpretation of HTTP Requests", "Request smuggling normalization controls"],
        "TLSPOSTURE" => ["NIST SP 800-53 SC-8/SC-23", "Transport security baseline controls"],
        "GRAPHQLDEPTH" => ["OWASP GraphQL query depth/cost controls", "OWASP API4 resource consumption"],
        "WEBSOCKETAUTH" => ["WebSocket authentication and origin controls", "OWASP ASVS session/auth controls"],
        "GRPCREFLECT" => ["Service reflection exposure minimization", "OWASP API9 inventory management"],
        "RATELIMITEVASION" => ["Rate-limiting bypass resistance", "OWASP API4 unrestricted resource consumption"],
        "SSRFENCODED" => ["CWE-918 Server-Side Request Forgery", "URL parsing and egress control hardening"],
        "FILEUPLOAD" => ["CWE-434 Unrestricted Upload of File with Dangerous Type", "File upload content validation controls"],
        "OPENAPIMISMATCH" => ["CWE-20 Improper Input Validation", "Schema and contract validation controls"],
        "LOGPOISON" => ["CWE-117 Improper Output Neutralization for Logs", "Audit/log integrity controls"],
        "OIDCSTATE" => ["OIDC Core: state parameter replay resistance", "OAuth 2.0 CSRF protection controls"],
        "OIDCNONCE" => ["OIDC Core: nonce replay resistance", "Token replay prevention controls"],
        "OIDCISS" => ["OIDC Core: issuer claim validation", "JWT claim validation controls"],
        "OIDCAUD" => ["OIDC Core: audience claim validation", "Token audience restriction controls"],
        "OIDCSUB" => ["OIDC/OAuth token substitution resistance", "Cross-token confusion prevention controls"],
        "MTLSREQUIRED" => ["mTLS client certificate authentication requirement", "NIST SP 800-53 IA/SC transport controls"],
        "MTLSEXPOSURE" => ["mTLS-protected endpoint segregation", "Sensitive endpoint exposure controls"],
        "WORKFLOWSKIP" => ["OWASP API6 Sensitive Business Flows", "CWE-841 Improper Enforcement of Behavioral Workflow"],
        "WORKFLOWDUP" => ["Idempotency and duplicate transition controls", "Business transaction integrity controls"],
        "WORKFLOWTOCTOU" => ["CWE-367 Time-of-check Time-of-use Race Condition", "Concurrency control hardening"],
        "JWTKID" => ["JWT header 'kid' validation controls", "CWE-20 Improper Input Validation"],
        "JWTJKU" => ["JWT 'jku' trusted key source restrictions", "Key retrieval trust-boundary controls"],
        "JWTX5U" => ["JWT 'x5u' trusted certificate URL restrictions", "Certificate URL injection resistance"],
        "JWTRSHS" => ["JWT algorithm confusion resistance (RS256/HS256)", "CWE-347 Improper Verification of Cryptographic Signature"],
        "DESYNCCLTE" => ["CWE-444 Inconsistent Interpretation of HTTP Requests", "CL.TE desync hardening"],
        "DESYNCTECL" => ["CWE-444 Inconsistent Interpretation of HTTP Requests", "TE.CL desync hardening"],
        "DESYNCDCL" => ["Duplicate Content-Length normalization controls", "HTTP parser consistency controls"],
        "HTTP2DOWNGRADE" => ["HTTP/2 to HTTP/1.1 downgrade handling controls", "Protocol downgrade consistency checks"],
        "GRPCMETA" => ["gRPC metadata authorization controls", "Header trust-boundary validation controls"],
        "WSMESSAGE" => ["WebSocket message-level authorization controls", "Injection-resistant message validation"],
        "LLMPROMPT" => ["LLM prompt injection resistance controls", "Input sanitization and instruction isolation controls"],
        "COUPONABUSE" => ["CWE-840 Business Logic Errors", "OWASP API6 Sensitive Business Flows"],
        "IMDSV2" => ["CWE-918 Server-Side Request Forgery", "Cloud metadata access hardening (IMDSv2/token-based)"],
        "DNSREBIND" => ["Host and origin validation controls", "DNS rebinding resistance controls"],
        "JWTJWKSPORT" => ["JWT JWKS key source trust restrictions", "CWE-345 Insufficient Verification of Data Authenticity"],
        "OIDCDISCOVERY" => ["OIDC discovery document issuer binding controls", "Metadata endpoint trust validation controls"],
        "CERTCHAIN" => ["X.509 certificate chain validation controls", "Certificate expiry and trust-anchor hygiene"],
        "NUMERICFLOW" => ["CWE-190 Integer Overflow or Wraparound", "CWE-191 Integer Underflow"],
        "DOUBLESPEND" => ["CWE-367 Time-of-check Time-of-use Race Condition", "Transaction idempotency and balance integrity controls"],
        "GRPCPROTOFUZZ" => ["gRPC protobuf parser robustness controls", "Malformed binary input handling controls"],
        "GRAPHQLCOMPLEX" => ["GraphQL query cost/complexity controls", "OWASP API4 resource consumption controls"],
        "WSFRAGMENT" => ["WebSocket fragmented frame handling controls", "Message reassembly validation controls"],
        "TIMINGLEAK" => ["Timing side-channel resistance controls", "User/account enumeration protection"],
        "EGRESS" => ["Outbound egress policy enforcement", "SSRF pivot containment controls"],
        "DOCKERAPI" => ["Docker daemon/API access hardening controls", "Container runtime interface exposure controls (CWE-306/CWE-200)"],
        "PORTFINGER" => ["Attack-surface reduction controls", "Unnecessary service exposure minimization controls"],
        "CLOUDPUB" => ["Cloud object storage public-access prevention controls", "Bucket/container ACL hardening controls"],
        "ENVEXPOSE" => ["CWE-200 Exposure of Sensitive Information to an Unauthorized Actor", "CWE-552 Files or Directories Accessible to External Parties"],
        "SUBTAKEOVER" => ["DNS hygiene and subdomain lifecycle controls", "Dangling DNS/subdomain takeover prevention controls"],
        "CSPHEADER" => ["Content-Security-Policy enforcement controls", "Browser script execution restriction controls"],
        "CLICKJACK" => ["X-Frame-Options/CSP frame-ancestors controls", "UI redress/clickjacking prevention controls"],
        "DOMXSSSIG" => ["DOM XSS sink/source hardening controls", "Client-side script injection resistance controls"],
        "SCRIPTSUPPLY" => ["Third-party JavaScript supply-chain inventory controls", "Script source trust/integrity controls"],
        "MOBILEPINNING" => ["Mobile TLS pinning verification signals", "MITM resistance for mobile API channels"],
        "MOBILESTORAGE" => ["Mobile local secret/PII exposure prevention controls", "Client-side storage minimization controls"],
        "MOBILEDEEPLINK" => ["Deep-link ownership validation controls", "Redirect and URI-scheme hijack prevention controls"],
        _ => ["Advanced defensive technical controls mapping"]
    };
}
