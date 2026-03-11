namespace ApiTester.Core;

public enum FrameworkPackFamily
{
    ApplicationApi,
    UsFederal,
    International,
    CloudInfrastructure,
    IndustryRegulatory,
    TestingAssurance,
    ArchitectureZeroTrust,
    SdlcDevSecOps
}

public sealed record TestMethodMetadata(string TestName, string? MethodName);

public sealed record FrameworkPackMapping(string Category, FrameworkPackFamily Family);

public static partial class Mappings
{
    public static string GetFrameworkCategory(string frameworkName)
    {
        return frameworkName switch
        {
            "OWASP API Security Top 10" or "OWASP ASVS" or "OWASP MASVS" or "Cloud Security Alliance API Security guidance"
                => "1) Application & API-Specific Standards",
            "NIST SP 800-53" or "NIST SP 800-61" or "NIST SP 800-63" or "NIST SP 800-171" or "NIST SP 800-207" or "NIST SP 800-190" or "FedRAMP" or "DISA STIG/SRG"
                => "2) U.S. Federal / Government Standards",
            "ISO 27001" or "ISO 27002" or "ISO 27017" or "ISO 27018" or "ISO 27701"
                => "3) International Security Standards",
            "Cloud Security Alliance CCM" or "CIS Critical Security Controls" or "Center for Internet Security Kubernetes Benchmark" or "MITRE ATT&CK Framework"
                => "4) Cloud & Infrastructure Security",
            "PCI DSS" or "FFIEC guidance" or "HIPAA Security Rule" or "GDPR" or "CCPA" or "CMMC" or "SOC 2"
                => "5) Industry & Regulatory Frameworks",
            "OWASP Testing Guide" or "CREST Penetration Testing standards" or "ISACA COBIT" or "NIST SP 800-115"
                => "6) Testing & Assurance Standards",
            "NIST Zero Trust (SP 800-207)" or "Cloud Security Alliance Zero Trust Guidance" or "Gartner CARTA model"
                => "7) Architecture & Zero Trust",
            "OWASP SAMM" or "BSI Secure Development models" or "Microsoft SDL"
                => "8) Secure SDLC & DevSecOps",
            "Advanced API Checks" => "9) Additional Advanced Checks",
            _ => "Framework Test"
        };
    }

    public static FrameworkPackMapping? GetFrameworkPackMapping(string frameworkName)
    {
        return frameworkName switch
        {
            "OWASP API Security Top 10" => new("1) Application & API-Specific Standards", FrameworkPackFamily.ApplicationApi),
            "OWASP ASVS" => new("1) Application & API-Specific Standards", FrameworkPackFamily.ApplicationApi),
            "OWASP MASVS" => new("1) Application & API-Specific Standards", FrameworkPackFamily.ApplicationApi),
            "Cloud Security Alliance API Security guidance" => new("1) Application & API-Specific Standards", FrameworkPackFamily.ApplicationApi),
            "NIST SP 800-53" => new("2) U.S. Federal / Government Standards", FrameworkPackFamily.UsFederal),
            "NIST SP 800-61" => new("2) U.S. Federal / Government Standards", FrameworkPackFamily.UsFederal),
            "NIST SP 800-63" => new("2) U.S. Federal / Government Standards", FrameworkPackFamily.UsFederal),
            "NIST SP 800-171" => new("2) U.S. Federal / Government Standards", FrameworkPackFamily.UsFederal),
            "NIST SP 800-207" => new("2) U.S. Federal / Government Standards", FrameworkPackFamily.UsFederal),
            "NIST SP 800-190" => new("2) U.S. Federal / Government Standards", FrameworkPackFamily.UsFederal),
            "FedRAMP" => new("2) U.S. Federal / Government Standards", FrameworkPackFamily.UsFederal),
            "DISA STIG/SRG" => new("2) U.S. Federal / Government Standards", FrameworkPackFamily.UsFederal),
            "ISO 27001" => new("3) International Security Standards", FrameworkPackFamily.International),
            "ISO 27002" => new("3) International Security Standards", FrameworkPackFamily.International),
            "ISO 27017" => new("3) International Security Standards", FrameworkPackFamily.International),
            "ISO 27018" => new("3) International Security Standards", FrameworkPackFamily.International),
            "ISO 27701" => new("3) International Security Standards", FrameworkPackFamily.International),
            "Cloud Security Alliance CCM" => new("4) Cloud & Infrastructure Security Standards", FrameworkPackFamily.CloudInfrastructure),
            "CIS Critical Security Controls" => new("4) Cloud & Infrastructure Security Standards", FrameworkPackFamily.CloudInfrastructure),
            "Center for Internet Security Kubernetes Benchmark" => new("4) Cloud & Infrastructure Security Standards", FrameworkPackFamily.CloudInfrastructure),
            "MITRE ATT&CK Framework" => new("4) Cloud & Infrastructure Security Standards", FrameworkPackFamily.CloudInfrastructure),
            "PCI DSS" => new("5) Industry & Regulatory Frameworks", FrameworkPackFamily.IndustryRegulatory),
            "FFIEC guidance" => new("5) Industry & Regulatory Frameworks", FrameworkPackFamily.IndustryRegulatory),
            "HIPAA Security Rule" => new("5) Industry & Regulatory Frameworks", FrameworkPackFamily.IndustryRegulatory),
            "GDPR" => new("5) Industry & Regulatory Frameworks", FrameworkPackFamily.IndustryRegulatory),
            "CCPA" => new("5) Industry & Regulatory Frameworks", FrameworkPackFamily.IndustryRegulatory),
            "CMMC" => new("5) Industry & Regulatory Frameworks", FrameworkPackFamily.IndustryRegulatory),
            "SOC 2" => new("5) Industry & Regulatory Frameworks", FrameworkPackFamily.IndustryRegulatory),
            "OWASP Testing Guide" => new("6) Testing & Assurance Standards", FrameworkPackFamily.TestingAssurance),
            "NIST SP 800-115" => new("6) Testing & Assurance Standards", FrameworkPackFamily.TestingAssurance),
            "CREST Penetration Testing standards" => new("6) Testing & Assurance Standards", FrameworkPackFamily.TestingAssurance),
            "ISACA COBIT" => new("6) Testing & Assurance Standards", FrameworkPackFamily.TestingAssurance),
            "NIST Zero Trust (SP 800-207)" => new("7) Architecture & Zero Trust", FrameworkPackFamily.ArchitectureZeroTrust),
            "Cloud Security Alliance Zero Trust Guidance" => new("7) Architecture & Zero Trust", FrameworkPackFamily.ArchitectureZeroTrust),
            "Gartner CARTA model" => new("7) Architecture & Zero Trust", FrameworkPackFamily.ArchitectureZeroTrust),
            "OWASP SAMM" => new("8) Secure SDLC & DevSecOps Standards", FrameworkPackFamily.SdlcDevSecOps),
            "BSI Secure Development models" => new("8) Secure SDLC & DevSecOps Standards", FrameworkPackFamily.SdlcDevSecOps),
            "Microsoft SDL" => new("8) Secure SDLC & DevSecOps Standards", FrameworkPackFamily.SdlcDevSecOps),
            _ => null
        };
    }

    public static string GetSpecificationForTestKey(string testKey)
    {
        return testKey switch
        {
            "AUTH" => "OWASP API Top 10 API2/API5; NIST AC/IA",
            "API1" => "OWASP API Top 10 API1:2023",
            "API2" => "OWASP API Top 10 API2:2023",
            "API3" => "OWASP API Top 10 API3:2023",
            "API4" => "OWASP API Top 10 API4:2023",
            "API5" => "OWASP API Top 10 API5:2023",
            "API6" => "OWASP API Top 10 API6:2023",
            "API7" => "OWASP API Top 10 API7:2023",
            "API8" => "OWASP API Top 10 API8:2023",
            "API9" => "OWASP API Top 10 API9:2023",
            "API10" => "OWASP API Top 10 API10:2023",
            "BOLA" => "OWASP API Top 10 API1; NIST AC-3",
            "PRIVESC" => "OWASP API Top 10 API5; NIST AC-6",
            "SSRF" => "OWASP API Top 10 API7; NIST SC-7",
            "SQLI" or "XSS" or "CMDINJ" => "OWASP Injection Testing; NIST SI-10",
            "NOSQLI" => "OWASP API Top 10 API8/API10; OWASP ASVS V5; CWE-943",
            "HEADERS" or "TRANSPORT" => "OWASP ASVS V9/V14; NIST SC-8/SC-23; RFC 9110/RFC 8446",
            "CORS" => "OWASP API Security Misconfiguration; NIST SC-7",
            "METHODS" or "VERBTAMPER" => "OWASP Security Misconfiguration; NIST CM-7; RFC 9110",
            "RATELIMIT" => "OWASP API Top 10 API4; NIST SC-5",
            "DISCLOSURE" or "ERROR" => "OWASP API Top 10 API8; NIST SI-11",
            "JWTNONE" or "JWTMALFORMED" or "JWTEXPIRED" or "JWTNOEXP" or "TOKENQUERY" or "TOKENFUZZ" =>
                "OWASP JWT/OAuth Hardening; NIST IA-2/IA-5; RFC 7519/7515/7517",
            "OAUTHREDIRECT" or "OAUTHPKCE" or "OAUTHREFRESH" or "OAUTHGRANT" or "OAUTHSCOPE" =>
                "OAuth 2.0 Security BCP; OWASP API AuthN/AuthZ; RFC 6749/RFC 9700",
            "CRLFINJECT" => "OWASP Input Validation; CWE-93 CRLF Injection",
            "HEADEROVERRIDE" => "OWASP API5/AuthZ hardening; NIST SC-7 boundary protection",
            "DUPHEADER" => "HTTP request normalization hardening; CWE-444",
            "METHODOVERRIDE" => "OWASP Security Misconfiguration; CWE-285 improper authorization",
            "RACE" => "OWASP API6 Business Logic; CWE-362 race condition",
            "DEEPJSON" => "OWASP API4 Resource Consumption; NIST SC-5",
            "UNICODE" => "OWASP Input Validation; CWE-176 Unicode handling",
            "VERSIONDISCOVERY" => "OWASP API9 Inventory Management",
            "XXE" or "XMLENTITYDOS" => "OWASP XML Security; CWE-611 XXE",
            "DESERIALJSON" => "OWASP Deserialization Controls; CWE-502",
            "MASSASSIGN" => "OWASP API3 Object Property Level Authorization; CWE-915",
            "SSTI" => "OWASP Injection Controls; CWE-1336",
            "SMUGGLESIGNAL" => "HTTP Request Smuggling Hardening; CWE-444; RFC 9110",
            "TLSPOSTURE" => "NIST SC-8/SC-23; TLS Baseline Hardening; RFC 8446",
            "GRAPHQLDEPTH" => "OWASP GraphQL Security; Resource Consumption Controls",
            "WEBSOCKETAUTH" => "WebSocket AuthN/AuthZ Controls; OWASP ASVS V4/V5",
            "GRPCREFLECT" => "gRPC service exposure hardening; API inventory controls",
            "RATELIMITEVASION" => "OWASP API4 Resource Consumption; Rate-limit bypass resistance",
            "SSRFENCODED" => "OWASP API7 SSRF; URL parser hardening",
            "FILEUPLOAD" => "OWASP File Upload Security; CWE-434",
            "OPENAPIMISMATCH" => "API contract/schema validation controls; CWE-20",
            "LOGPOISON" => "OWASP Logging Security; CWE-117 log injection",
            "OIDCSTATE" or "OIDCNONCE" or "OIDCISS" or "OIDCAUD" or "OIDCSUB" =>
                "OIDC Core validation controls; OAuth 2.0 security BCP",
            "MTLSREQUIRED" or "MTLSEXPOSURE" => "mTLS client authentication and transport hardening controls",
            "WORKFLOWSKIP" or "WORKFLOWDUP" or "WORKFLOWTOCTOU" =>
                "OWASP API6 sensitive business flows; CWE-841/CWE-367",
            "JWTKID" or "JWTJKU" or "JWTX5U" or "JWTRSHS" =>
                "JWT/OIDC header validation hardening; signature key confusion resistance",
            "DESYNCCLTE" or "DESYNCTECL" or "DESYNCDCL" or "HTTP2DOWNGRADE" =>
                "HTTP request desync/smuggling hardening; parser normalization controls",
            "GRPCMETA" => "gRPC metadata authorization/input validation controls",
            "WSMESSAGE" => "WebSocket message authorization and injection controls",
            "LLMPROMPT" => "LLM prompt injection and instruction-boundary validation controls",
            "COUPONABUSE" => "Business logic abuse controls; OWASP API6/CWE-840",
            "IMDSV2" => "SSRF cloud metadata hardening; CWE-918",
            "DNSREBIND" => "DNS rebinding and host validation controls",
            "JWTJWKSPORT" => "JWKS trust-boundary controls; JWT key source validation",
            "OIDCDISCOVERY" => "OIDC discovery metadata trust and issuer binding controls",
            "CERTCHAIN" => "Certificate trust chain validation; PKI hardening controls",
            "NUMERICFLOW" => "Business logic numeric validation; CWE-190/CWE-191",
            "DOUBLESPEND" => "TOCTOU/double-spend transaction integrity controls; CWE-367",
            "GRPCPROTOFUZZ" => "gRPC parser robustness and malformed input handling controls",
            "GRAPHQLCOMPLEX" => "GraphQL complexity/cost limiting controls; resource abuse resistance",
            "WSFRAGMENT" => "WebSocket frame/message handling robustness controls",
            "TIMINGLEAK" => "Timing side-channel resistance; user enumeration protection",
            "EGRESS" => "Egress filtering and out-of-band SSRF containment controls",
            "DOCKERAPI" => "Container runtime API exposure and daemon hardening controls; CWE-306/CWE-200",
            "PORTFINGER" => "Network service exposure minimization and hardening controls",
            "CLOUDPUB" => "Cloud object storage access control and public exposure prevention controls",
            "ENVEXPOSE" => "Sensitive configuration exposure prevention; CWE-200/CWE-552",
            "SUBTAKEOVER" => "DNS/subdomain ownership hygiene and takeover resistance controls",
            "CSPHEADER" => "Browser Content Security Policy hardening controls",
            "CLICKJACK" => "Frame-embedding restrictions and clickjacking defenses",
            "DOMXSSSIG" => "DOM-based XSS sink/source hardening controls",
            "SCRIPTSUPPLY" => "Third-party script supply-chain inventory and integrity controls",
            "MOBILEPINNING" => "Mobile certificate pinning enforcement validation signals",
            "MOBILESTORAGE" => "Mobile local storage secret minimization and encryption controls",
            "MOBILEDEEPLINK" => "Mobile deep-link ownership binding and hijack-resistance controls",
            "FFIECAUTH" or "FFIECDDOS" or "FFIECLOG" => "FFIEC cybersecurity assessment guidance",
            "HIPAA312A" or "HIPAA312C" or "HIPAA312E" => "HIPAA 45 CFR 164.312 technical safeguards",
            "GDPRART5" or "GDPRART25" or "GDPRART32" => "GDPR Articles 5, 25, 32",
            "CCPA150" or "CCPAPRIV" => "CCPA/CPRA security and privacy requirements",
            "CMMCAC" or "CMMCAT" or "CMMCAU" or "CMMCCM" or "CMMCIA" or "CMMCIR" or "CMMCMA" or "CMMCMP" or "CMMCPE" or "CMMCPS" or "CMMCRA" or "CMMCCA" or "CMMCSC" or "CMMCSI" =>
                "CMMC 2.0 control domains",
            "SOC2CC6" or "SOC2CC7" or "SOC2CC8" => "SOC 2 Trust Services Criteria CC6/CC7/CC8",
            "FEDRAMPAC" or "FEDRAMPAU" or "FEDRAMPCM" or "FEDRAMPIR" or "FEDRAMPRA" or "FEDRAMPSC" or "FEDRAMPSI" or "FEDRAMPCA" =>
                "FedRAMP security control baseline mappings",
            "STIGAUTH" or "STIGNET" or "STIGAUD" or "STIGCONF" or "STIGASD" or "STIGWSRG" =>
                "DISA STIG/SRG hardening and auditing requirements",
            "N171AC" or "N171AT" or "N171AU" or "N171CM" or "N171IA" or "N171IR" or "N171MA" or "N171MP" or "N171PS" or "N171PE" or "N171RA" or "N171CA" or "N171SC" or "N171SI" =>
                "NIST SP 800-171 CUI protection requirements",
            "ASVSV2" or "ASVSV3" or "ASVSV4" or "ASVSV5" or "ASVSV6" or "ASVSV7" or "ASVSV8" or "ASVSV9" or "ASVSV13" or "ASVSV14" =>
                "OWASP ASVS v4 verification requirements",
            "MASVSAUTH" or "MASVSNETWORK" or "MASVSSTORAGE" => "OWASP MASVS v2 control categories",
            "CSAAPIIAM" or "CSAAPIINJ" or "CSAAPITRANS" => "CSA API Security Guidance controls",
            "CCMIAM" or "CCMIVS" => "CSA CCM control objectives",
            "CIS3" or "CIS16" => "CIS Critical Security Controls v8",
            "CISK8SAPI" or "CISK8SSECRETS" => "CIS Kubernetes Benchmark controls",
            "MITRET1190" or "MITRET1078" or "MITRET1550001" or "MITRET1110" or "MITRET1059" or "MITRET1552001" or "MITRET1071001" or
            "MITRET1195" or "MITRET1133" or "MITRET1078_004" or "MITRET1040" or "MITRET1562" or "MITRET1595" =>
                "MITRE ATT&CK technique mappings",
            "WSTGATHN" or "WSTGINPV" or "WSTGCONF" or "WSTGBUSL" => "OWASP WSTG control mappings",
            "N115PLAN" or "N115EXEC" or "N115REPORT" => "NIST SP 800-115 technical testing lifecycle mappings",
            "CRESTAUTH" or "CRESTINJ" => "CREST penetration testing standards mapping",
            "COBITDSS05" or "COBITMEA" => "COBIT governance and assurance objectives",
            "SAMMVERIFY" or "SAMMTHREAT" => "OWASP SAMM practice mappings",
            "BSICODE" or "BSITEST" => "BSI secure development control mappings",
            "SDLTHREAT" or "SDLVERIFY" => "Microsoft SDL practice mappings",
            "ZT207PDP" or "ZT207PEP" or "ZT207CDM" => "NIST SP 800-207 zero trust mappings",
            "CSAZTIDENTITY" or "CSAZTWORKLOAD" => "CSA Zero Trust guidance mappings",
            "CARTAADAPTIVE" or "CARTARISK" => "Gartner CARTA model mappings",
            "PCIDSS4" or "PCIDSS6" or "PCIDSS8" or "PCIDSS10" or "PCIDSS11" => "PCI DSS v4.0 control requirements",
            "ISO27001A5" or "ISO27001A8" or "ISO27002820" or "ISO27002816" or "ISO27002822" or "ISO27002824" or "ISO27002825" or "ISO27002826" or "ISO27017SHARED" or "ISO27017NETWORK" or "ISO27018PII" or "ISO27018PROCESS" or "ISO27701CTRL" or "ISO27701PROC" =>
                "ISO/IEC 27001/27002/27017/27018/27701 control mappings",
            "OPENREDIRECT" => "OWASP ASVS V5",
            "PATHTRAV" => "OWASP Input Validation; NIST SI-10",
            "FORCEDBROWSE" => "OWASP API Top 10 API1/API5; OWASP ASVS V4; NIST AC-3/AC-6",
            "HOSTHEADER" => "OWASP Misconfiguration; NIST SC-7",
            "CACHE" or "COOKIEFLAGS" => "OWASP Session Management; NIST SC-23",
            "CSRFPROTECT" => "OWASP ASVS V4; NIST SC-23; PCI DSS Req 6",
            "GRAPHQL" => "OWASP GraphQL Security",
            "LARGEPAYLOAD" => "OWASP API4 Resource Consumption; NIST SC-5",
            "CONTENTTYPE" or "PARAMPOLLUTION" or "TYPECONF" => "OWASP Input Validation; CWE-20/CWE-1287",
            "PARAMSHADOW" => "HTTP parameter canonicalization and duplicate-key handling controls; CWE-20/CWE-444",
            "JSONSMUGGLE" => "JSON key normalization and parser consistency controls; CWE-20/CWE-436",
            "AUTHHEADEROVR" => "Header trust-boundary authentication controls; OWASP API2/API5; CWE-285",
            "TENANTLEAK" => "Multi-tenant object isolation controls; OWASP API1; CWE-284/CWE-639",
            "ASYNCJOBINJ" => "Asynchronous job/task authorization and input validation controls; CWE-862/CWE-915",
            "FILEPARSERABUSE" => "File parser hardening controls; CWE-22/CWE-611/CWE-434",
            "VERSIONFALLBACK" => "API version lifecycle and deprecated endpoint hardening controls; OWASP API9",
            "CACHEKEYCONF" => "Web cache key normalization and poisoning resistance controls; CWE-444/CWE-345",
            "REPLAY" => "OWASP API6 Business Flow; NIST IA/AC",
            _ => "Internal defensive mapping"
        };
    }
}
