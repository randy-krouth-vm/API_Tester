namespace ApiTester.Core;

public static partial class Mappings
{
    public static IReadOnlyList<string> GetFrameworkControlKeys(string frameworkName)
    {
        return frameworkName switch
        {
            "OWASP API Security Top 10" => ["API1", "API2", "API3", "API4", "API5", "API6", "API7", "API8", "API9", "API10"],
            "OWASP ASVS" => ["ASVSV2", "ASVSV3", "ASVSV4", "CSRFPROTECT", "ASVSV5", "ASVSV6", "ASVSV7", "ASVSV8", "ASVSV9", "ASVSV13", "ASVSV14"],
            "OWASP MASVS" => ["MASVSAUTH", "MASVSNETWORK", "MASVSSTORAGE"],
            "Cloud Security Alliance API Security guidance" => ["CSAAPIIAM", "CSAAPIINJ", "CSAAPITRANS"],
            "NIST SP 800-53" => ["N53AC2", "N53AC3", "N53AC6", "N53IA2", "N53IA5", "N53AU2", "N53AU9", "N53AU12", "N53CM6", "N53CM7", "N53SA11", "N53IR6", "N53RA5", "N53SC5", "N53SC7", "N53SC8", "N53SC23", "N53SC28", "N53SI10", "N53SI11"],
            "NIST SP 800-61" => ["N61DETECT", "N61CONTAIN", "N61ERADICATE", "N61RECOVER"],
            "NIST SP 800-63" => ["N63AAL", "N63REPLAY", "N63SESSION"],
            "NIST SP 800-171" => ["N171AC", "N171AT", "N171AU", "N171CM", "N171IA", "N171IR", "N171MA", "N171MP", "N171PE", "N171PS", "N171RA", "N171CA", "N171SC", "N171SI"],
            "NIST SP 800-207" => ["N207VERIFY", "N207LEAST", "N207POLICY"],
            "NIST SP 800-190" => ["N190NETWORK", "N190RUNTIME", "N190SECRETS"],
            "FedRAMP" => ["FEDRAMPAC", "FEDRAMPAU", "FEDRAMPCM", "FEDRAMPIR", "FEDRAMPRA", "FEDRAMPSC", "FEDRAMPSI", "FEDRAMPCA"],
            "DISA STIG/SRG" => ["STIGAUTH", "STIGNET", "STIGAUD", "STIGCONF", "STIGASD", "STIGWSRG"],
            "ISO 27001" => ["ISO27001A5", "ISO27001A8"],
            "ISO 27002" => ["ISO27002820", "ISO27002816", "ISO27002822", "ISO27002824", "ISO27002825", "ISO27002826"],
            "ISO 27017" => ["ISO27017SHARED", "ISO27017NETWORK"],
            "ISO 27018" => ["ISO27018PII", "ISO27018PROCESS"],
            "ISO 27701" => ["ISO27701CTRL", "ISO27701PROC"],
            "Cloud Security Alliance CCM" or "CSA CCM" => ["CCMIAM", "CCMIVS"],
            "CIS Critical Security Controls" => ["CIS3", "CIS16"],
            "Center for Internet Security Kubernetes Benchmark" or "CIS Kubernetes Benchmark" => ["CISK8SAPI", "CISK8SSECRETS"],
            "MITRE ATT&CK Framework" => ["MITRET1190", "MITRET1078", "MITRET1550001", "MITRET1110", "MITRET1059", "MITRET1552001", "MITRET1071001", "MITRET1195", "MITRET1133", "MITRET1078_004", "MITRET1040", "MITRET1562", "MITRET1595"],
            "PCI DSS" => ["PCIDSS4", "PCIDSS6", "PCIDSS8", "PCIDSS10", "PCIDSS11"],
            "FFIEC guidance" => ["FFIECAUTH", "FFIECDDOS", "FFIECLOG"],
            "HIPAA Security Rule" => ["HIPAA312A", "HIPAA312C", "HIPAA312E"],
            "GDPR" => ["GDPRART5", "GDPRART25", "GDPRART32"],
            "CCPA" => ["CCPA150", "CCPAPRIV"],
            "CMMC" => ["CMMCAC", "CMMCAT", "CMMCAU", "CMMCCM", "CMMCIA", "CMMCIR", "CMMCMA", "CMMCMP", "CMMCPE", "CMMCPS", "CMMCRA", "CMMCCA", "CMMCSC", "CMMCSI"],
            "SOC 2" => ["SOC2CC6", "SOC2CC7", "SOC2CC8"],
            "OWASP Testing Guide" => ["WSTGATHN", "WSTGINPV", "WSTGCONF", "WSTGBUSL"],
            "NIST SP 800-115" => ["N115PLAN", "N115EXEC", "N115REPORT"],
            "CREST Penetration Testing standards" => ["CRESTAUTH", "CRESTINJ"],
            "ISACA COBIT" => ["COBITDSS05", "COBITMEA"],
            "NIST Zero Trust (SP 800-207)" => ["ZT207PDP", "ZT207PEP", "ZT207CDM"],
            "Cloud Security Alliance Zero Trust Guidance" or "CSA Zero Trust Guidance" => ["CSAZTIDENTITY", "CSAZTWORKLOAD"],
            "Gartner CARTA model" => ["CARTAADAPTIVE", "CARTARISK"],
            "OWASP SAMM" => ["SAMMVERIFY", "SAMMTHREAT"],
            "BSI Secure Development models" => ["BSICODE", "BSITEST"],
            "Microsoft SDL" => ["SDLTHREAT", "SDLVERIFY"],
            "Advanced API Checks" => ["OPENREDIRECT", "PATHTRAV", "FORCEDBROWSE", "HOSTHEADER", "CACHE", "COOKIEFLAGS", "CSRFPROTECT", "JWTNONE", "GRAPHQL", "LARGEPAYLOAD", "CONTENTTYPE", "PARAMPOLLUTION", "TYPECONF", "PARAMSHADOW", "JSONSMUGGLE", "AUTHHEADEROVR", "TENANTLEAK", "ASYNCJOBINJ", "FILEPARSERABUSE", "VERSIONFALLBACK", "CACHEKEYCONF", "NOSQLI", "REPLAY", "VERBTAMPER"],
            _ => []
        };
    }
}
