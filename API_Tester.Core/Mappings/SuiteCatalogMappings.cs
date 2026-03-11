namespace ApiTester.Core;

public sealed record StandardFrameworkPackDefinition(
    string CategoryName,
    string[] Frameworks,
    string[] TestMethodNames);

public sealed record NamedSuiteDefinition(
    string SuiteKey,
    string Name,
    string[] TestMethodNames);

public static class SuiteCatalogMappings
{
    public static IReadOnlyList<StandardFrameworkPackDefinition> GetStandardFrameworkPacks()
    {
        return
        [
            new(
                "1) Application & API-Specific Standards",
                ["OWASP API Security Top 10", "OWASP ASVS", "OWASP MASVS", "Cloud Security Alliance API Security guidance"],
                ["RunAuthAndAccessControlTestsAsync", "RunMITREATTampCKFrameworkSsrfTestsAsync", "RunSqlInjectionTestsAsync", "RunXssTestsAsync", "RunSecurityHeaderTestsAsync", "RunCorsTestsAsync", "RunHttpMethodTestsAsync"]),
            new(
                "2) U.S. Federal / Government Standards",
                ["NIST SP 800-53", "NIST SP 800-61", "NIST SP 800-63", "NIST SP 800-171", "NIST SP 800-207", "NIST SP 800-190", "FedRAMP", "DISA STIG/SRG"],
                ["RunTransportSecurityTestsAsync", "RunAuthAndAccessControlTestsAsync", "RunSecurityHeaderTestsAsync", "RunCorsTestsAsync", "RunHttpMethodTestsAsync", "RunRateLimitTestsAsync", "RunInformationDisclosureTestsAsync"]),
            new(
                "3) International Security Standards",
                ["ISO 27001", "ISO 27002", "ISO 27017", "ISO 27018", "ISO 27701"],
                ["RunTransportSecurityTestsAsync", "RunSecurityHeaderTestsAsync", "RunAuthAndAccessControlTestsAsync", "RunInformationDisclosureTestsAsync", "RunRateLimitTestsAsync"]),
            new(
                "4) Cloud & Infrastructure Security Standards",
                ["CSA CCM", "CIS Critical Security Controls", "CIS Kubernetes Benchmark", "MITRE ATT&CK Framework"],
                ["RunTransportSecurityTestsAsync", "RunSecurityHeaderTestsAsync", "RunMITREATTampCKFrameworkSsrfTestsAsync", "RunCorsTestsAsync", "RunHttpMethodTestsAsync", "RunRateLimitTestsAsync", "RunInformationDisclosureTestsAsync"]),
            new(
                "5) Industry & Regulatory Frameworks",
                ["PCI DSS", "FFIEC guidance", "HIPAA Security Rule", "GDPR", "CCPA", "CMMC", "SOC 2"],
                ["RunTransportSecurityTestsAsync", "RunAuthAndAccessControlTestsAsync", "RunSecurityHeaderTestsAsync", "RunInformationDisclosureTestsAsync", "RunRateLimitTestsAsync", "RunSqlInjectionTestsAsync"]),
            new(
                "6) Testing & Assurance Standards",
                ["OWASP Testing Guide", "NIST SP 800-115", "CREST Penetration Testing standards", "ISACA COBIT"],
                ["RunAuthAndAccessControlTestsAsync", "RunMITREATTampCKFrameworkSsrfTestsAsync", "RunXssTestsAsync", "RunSqlInjectionTestsAsync", "RunSecurityHeaderTestsAsync", "RunCorsTestsAsync", "RunHttpMethodTestsAsync", "RunRateLimitTestsAsync", "RunInformationDisclosureTestsAsync"]),
            new(
                "7) Architecture & Zero Trust",
                ["NIST SP 800-207", "CSA Zero Trust Guidance", "Gartner CARTA model"],
                ["RunTransportSecurityTestsAsync", "RunAuthAndAccessControlTestsAsync", "RunCorsTestsAsync", "RunHttpMethodTestsAsync", "RunRateLimitTestsAsync", "RunInformationDisclosureTestsAsync"]),
            new(
                "8) Secure SDLC & DevSecOps Standards",
                ["OWASP SAMM", "BSI Secure Development models", "Microsoft SDL"],
                ["RunTransportSecurityTestsAsync", "RunSecurityHeaderTestsAsync", "RunAuthAndAccessControlTestsAsync", "RunSqlInjectionTestsAsync", "RunXssTestsAsync", "RunMITREATTampCKFrameworkSsrfTestsAsync", "RunRateLimitTestsAsync", "RunInformationDisclosureTestsAsync"])
        ];
    }

    public static NamedSuiteDefinition? GetNamedSuite(string suiteKey)
    {
        return suiteKey switch
        {
            "SUITE_AUTHZ" => new(
                "SUITE_AUTHZ",
                "Authorization & Access Control",
                ["RunCMMCBolaTestsAsync", "RunAuthAndAccessControlTestsAsync", "RunCsrfProtectionTestsAsync", "RunAuthBruteforceResistanceTestsAsync", "RunBrokenObjectPropertyLevelAuthTestsAsync", "RunPrivilegeEscalationTestsAsync", "RunIdempotencyReplayTestsAsync", "RunMassAssignmentTestsAsync", "RunHeaderOverrideTestsAsync", "RunMethodOverrideTestsAsync"]),
            "SUITE_INJECTION" => new(
                "SUITE_INJECTION",
                "Injection & Input Validation",
                ["RunSqlInjectionTestsAsync", "RunXssTestsAsync", "RunCommandInjectionTestsAsync", "RunCrlfInjectionTestsAsync", "RunSstiProbeTestsAsync", "RunXxeProbeTestsAsync", "RunXmlEntityExpansionTestsAsync", "RunJsonDeserializationAbuseTestsAsync", "RunMITREATTampCKFrameworkSsrfTestsAsync", "RunAdvancedSsrfEncodingTestsAsync", "RunUnicodeNormalizationTestsAsync", "RunParameterPollutionTestsAsync", "RunContentTypeValidationTestsAsync", "RunFileUploadValidationTestsAsync"]),
            "SUITE_IDENTITY" => new(
            "SUITE_IDENTITY",
            "Identity & Token Security (JWT/OAuth)",
            ["RunAuthBruteforceResistanceTestsAsync", "RunJwtNoneAlgorithmTestsAsync", "RunJwtMalformedTokenTestsAsync", "RunJwtExpiredTokenTestsAsync", "RunJwtMissingClaimsTestsAsync", "RunTokenInQueryTestsAsync", "RunTokenParserFuzzTestsAsync", "RunKerberosNegotiateAuthTestsAsync", "RunOAuth1SignatureValidationTestsAsync", "RunOAuthRedirectUriValidationTestsAsync", "RunOAuthPkceEnforcementTestsAsync", "RunOAuthRefreshTokenTestsAsync", "RunOAuthGrantTypeMisuseTestsAsync", "RunOAuthScopeEscalationTestsAsync"]),
            "SUITE_INFRA" => new(
                "SUITE_INFRA",
                "API Infrastructure & Protocol Specifics",
                ["RunPortServiceFingerprintTestsAsync", "RunCloudPublicStorageExposureTestsAsync", "RunEnvFileExposureTestsAsync", "RunSubdomainTakeoverSignalTestsAsync", "RunGraphQlIntrospectionTestsAsync", "RunGraphQlDepthBombTestsAsync", "RunGrpcReflectionTestsAsync", "RunWebSocketAuthTestsAsync", "RunThirdPartyScriptInventoryTestsAsync", "RunTlsPostureTestsAsync", "RunTransportSecurityTestsAsync", "RunOpenApiSchemaMismatchTestsAsync", "RunRequestSmugglingSignalTestsAsync", "RunApiVersionDiscoveryTestsAsync", "RunApiInventoryManagementTestsAsync", "RunUnsafeApiConsumptionTestsAsync", "RunMobileCertificatePinningSignalTestsAsync", "RunMobileLocalStorageSensitivityTestsAsync", "RunMobileDeepLinkHijackingTestsAsync", "RunDockerContainerExposureTestsAsync"]),
            "SUITE_HARDENING" => new(
                "SUITE_HARDENING",
                "HTTP & Server Hardening",
                ["RunSecurityHeaderTestsAsync", "RunCspHeaderTestsAsync", "RunClickjackingHeaderTestsAsync", "RunDomXssSignalTestsAsync", "RunCorsTestsAsync", "RunHttpMethodTestsAsync", "RunVerbTamperingTestsAsync", "RunDuplicateHeaderTestsAsync", "RunHostHeaderInjectionTestsAsync", "RunCacheControlTestsAsync", "RunCookieSecurityFlagTestsAsync", "RunDISASTIGSRGSecurityMisconfigurationTestsAsync"]),
            "SUITE_RESILIENCE" => new(
                "SUITE_RESILIENCE",
                "Resilience & Information Disclosure",
                ["RunRateLimitTestsAsync", "RunRateLimitEvasionTestsAsync", "RunLargePayloadAbuseTestsAsync", "RunDeepJsonNestingTestsAsync", "RunRaceConditionReplayTestsAsync", "RunInformationDisclosureTestsAsync", "RunErrorHandlingLeakageTestsAsync", "RunLogPoisoningTestsAsync", "RunOpenRedirectTestsAsync", "RunPathTraversalTestsAsync"]),
            _ => null
        };
    }

    public static IReadOnlySet<string> GetDynamicProbeExcludedMethodNames()
    {
        return new HashSet<string>(StringComparer.Ordinal)
        {
            "RunSiteSpiderAndCoverageAsync",
            "RunMaximumCoverageAssessmentAsync"
        };
    }

    public static StandardFrameworkPackDefinition? GetStandardFrameworkPack(string categoryName)
    {
        foreach (var pack in GetStandardFrameworkPacks())
        {
            if (string.Equals(pack.CategoryName, categoryName, StringComparison.Ordinal))
            {
                return pack;
            }
        }

        return null;
    }

    public static string GetStandardFrameworkRunMessage(string categoryName)
    {
        return categoryName switch
        {
            "1) Application & API-Specific Standards" => "Running Application & API standards checks...",
            "2) U.S. Federal / Government Standards" => "Running U.S. Federal standards checks...",
            "3) International Security Standards" => "Running International standards checks...",
            "4) Cloud & Infrastructure Security Standards" => "Running Cloud & Infrastructure standards checks...",
            "5) Industry & Regulatory Frameworks" => "Running Industry & Regulatory standards checks...",
            "6) Testing & Assurance Standards" => "Running Testing & Assurance standards checks...",
            "7) Architecture & Zero Trust" => "Running Architecture & Zero Trust standards checks...",
            "8) Secure SDLC & DevSecOps Standards" => "Running Secure SDLC & DevSecOps standards checks...",
            _ => $"Running {categoryName}..."
        };
    }

    public static IReadOnlyList<string> GetDefaultNamedSuiteExecutionOrder()
    {
        return
        [
            "SUITE_AUTHZ",
            "SUITE_INJECTION",
            "SUITE_IDENTITY",
            "SUITE_INFRA",
            "SUITE_HARDENING",
            "SUITE_RESILIENCE"
        ];
    }
}
