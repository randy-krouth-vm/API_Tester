namespace API_Tester.SecurityCatalog;

public static class CveCoverageMapper
{
    private static readonly string[] InputAbuseKeywords =
    {
        "input validation", "improper input", "validation error", "sanitization", "unsanitized",
        "injection", "buffer overflow", "out-of-bounds", "out of bounds", "memory corruption",
        "heap overflow", "stack overflow", "use-after-free", "use after free", "integer overflow",
        "integer underflow", "type confusion", "deserialization", "parser", "format string"
    };

    private static readonly string[] AuthzAuthnKeywords =
    {
        "broken authentication", "improper authentication", "missing authentication",
        "improper authorization", "authorization bypass", "access control", "privilege escalation",
        "elevation of privilege", "session fixation", "session hijack", "token validation",
        "jwt", "oauth", "openid", "oidc", "credential stuffing", "brute force"
    };

    private static readonly string[] ExposureKeywords =
    {
        "information disclosure", "sensitive information", "data exposure", "metadata",
        "directory listing", "debug endpoint", "verbose error", "stack trace", "leak"
    };

    private static readonly string[] TraversalRedirectKeywords =
    {
        "path traversal", "directory traversal", "open redirect", "url redirect",
        "file inclusion", "lfi", "rfi"
    };

    private static readonly string[] ProtocolDosKeywords =
    {
        "denial of service", "dos", "resource exhaustion", "request smuggling",
        "desync", "http/2", "chunked", "content-length", "rate limit", "amplification",
        "graphql", "grpc", "websocket"
    };

    private static readonly string[] CryptoTransportKeywords =
    {
        "tls", "ssl", "certificate", "x509", "trust chain", "signature verification",
        "jwks", "jku", "x5u", "algorithm confusion", "cryptographic"
    };

    private static readonly string[] BrowserClientKeywords =
    {
        "content security policy", "csp", "clickjacking", "frame-ancestors", "x-frame-options",
        "dom xss", "dom-based xss", "third-party script", "supply chain", "javascript library",
        "client-side script", "frontend", "browser"
    };

    private static readonly string[] NetworkInfraKeywords =
    {
        "open port", "port scanning", "service fingerprint", "service enumeration", "egress filtering",
        "reverse shell", "command and control", "c2", "subdomain takeover", "dangling dns", "dns takeover",
        "public bucket", "public s3", "blob storage", "object storage", "environment file", ".env"
    };

    private static readonly string[] MobileKeywords =
    {
        "mobile", "android", "ios", "certificate pinning", "pinning", "sharedpreferences",
        "keychain", "deep link", "deeplink", "intent scheme", "assetlinks", "app-site-association"
    };

    private static readonly Dictionary<string, double> FunctionEffectiveness = new(StringComparer.Ordinal)
    {
        ["RunSsrfTestsAsync"] = 0.86,
        ["RunAdvancedSsrfEncodingTestsAsync"] = 0.89,
        ["RunCloudMetadataImdsV2TestsAsync"] = 0.90,
        ["RunSqlInjectionTestsAsync"] = 0.88,
        ["RunXssTestsAsync"] = 0.84,
        ["RunCommandInjectionTestsAsync"] = 0.88,
        ["RunXxeProbeTestsAsync"] = 0.83,
        ["RunXmlEntityExpansionTestsAsync"] = 0.82,
        ["RunJsonDeserializationAbuseTestsAsync"] = 0.85,
        ["RunAuthAndAccessControlTestsAsync"] = 0.82,
        ["RunBolaTestsAsync"] = 0.87,
        ["RunBrokenObjectPropertyLevelAuthTestsAsync"] = 0.85,
        ["RunPrivilegeEscalationTestsAsync"] = 0.85,
        ["RunIdempotencyReplayTestsAsync"] = 0.81,
        ["RunMassAssignmentTestsAsync"] = 0.84,
        ["RunJwtRsHsConfusionTestsAsync"] = 0.89,
        ["RunJwtNoneAlgorithmTestsAsync"] = 0.87,
        ["RunJwtKidHeaderInjectionTestsAsync"] = 0.88,
        ["RunOAuthRedirectUriValidationTestsAsync"] = 0.86,
        ["RunOAuthPkceEnforcementTestsAsync"] = 0.84,
        ["RunOidcIssuerValidationTestsAsync"] = 0.84,
        ["RunRequestSmugglingSignalTestsAsync"] = 0.83,
        ["RunHttpClTeDesyncTestsAsync"] = 0.84,
        ["RunHttpTeClDesyncTestsAsync"] = 0.84,
        ["RunDualContentLengthTestsAsync"] = 0.82,
        ["RunTlsPostureTestsAsync"] = 0.80,
        ["RunTransportSecurityTestsAsync"] = 0.80,
        ["RunRateLimitTestsAsync"] = 0.78,
        ["RunRateLimitEvasionTestsAsync"] = 0.79,
        ["RunFileUploadValidationTestsAsync"] = 0.84,
        ["RunOpenApiSchemaMismatchTestsAsync"] = 0.79,
        ["RunLlmPromptInjectionTestsAsync"] = 0.76,
        ["RunSecurityMisconfigurationTestsAsync"] = 0.72,
        ["RunInformationDisclosureTestsAsync"] = 0.74,
        ["RunDockerContainerExposureTestsAsync"] = 0.84,
        ["RunPortServiceFingerprintTestsAsync"] = 0.82,
        ["RunCloudPublicStorageExposureTestsAsync"] = 0.84,
        ["RunEnvFileExposureTestsAsync"] = 0.85,
        ["RunSubdomainTakeoverSignalTestsAsync"] = 0.81,
        ["RunCspHeaderTestsAsync"] = 0.83,
        ["RunClickjackingHeaderTestsAsync"] = 0.83,
        ["RunDomXssSignalTestsAsync"] = 0.80,
        ["RunThirdPartyScriptInventoryTestsAsync"] = 0.79,
        ["RunMobileCertificatePinningSignalTestsAsync"] = 0.78,
        ["RunMobileLocalStorageSensitivityTestsAsync"] = 0.80,
        ["RunMobileDeepLinkHijackingTestsAsync"] = 0.79
    };
    private static readonly (string Needle, string[] Functions)[] CweRules =
    {
        ("CWE-79", new[] { "RunXssTestsAsync", "RunContentTypeValidationTestsAsync" }),
        ("CWE-89", new[] { "RunSqlInjectionTestsAsync", "RunContentTypeValidationTestsAsync" }),
        ("CWE-77", new[] { "RunCommandInjectionTestsAsync" }),
        ("CWE-78", new[] { "RunCommandInjectionTestsAsync" }),
        ("CWE-93", new[] { "RunCrlfInjectionTestsAsync", "RunLogPoisoningTestsAsync" }),
        ("CWE-94", new[] { "RunSstiProbeTestsAsync" }),
        ("CWE-611", new[] { "RunXxeProbeTestsAsync", "RunXmlEntityExpansionTestsAsync" }),
        ("CWE-776", new[] { "RunXmlEntityExpansionTestsAsync" }),
        ("CWE-502", new[] { "RunJsonDeserializationAbuseTestsAsync" }),
        ("CWE-176", new[] { "RunUnicodeNormalizationTestsAsync" }),
        ("CWE-20", new[] { "RunContentTypeValidationTestsAsync", "RunParameterPollutionTestsAsync" }),
        ("CWE-434", new[] { "RunFileUploadValidationTestsAsync" }),
        ("CWE-639", new[] { "RunBolaTestsAsync", "RunAuthAndAccessControlTestsAsync" }),
        ("CWE-285", new[] { "RunPrivilegeEscalationTestsAsync", "RunAuthAndAccessControlTestsAsync", "RunVerbTamperingTestsAsync" }),
        ("CWE-362", new[] { "RunRaceConditionReplayTestsAsync", "RunWorkflowToctouRaceTestsAsync", "RunDoubleSpendToctouTestsAsync" }),
        ("CWE-915", new[] { "RunMassAssignmentTestsAsync" }),
        ("CWE-347", new[] { "RunJwtNoneAlgorithmTestsAsync", "RunJwtRsHsConfusionTestsAsync", "RunJwtKidHeaderInjectionTestsAsync" }),
        ("CWE-601", new[] { "RunOpenRedirectTestsAsync", "RunOAuthRedirectUriValidationTestsAsync" }),
        ("CWE-918", new[] { "RunSsrfTestsAsync", "RunAdvancedSsrfEncodingTestsAsync", "RunCloudMetadataImdsV2TestsAsync", "RunEgressFilteringTestsAsync" }),
        ("CWE-444", new[] { "RunRequestSmugglingSignalTestsAsync", "RunHttpClTeDesyncTestsAsync", "RunHttpTeClDesyncTestsAsync", "RunDualContentLengthTestsAsync" }),
        ("CWE-319", new[] { "RunTlsPostureTestsAsync", "RunTransportSecurityTestsAsync" }),
        ("CWE-295", new[] { "RunCertificateTrustChainTestsAsync", "RunTlsPostureTestsAsync", "RunTransportSecurityTestsAsync", "RunMtlsRequiredTestsAsync" }),
        ("CWE-614", new[] { "RunCookieSecurityFlagTestsAsync" }),
        ("CWE-525", new[] { "RunCacheControlTestsAsync", "RunInformationDisclosureTestsAsync" }),
        ("CWE-346", new[] { "RunHostHeaderInjectionTestsAsync", "RunDnsRebindingTestsAsync" }),
        ("CWE-345", new[] { "RunCertificateTrustChainTestsAsync", "RunJwtJkuRemoteKeyTestsAsync", "RunJwtX5uHeaderInjectionTestsAsync", "RunJwksEndpointPoisoningTestsAsync" }),
        ("CWE-16", new[] { "RunSecurityHeaderTestsAsync", "RunCorsTestsAsync", "RunHttpMethodTestsAsync", "RunSecurityMisconfigurationTestsAsync" }),
        ("CWE-285", new[] { "RunBrokenObjectPropertyLevelAuthTestsAsync", "RunMethodOverrideTestsAsync", "RunHeaderOverrideTestsAsync" }),
        ("CWE-294", new[] { "RunIdempotencyReplayTestsAsync", "RunTokenInQueryTestsAsync" }),
        ("CWE-841", new[] { "RunWorkflowStepSkippingTestsAsync", "RunWorkflowDuplicateTransitionTestsAsync", "RunCouponCreditExhaustionTestsAsync" }),
        ("CWE-1284", new[] { "RunNumericalOverflowUnderflowTestsAsync", "RunCouponCreditExhaustionTestsAsync" }),
        ("CWE-400", new[] { "RunTokenParserFuzzTestsAsync", "RunApiInventoryManagementTestsAsync" }),
        ("CWE-20", new[] { "RunOpenApiSchemaMismatchTestsAsync", "RunApiInventoryManagementTestsAsync" }),
        ("CWE-444", new[] { "RunDuplicateHeaderTestsAsync", "RunHttp2DowngradeSignalTestsAsync" }),
        ("CWE-287", new[] { "RunMtlsEndpointExposureTestsAsync", "RunMtlsRequiredTestsAsync" }),
        ("CWE-200", new[] { "RunInformationDisclosureTestsAsync", "RunErrorHandlingLeakageTestsAsync", "RunApiVersionDiscoveryTestsAsync" }),
        ("CWE-287", new[] { "RunAuthAndAccessControlTestsAsync", "RunJwtMalformedTokenTestsAsync", "RunTokenInQueryTestsAsync" }),
        ("CWE-352", new[] { "RunCsrfProtectionTestsAsync", "RunOidcStateReplayTestsAsync", "RunOAuthPkceEnforcementTestsAsync" }),
        ("CWE-307", new[] { "RunAuthBruteforceResistanceTestsAsync", "RunRateLimitTestsAsync" }),
        ("CWE-306", new[] { "RunDockerContainerExposureTestsAsync", "RunAuthAndAccessControlTestsAsync" }),
        ("CWE-1188", new[] { "RunDockerContainerExposureTestsAsync", "RunApiInventoryManagementTestsAsync" }),
        ("CWE-1021", new[] { "RunClickjackingHeaderTestsAsync", "RunCspHeaderTestsAsync" }),
        ("CWE-693", new[] { "RunCspHeaderTestsAsync", "RunClickjackingHeaderTestsAsync", "RunSecurityHeaderTestsAsync" }),
        ("CWE-79", new[] { "RunDomXssSignalTestsAsync", "RunXssTestsAsync" }),
        ("CWE-346", new[] { "RunSubdomainTakeoverSignalTestsAsync", "RunDnsRebindingTestsAsync" }),
        ("CWE-200", new[] { "RunEnvFileExposureTestsAsync", "RunCloudPublicStorageExposureTestsAsync", "RunInformationDisclosureTestsAsync" }),
        ("CWE-284", new[] { "RunCloudPublicStorageExposureTestsAsync", "RunAuthAndAccessControlTestsAsync" }),
        ("CWE-16", new[] { "RunPortServiceFingerprintTestsAsync", "RunSecurityMisconfigurationTestsAsync" }),
        ("CWE-940", new[] { "RunMobileDeepLinkHijackingTestsAsync", "RunOAuthRedirectUriValidationTestsAsync" }),
        ("CWE-319", new[] { "RunMobileCertificatePinningSignalTestsAsync", "RunTransportSecurityTestsAsync" }),
        ("CWE-312", new[] { "RunMobileLocalStorageSensitivityTestsAsync", "RunInformationDisclosureTestsAsync" })
    };

    private static readonly (string Needle, string[] Functions)[] DescriptionRules =
    {
        ("ssrf", new[] { "RunSsrfTestsAsync", "RunAdvancedSsrfEncodingTestsAsync", "RunCloudMetadataImdsV2TestsAsync", "RunEgressFilteringTestsAsync" }),
        ("server-side request forgery", new[] { "RunSsrfTestsAsync", "RunAdvancedSsrfEncodingTestsAsync" }),
        ("sql injection", new[] { "RunSqlInjectionTestsAsync" }),
        ("cross-site scripting", new[] { "RunXssTestsAsync" }),
        ("xss", new[] { "RunXssTestsAsync" }),
        ("command injection", new[] { "RunCommandInjectionTestsAsync" }),
        ("xxe", new[] { "RunXxeProbeTestsAsync", "RunXmlEntityExpansionTestsAsync" }),
        ("deserialization", new[] { "RunJsonDeserializationAbuseTestsAsync" }),
        ("template injection", new[] { "RunSstiProbeTestsAsync" }),
        ("request smuggling", new[] { "RunRequestSmugglingSignalTestsAsync", "RunHttpClTeDesyncTestsAsync", "RunHttpTeClDesyncTestsAsync", "RunDualContentLengthTestsAsync" }),
        ("websocket", new[] { "RunWebSocketAuthTestsAsync", "RunWebSocketMessageInjectionTestsAsync", "RunWebSocketFragmentationTestsAsync" }),
        ("graphql", new[] { "RunGraphQlIntrospectionTestsAsync", "RunGraphQlDepthBombTestsAsync", "RunGraphQlComplexityTestsAsync" }),
        ("grpc", new[] { "RunGrpcReflectionTestsAsync", "RunGrpcMetadataAbuseTestsAsync", "RunGrpcProtobufFuzzingTestsAsync" }),
        ("jwt", new[] { "RunJwtNoneAlgorithmTestsAsync", "RunJwtMalformedTokenTestsAsync", "RunJwtExpiredTokenTestsAsync", "RunJwtMissingClaimsTestsAsync", "RunJwtKidHeaderInjectionTestsAsync", "RunJwtJkuRemoteKeyTestsAsync", "RunJwtX5uHeaderInjectionTestsAsync", "RunJwtRsHsConfusionTestsAsync", "RunJwksEndpointPoisoningTestsAsync" }),
        ("oauth", new[] { "RunOAuthRedirectUriValidationTestsAsync", "RunOAuthPkceEnforcementTestsAsync", "RunOAuthRefreshTokenTestsAsync", "RunOAuthGrantTypeMisuseTestsAsync", "RunOAuthScopeEscalationTestsAsync" }),
        ("openid", new[] { "RunOidcDiscoveryHijackingTestsAsync", "RunOidcStateReplayTestsAsync", "RunOidcNonceReplayTestsAsync", "RunOidcIssuerValidationTestsAsync", "RunOidcAudienceValidationTestsAsync", "RunOidcTokenSubstitutionTestsAsync" }),
        ("rate limit", new[] { "RunRateLimitTestsAsync", "RunRateLimitEvasionTestsAsync" }),
        ("denial of service", new[] { "RunRateLimitTestsAsync", "RunLargePayloadAbuseTestsAsync", "RunDeepJsonNestingTestsAsync" }),
        ("path traversal", new[] { "RunPathTraversalTestsAsync" }),
        ("open redirect", new[] { "RunOpenRedirectTestsAsync" }),
        ("host header", new[] { "RunHostHeaderInjectionTestsAsync" }),
        ("file upload", new[] { "RunFileUploadValidationTestsAsync" }),
        ("timing", new[] { "RunSideChannelTimingTestsAsync" })
        ,
        ("cors", new[] { "RunCorsTestsAsync" }),
        ("security header", new[] { "RunSecurityHeaderTestsAsync", "RunSecurityMisconfigurationTestsAsync" }),
        ("hsts", new[] { "RunSecurityHeaderTestsAsync", "RunTlsPostureTestsAsync" }),
        ("cookie", new[] { "RunCookieSecurityFlagTestsAsync", "RunCacheControlTestsAsync" }),
        ("cache", new[] { "RunCacheControlTestsAsync" }),
        ("inventory", new[] { "RunApiInventoryManagementTestsAsync", "RunApiVersionDiscoveryTestsAsync", "RunUnsafeApiConsumptionTestsAsync" }),
        ("api discovery", new[] { "RunApiInventoryManagementTestsAsync", "RunApiVersionDiscoveryTestsAsync" }),
        ("openapi", new[] { "RunOpenApiSchemaMismatchTestsAsync", "RunApiInventoryManagementTestsAsync" }),
        ("schema", new[] { "RunOpenApiSchemaMismatchTestsAsync" }),
        ("authorization bypass", new[] { "RunHeaderOverrideTestsAsync", "RunMethodOverrideTestsAsync", "RunBrokenObjectPropertyLevelAuthTestsAsync" }),
        ("duplicate header", new[] { "RunDuplicateHeaderTestsAsync", "RunHeaderOverrideTestsAsync" }),
        ("method override", new[] { "RunMethodOverrideTestsAsync", "RunVerbTamperingTestsAsync", "RunHttpMethodTestsAsync" }),
        ("http method", new[] { "RunHttpMethodTestsAsync", "RunVerbTamperingTestsAsync" }),
        ("replay", new[] { "RunIdempotencyReplayTestsAsync", "RunWorkflowDuplicateTransitionTestsAsync", "RunTokenInQueryTestsAsync" }),
        ("workflow", new[] { "RunWorkflowStepSkippingTestsAsync", "RunWorkflowDuplicateTransitionTestsAsync", "RunWorkflowToctouRaceTestsAsync" }),
        ("business logic", new[] { "RunCouponCreditExhaustionTestsAsync", "RunNumericalOverflowUnderflowTestsAsync", "RunWorkflowStepSkippingTestsAsync" }),
        ("coupon", new[] { "RunCouponCreditExhaustionTestsAsync", "RunNumericalOverflowUnderflowTestsAsync" }),
        ("credit", new[] { "RunCouponCreditExhaustionTestsAsync", "RunNumericalOverflowUnderflowTestsAsync" }),
        ("overflow", new[] { "RunNumericalOverflowUnderflowTestsAsync" }),
        ("underflow", new[] { "RunNumericalOverflowUnderflowTestsAsync" }),
        ("dns rebinding", new[] { "RunDnsRebindingTestsAsync", "RunHostHeaderInjectionTestsAsync" }),
        ("certificate", new[] { "RunCertificateTrustChainTestsAsync", "RunMtlsRequiredTestsAsync" }),
        ("mtls", new[] { "RunMtlsRequiredTestsAsync", "RunMtlsEndpointExposureTestsAsync" }),
        ("client certificate", new[] { "RunMtlsRequiredTestsAsync", "RunCertificateTrustChainTestsAsync" }),
        ("http/2", new[] { "RunHttp2DowngradeSignalTestsAsync", "RunRequestSmugglingSignalTestsAsync" }),
        ("desync", new[] { "RunHttp2DowngradeSignalTestsAsync", "RunHttpClTeDesyncTestsAsync", "RunHttpTeClDesyncTestsAsync" }),
        ("token in query", new[] { "RunTokenInQueryTestsAsync" }),
        ("token parser", new[] { "RunTokenParserFuzzTestsAsync" }),
        ("fuzz", new[] { "RunTokenParserFuzzTestsAsync", "RunGrpcProtobufFuzzingTestsAsync" }),
        ("llm", new[] { "RunLlmPromptInjectionTestsAsync" }),
        ("prompt injection", new[] { "RunLlmPromptInjectionTestsAsync" }),
        ("unsafe consumption", new[] { "RunUnsafeApiConsumptionTestsAsync", "RunSsrfTestsAsync" }),
        ("csrf", new[] { "RunCsrfProtectionTestsAsync", "RunOidcStateReplayTestsAsync" }),
        ("cross-site request forgery", new[] { "RunCsrfProtectionTestsAsync" }),
        ("brute force", new[] { "RunAuthBruteforceResistanceTestsAsync", "RunRateLimitTestsAsync" }),
        ("credential stuffing", new[] { "RunAuthBruteforceResistanceTestsAsync", "RunRateLimitEvasionTestsAsync" }),
        ("password spraying", new[] { "RunAuthBruteforceResistanceTestsAsync" }),
        ("docker", new[] { "RunDockerContainerExposureTestsAsync", "RunApiInventoryManagementTestsAsync" }),
        ("dockerd", new[] { "RunDockerContainerExposureTestsAsync" }),
        ("container", new[] { "RunDockerContainerExposureTestsAsync", "RunApiInventoryManagementTestsAsync" }),
        ("containerd", new[] { "RunDockerContainerExposureTestsAsync" }),
        ("kubernetes", new[] { "RunDockerContainerExposureTestsAsync", "RunApiInventoryManagementTestsAsync" }),
        ("kubelet", new[] { "RunDockerContainerExposureTestsAsync", "RunApiInventoryManagementTestsAsync" }),
        ("port scan", new[] { "RunPortServiceFingerprintTestsAsync", "RunSecurityMisconfigurationTestsAsync" }),
        ("service fingerprint", new[] { "RunPortServiceFingerprintTestsAsync" }),
        ("public bucket", new[] { "RunCloudPublicStorageExposureTestsAsync", "RunInformationDisclosureTestsAsync" }),
        ("s3 bucket", new[] { "RunCloudPublicStorageExposureTestsAsync" }),
        ("blob storage", new[] { "RunCloudPublicStorageExposureTestsAsync" }),
        ("env file", new[] { "RunEnvFileExposureTestsAsync" }),
        (".env", new[] { "RunEnvFileExposureTestsAsync", "RunInformationDisclosureTestsAsync" }),
        ("subdomain takeover", new[] { "RunSubdomainTakeoverSignalTestsAsync", "RunDnsRebindingTestsAsync" }),
        ("content security policy", new[] { "RunCspHeaderTestsAsync", "RunSecurityHeaderTestsAsync" }),
        ("csp", new[] { "RunCspHeaderTestsAsync" }),
        ("clickjacking", new[] { "RunClickjackingHeaderTestsAsync", "RunCspHeaderTestsAsync" }),
        ("frame-ancestors", new[] { "RunClickjackingHeaderTestsAsync", "RunCspHeaderTestsAsync" }),
        ("x-frame-options", new[] { "RunClickjackingHeaderTestsAsync" }),
        ("dom-based xss", new[] { "RunDomXssSignalTestsAsync", "RunXssTestsAsync" }),
        ("dom xss", new[] { "RunDomXssSignalTestsAsync", "RunXssTestsAsync" }),
        ("third-party script", new[] { "RunThirdPartyScriptInventoryTestsAsync", "RunCspHeaderTestsAsync" }),
        ("supply chain", new[] { "RunThirdPartyScriptInventoryTestsAsync" }),
        ("certificate pinning", new[] { "RunMobileCertificatePinningSignalTestsAsync", "RunTlsPostureTestsAsync" }),
        ("sharedpreferences", new[] { "RunMobileLocalStorageSensitivityTestsAsync" }),
        ("keychain", new[] { "RunMobileLocalStorageSensitivityTestsAsync" }),
        ("deep link", new[] { "RunMobileDeepLinkHijackingTestsAsync", "RunOAuthRedirectUriValidationTestsAsync" }),
        ("deeplink", new[] { "RunMobileDeepLinkHijackingTestsAsync" }),
        ("assetlinks", new[] { "RunMobileDeepLinkHijackingTestsAsync" }),
        ("app-site-association", new[] { "RunMobileDeepLinkHijackingTestsAsync" })
    };

    public static IReadOnlyList<string> MapToFunctions(CveRecord record) =>
        MapWithDiagnostics(record).Functions;

    public static (IReadOnlyList<string> Functions, string Confidence, IReadOnlyList<string> Signals) MapWithDiagnostics(CveRecord record)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        var signals = new List<string>();
        var cweHits = 0;
        var descHits = 0;
        var heuristicHits = 0;

        var cwe = record.Cwe ?? string.Empty;
        var description = record.Description ?? string.Empty;
        var lowerDescription = description.ToLowerInvariant();

        foreach (var (needle, functions) in CweRules)
        {
            if (cwe.Contains(needle, StringComparison.OrdinalIgnoreCase))
            {
                cweHits++;
                signals.Add($"cwe:{needle}");
                foreach (var function in functions)
                {
                    result.Add(function);
                }
            }
        }

        foreach (var (needle, functions) in DescriptionRules)
        {
            if (lowerDescription.Contains(needle, StringComparison.Ordinal))
            {
                descHits++;
                signals.Add($"desc:{needle}");
                foreach (var function in functions)
                {
                    result.Add(function);
                }
            }
        }

        // Broader heuristics to reduce fallback-only mappings when CVE text is generic or CWE is missing.
        if (ContainsAny(lowerDescription, InputAbuseKeywords))
        {
            heuristicHits++;
            signals.Add("heuristic:input-abuse");
            result.Add("RunContentTypeValidationTestsAsync");
            result.Add("RunParameterPollutionTestsAsync");
            result.Add("RunTokenParserFuzzTestsAsync");
            result.Add("RunOpenApiSchemaMismatchTestsAsync");
        }

        if (ContainsAny(lowerDescription, AuthzAuthnKeywords))
        {
            heuristicHits++;
            signals.Add("heuristic:authz-authn");
            result.Add("RunAuthAndAccessControlTestsAsync");
            result.Add("RunPrivilegeEscalationTestsAsync");
            result.Add("RunBolaTestsAsync");
            result.Add("RunJwtMalformedTokenTestsAsync");
        }

        if (ContainsAny(lowerDescription, ExposureKeywords))
        {
            heuristicHits++;
            signals.Add("heuristic:exposure");
            result.Add("RunInformationDisclosureTestsAsync");
            result.Add("RunErrorHandlingLeakageTestsAsync");
            result.Add("RunSecurityHeaderTestsAsync");
        }

        if (ContainsAny(lowerDescription, TraversalRedirectKeywords))
        {
            heuristicHits++;
            signals.Add("heuristic:traversal-redirect");
            result.Add("RunPathTraversalTestsAsync");
            result.Add("RunOpenRedirectTestsAsync");
        }

        if (ContainsAny(lowerDescription, ProtocolDosKeywords))
        {
            heuristicHits++;
            signals.Add("heuristic:protocol-dos");
            result.Add("RunRateLimitTestsAsync");
            result.Add("RunLargePayloadAbuseTestsAsync");
            result.Add("RunDeepJsonNestingTestsAsync");
            result.Add("RunRequestSmugglingSignalTestsAsync");
        }

        if (ContainsAny(lowerDescription, CryptoTransportKeywords))
        {
            heuristicHits++;
            signals.Add("heuristic:crypto-transport");
            result.Add("RunTlsPostureTestsAsync");
            result.Add("RunTransportSecurityTestsAsync");
            result.Add("RunCertificateTrustChainTestsAsync");
            result.Add("RunJwtRsHsConfusionTestsAsync");
        }

        if (ContainsAny(lowerDescription, BrowserClientKeywords))
        {
            heuristicHits++;
            signals.Add("heuristic:browser-client");
            result.Add("RunCspHeaderTestsAsync");
            result.Add("RunClickjackingHeaderTestsAsync");
            result.Add("RunDomXssSignalTestsAsync");
            result.Add("RunThirdPartyScriptInventoryTestsAsync");
        }

        if (ContainsAny(lowerDescription, NetworkInfraKeywords))
        {
            heuristicHits++;
            signals.Add("heuristic:network-infra");
            result.Add("RunPortServiceFingerprintTestsAsync");
            result.Add("RunCloudPublicStorageExposureTestsAsync");
            result.Add("RunEnvFileExposureTestsAsync");
            result.Add("RunSubdomainTakeoverSignalTestsAsync");
            result.Add("RunEgressFilteringTestsAsync");
        }

        if (ContainsAny(lowerDescription, MobileKeywords))
        {
            heuristicHits++;
            signals.Add("heuristic:mobile");
            result.Add("RunMobileCertificatePinningSignalTestsAsync");
            result.Add("RunMobileLocalStorageSensitivityTestsAsync");
            result.Add("RunMobileDeepLinkHijackingTestsAsync");
        }

        // Baseline fallback so every CVE has at least a defensive validation path.
        if (result.Count == 0)
        {
            result.Add("RunSecurityMisconfigurationTestsAsync");
            result.Add("RunInformationDisclosureTestsAsync");
            result.Add("RunAuthAndAccessControlTestsAsync");
            signals.Add("fallback:baseline");
        }

        var confidence = cweHits > 0
            ? "high"
            : descHits > 0
                ? "medium"
                : "low";

        return (result.OrderBy(x => x, StringComparer.Ordinal).ToArray(), confidence, signals.Distinct(StringComparer.Ordinal).ToArray());
    }

    public static double ConfidenceToScore(string confidence) =>
        confidence switch
        {
            "high" => 0.78,
            "medium" => 0.60,
            _ => 0.42
        };

    public static double CalculatePerformanceConfidenceScore(
        string confidence,
        IReadOnlyList<string> functions,
        IReadOnlyList<string> signals)
    {
        var baseScore = ConfidenceToScore(confidence);
        var cweSignals = signals.Count(s => s.StartsWith("cwe:", StringComparison.Ordinal));
        var descSignals = signals.Count(s => s.StartsWith("desc:", StringComparison.Ordinal));
        var fallback = signals.Any(s => s.Equals("fallback:baseline", StringComparison.Ordinal));

        var knownWeights = functions
            .Select(f => FunctionEffectiveness.TryGetValue(f, out var w) ? w : 0.70)
            .ToList();
        var avgFunctionQuality = knownWeights.Count == 0 ? 0.70 : knownWeights.Average();

        var signalBoost = Math.Min(cweSignals * 0.04, 0.16) + Math.Min(descSignals * 0.02, 0.10);
        var breadthBoost = Math.Min(functions.Count, 8) * 0.01;
        var fallbackPenalty = fallback ? 0.15 : 0.0;

        var score = (baseScore * 0.45) + (avgFunctionQuality * 0.55) + signalBoost + breadthBoost - fallbackPenalty;
        return Math.Clamp(Math.Round(score, 4), 0.20, 0.98);
    }

    public static string BuildDefaultSettingsProfile(IReadOnlyList<string> functions)
    {
        var set = new HashSet<string>(functions, StringComparer.Ordinal);

        var isConcurrencyHeavy = set.Any(f =>
            f.Contains("Race", StringComparison.Ordinal) ||
            f.Contains("RateLimit", StringComparison.Ordinal) ||
            f.Contains("Workflow", StringComparison.Ordinal) ||
            f.Contains("Bruteforce", StringComparison.Ordinal));

        var isPayloadHeavy = set.Any(f =>
            f.Contains("LargePayload", StringComparison.Ordinal) ||
            f.Contains("DeepJson", StringComparison.Ordinal) ||
            f.Contains("GraphQlComplexity", StringComparison.Ordinal) ||
            f.Contains("GraphQlDepth", StringComparison.Ordinal));

        var mode = isConcurrencyHeavy ? "cautious" : "balanced";
        var maxRequests = isConcurrencyHeavy ? 14 : 8;
        var maxPayloadKb = isPayloadHeavy ? 640 : 320;

        return $"mode={mode};timeoutSeconds=20;maxRequestsPerTest={maxRequests};sameOriginOnly=true;maxSpiderDepth=3;maxPayloadKb={maxPayloadKb};followExternalLinks=false";
    }

    public static double CalculateDefaultSettingsPreventionScore(double confidenceScore, IReadOnlyList<string> functions)
    {
        var set = new HashSet<string>(functions, StringComparer.Ordinal);
        var baseScore = confidenceScore * 100.0;
        var breadthBoost = Math.Min(set.Count, 8) * 2.5;
        var hasAuthCoverage = set.Any(f => f.Contains("Auth", StringComparison.Ordinal) || f.Contains("Jwt", StringComparison.Ordinal) || f.Contains("OAuth", StringComparison.Ordinal));
        var hasInjectionCoverage = set.Any(f => f.Contains("Injection", StringComparison.Ordinal) || f.Contains("Sql", StringComparison.Ordinal) || f.Contains("Xss", StringComparison.Ordinal));
        var hasTransportCoverage = set.Any(f => f.Contains("Tls", StringComparison.Ordinal) || f.Contains("Transport", StringComparison.Ordinal) || f.Contains("Header", StringComparison.Ordinal));
        var categoryBoost = (hasAuthCoverage ? 4.0 : 0.0) + (hasInjectionCoverage ? 4.0 : 0.0) + (hasTransportCoverage ? 4.0 : 0.0);

        // Penalize likely fallback-only mappings.
        var baselineOnly = set.SetEquals(new[]
        {
            "RunSecurityMisconfigurationTestsAsync",
            "RunInformationDisclosureTestsAsync",
            "RunAuthAndAccessControlTestsAsync"
        });
        var penalty = baselineOnly ? 18.0 : 0.0;

        var score = baseScore + breadthBoost + categoryBoost - penalty;
        return Math.Clamp(Math.Round(score, 2), 15.0, 98.0);
    }

    public static double CalculateRealWorldCoverageScore(
        string confidence,
        double confidenceScore,
        double defaultSettingsPreventionScore,
        IReadOnlyList<string> functions,
        IReadOnlyList<string> signals,
        string defaultSettings)
    {
        var confidenceEvidence = confidence switch
        {
            "high" => 0.88,
            "medium" => 0.68,
            _ => 0.46
        };

        var quality = functions
            .Select(f => FunctionEffectiveness.TryGetValue(f, out var w) ? w : 0.68)
            .DefaultIfEmpty(0.68)
            .Average();

        var baselineOnly = new HashSet<string>(functions, StringComparer.Ordinal)
            .SetEquals(new[]
            {
                "RunSecurityMisconfigurationTestsAsync",
                "RunInformationDisclosureTestsAsync",
                "RunAuthAndAccessControlTestsAsync"
            });

        var hasCweSignal = signals.Any(s => s.StartsWith("cwe:", StringComparison.Ordinal));
        var hasDescSignal = signals.Any(s => s.StartsWith("desc:", StringComparison.Ordinal));
        var heuristicOnly = !hasCweSignal && !hasDescSignal && signals.Any(s => s.StartsWith("heuristic:", StringComparison.Ordinal));

        var settingsHardened =
            defaultSettings.Contains("sameOriginOnly=true", StringComparison.OrdinalIgnoreCase) &&
            defaultSettings.Contains("followExternalLinks=false", StringComparison.OrdinalIgnoreCase) &&
            defaultSettings.Contains("timeoutSeconds=", StringComparison.OrdinalIgnoreCase);

        var evidencePenalty = baselineOnly ? 0.22 : heuristicOnly ? 0.14 : 0.0;
        var settingsBoost = settingsHardened ? 0.03 : 0.0;
        var breadthBoost = Math.Min(functions.Count, 6) * 0.01;

        var preventionNorm = Math.Clamp(defaultSettingsPreventionScore / 100.0, 0.0, 1.0);
        var fused = (confidenceScore * 0.32) + (confidenceEvidence * 0.26) + (quality * 0.22) + (preventionNorm * 0.20);
        var adjusted = Math.Clamp(fused + settingsBoost + breadthBoost - evidencePenalty, 0.18, 0.98);
        return Math.Round(adjusted * 100.0, 2);
    }

    public static string ToDetectionLabel(string confidence) =>
        confidence switch
        {
            "high" => "Detected CVE mapping: HIGH confidence",
            "medium" => "Detected CVE mapping: MEDIUM confidence",
            _ => "Detected CVE mapping: LOW confidence (fallback/broad mapping)"
        };

    private static bool ContainsAny(string input, IEnumerable<string> needles)
    {
        foreach (var needle in needles)
        {
            if (input.Contains(needle, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
