using System.Text.RegularExpressions;
using System.Text.Json;

namespace API_Tester.SecurityCatalog;

public static class CveCoverageMapper
{
    private static readonly Lazy<IReadOnlyDictionary<string, double>> CodeDerivedFunctionEffectiveness =
    new(BuildCodeDerivedFunctionEffectiveness);
    private static readonly Lazy<CalibrationModel?> Calibration =
    new(LoadCalibrationModel);

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
        ["RunMITREATTampCKFrameworkSsrfTestsAsync"] = 0.86,
        ["RunAdvancedSsrfEncodingTestsAsync"] = 0.89,
        ["RunCloudMetadataImdsV2TestsAsync"] = 0.90,
        ["RunSqlInjectionTestsAsync"] = 0.88,
        ["RunXssTestsAsync"] = 0.84,
        ["RunCommandInjectionTestsAsync"] = 0.88,
        ["RunXxeProbeTestsAsync"] = 0.83,
        ["RunXmlEntityExpansionTestsAsync"] = 0.82,
        ["RunJsonDeserializationAbuseTestsAsync"] = 0.85,
        ["RunAuthAndAccessControlTestsAsync"] = 0.82,
        ["RunCMMCBolaTestsAsync"] = 0.87,
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
        ["RunDISASTIGSRGSecurityMisconfigurationTestsAsync"] = 0.72,
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
        ("CWE-639", new[] { "RunCMMCBolaTestsAsync", "RunAuthAndAccessControlTestsAsync" }),
        ("CWE-285", new[] { "RunPrivilegeEscalationTestsAsync", "RunAuthAndAccessControlTestsAsync", "RunVerbTamperingTestsAsync" }),
        ("CWE-362", new[] { "RunRaceConditionReplayTestsAsync", "RunWorkflowToctouRaceTestsAsync", "RunDoubleSpendToctouTestsAsync" }),
        ("CWE-915", new[] { "RunMassAssignmentTestsAsync" }),
        ("CWE-347", new[] { "RunJwtNoneAlgorithmTestsAsync", "RunJwtRsHsConfusionTestsAsync", "RunJwtKidHeaderInjectionTestsAsync" }),
        ("CWE-601", new[] { "RunOpenRedirectTestsAsync", "RunOAuthRedirectUriValidationTestsAsync" }),
        ("CWE-918", new[] { "RunMITREATTampCKFrameworkSsrfTestsAsync", "RunAdvancedSsrfEncodingTestsAsync", "RunCloudMetadataImdsV2TestsAsync", "RunEgressFilteringTestsAsync" }),
        ("CWE-444", new[] { "RunRequestSmugglingSignalTestsAsync", "RunHttpClTeDesyncTestsAsync", "RunHttpTeClDesyncTestsAsync", "RunDualContentLengthTestsAsync" }),
        ("CWE-319", new[] { "RunTlsPostureTestsAsync", "RunTransportSecurityTestsAsync" }),
        ("CWE-295", new[] { "RunCertificateTrustChainTestsAsync", "RunTlsPostureTestsAsync", "RunTransportSecurityTestsAsync", "RunMtlsRequiredTestsAsync" }),
        ("CWE-614", new[] { "RunCookieSecurityFlagTestsAsync" }),
        ("CWE-525", new[] { "RunCacheControlTestsAsync", "RunInformationDisclosureTestsAsync" }),
        ("CWE-346", new[] { "RunHostHeaderInjectionTestsAsync", "RunDnsRebindingTestsAsync" }),
        ("CWE-345", new[] { "RunCertificateTrustChainTestsAsync", "RunJwtJkuRemoteKeyTestsAsync", "RunJwtX5uHeaderInjectionTestsAsync", "RunJwksEndpointPoisoningTestsAsync" }),
        ("CWE-16", new[] { "RunSecurityHeaderTestsAsync", "RunCorsTestsAsync", "RunHttpMethodTestsAsync", "RunDISASTIGSRGSecurityMisconfigurationTestsAsync" }),
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
        ("CWE-16", new[] { "RunPortServiceFingerprintTestsAsync", "RunDISASTIGSRGSecurityMisconfigurationTestsAsync" }),
        ("CWE-940", new[] { "RunMobileDeepLinkHijackingTestsAsync", "RunOAuthRedirectUriValidationTestsAsync" }),
        ("CWE-319", new[] { "RunMobileCertificatePinningSignalTestsAsync", "RunTransportSecurityTestsAsync" }),
        ("CWE-312", new[] { "RunMobileLocalStorageSensitivityTestsAsync", "RunInformationDisclosureTestsAsync" })
    };

    private static readonly (string Needle, string[] Functions)[] DescriptionRules =
    {
        ("ssrf", new[] { "RunMITREATTampCKFrameworkSsrfTestsAsync", "RunAdvancedSsrfEncodingTestsAsync", "RunCloudMetadataImdsV2TestsAsync", "RunEgressFilteringTestsAsync" }),
        ("server-side request forgery", new[] { "RunMITREATTampCKFrameworkSsrfTestsAsync", "RunAdvancedSsrfEncodingTestsAsync" }),
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
        ("security header", new[] { "RunSecurityHeaderTestsAsync", "RunDISASTIGSRGSecurityMisconfigurationTestsAsync" }),
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
        ("unsafe consumption", new[] { "RunUnsafeApiConsumptionTestsAsync", "RunMITREATTampCKFrameworkSsrfTestsAsync" }),
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
        ("port scan", new[] { "RunPortServiceFingerprintTestsAsync", "RunDISASTIGSRGSecurityMisconfigurationTestsAsync" }),
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
            result.Add("RunCMMCBolaTestsAsync");
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
            result.Add("RunDISASTIGSRGSecurityMisconfigurationTestsAsync");
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
        .Select(GetEffectiveFunctionWeight)
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
            "RunDISASTIGSRGSecurityMisconfigurationTestsAsync",
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

        var codeAppliedCoverage = CalculateAppliedCodeCoverageScore(functions, signals, confidence);

        var baselineOnly = new HashSet<string>(functions, StringComparer.Ordinal)
        .SetEquals(new[]
        {
            "RunDISASTIGSRGSecurityMisconfigurationTestsAsync",
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
        // Prioritize concrete test-code application; use mapping confidence as a secondary stabilizer.
        var fused = (codeAppliedCoverage * 0.50) + (confidenceScore * 0.22) + (confidenceEvidence * 0.14) + (preventionNorm * 0.14);
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

    private static double GetEffectiveFunctionWeight(string functionName)
    {
        var configured = FunctionEffectiveness.TryGetValue(functionName, out var configuredWeight)
        ? configuredWeight
        : 0.70;
        var merged = configured;

        if (CodeDerivedFunctionEffectiveness.Value.TryGetValue(functionName, out var codeDerived))
        {
            // Favor measured code characteristics while keeping configured weights as a stabilizer.
            merged = Math.Clamp(Math.Round((configured * 0.35) + (codeDerived * 0.65), 4), 0.55, 0.96);
        }

        if (Calibration.Value is not null &&
        Calibration.Value.Functions.TryGetValue(functionName, out var functionStats))
        {
            // Bayesian-style shrinkage: empirical performance gets more influence as sample count rises.
            var empiricalBlend = Math.Clamp(functionStats.Samples / (functionStats.Samples + 40.0), 0.0, 0.70);
            merged = (merged * (1.0 - empiricalBlend)) + (functionStats.SuccessRate * empiricalBlend);
        }

        return Math.Clamp(Math.Round(merged, 4), 0.50, 0.96);
    }

    private static IReadOnlyDictionary<string, double> BuildCodeDerivedFunctionEffectiveness()
    {
        var sourcePath = TryResolveMainPageSourcePath();
        if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
        {
            return new Dictionary<string, double>(StringComparer.Ordinal);
        }

        string source;
        try
        {
            source = File.ReadAllText(sourcePath);
        }
        catch
        {
            return new Dictionary<string, double>(StringComparer.Ordinal);
        }

        var methods = ExtractRunTestMethodBodies(source);
        if (methods.Count == 0)
        {
            return new Dictionary<string, double>(StringComparer.Ordinal);
        }

        var scores = new Dictionary<string, double>(StringComparer.Ordinal);
        foreach (var kv in methods)
        {
            scores[kv.Key] = ComputeCodeDerivedWeight(kv.Value);
        }

        return scores;
    }

    private static string? TryResolveMainPageSourcePath()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 14 && current is not null; i++)
        {
            var direct = Path.Combine(current.FullName, "MainPage.xaml.cs");
            if (File.Exists(direct))
            {
                return direct;
            }

            var nested = Path.Combine(current.FullName, "API_Tester", "MainPage.xaml.cs");
            if (File.Exists(nested))
            {
                return nested;
            }

            current = current.Parent;
        }

        return null;
    }

    private static Dictionary<string, string> ExtractRunTestMethodBodies(string source)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var methodPattern = new Regex(
        @"private\s+async\s+Task<string>\s+(Run[A-Za-z0-9_]+TestsAsync)\s*\([^)]*\)\s*\{",
            RegexOptions.Compiled);

        foreach (Match match in methodPattern.Matches(source))
        {
            if (match.Groups.Count < 2)
            {
                continue;
            }

            var methodName = match.Groups[1].Value;
            var openBraceIndex = source.IndexOf('{', match.Index);
            if (openBraceIndex < 0)
            {
                continue;
            }

            var closeBraceIndex = FindMatchingBrace(source, openBraceIndex);
            if (closeBraceIndex <= openBraceIndex)
            {
                continue;
            }

            var body = source.Substring(openBraceIndex + 1, closeBraceIndex - openBraceIndex - 1);
            result[methodName] = body;
        }

        return result;
    }

    private static int FindMatchingBrace(string text, int openBraceIndex)
    {
        var depth = 0;
        for (var i = openBraceIndex; i < text.Length; i++)
        {
            if (text[i] == '{')
            {
                depth++;
            }
            else if (text[i] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }
        }

        return -1;
    }

    private static double ComputeCodeDerivedWeight(string body)
    {
        var safeSendCalls = CountOccurrences(body, "SafeSendAsync(");
        var appendQueryCalls = CountOccurrences(body, "AppendQuery(");
        var findingsAdds = CountOccurrences(body, "findings.Add(");
        var conditionals = CountOccurrences(body, "if (");
        var catches = CountOccurrences(body, "catch");

        var httpMethodSet = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match match in Regex.Matches(body, @"HttpMethod\.(Get|Post|Put|Delete|Patch|Head|Options)"))
        {
            if (match.Groups.Count > 1)
            {
                httpMethodSet.Add(match.Groups[1].Value);
            }
        }

        var analysisSignals = 0;
        if (body.Contains("TryGetHeader(", StringComparison.Ordinal)) analysisSignals++;
        if (body.Contains("ContainsAny(", StringComparison.Ordinal)) analysisSignals++;
        if (body.Contains("Regex(", StringComparison.Ordinal)) analysisSignals++;
        if (body.Contains("Json", StringComparison.Ordinal)) analysisSignals++;
        if (body.Contains("UriBuilder", StringComparison.Ordinal)) analysisSignals++;
        if (body.Contains("ReadBodyAsync(", StringComparison.Ordinal)) analysisSignals++;

        var baseWeight = 0.56;
        var probeDepth = Math.Min(safeSendCalls + appendQueryCalls, 8) * 0.035;
        var evidenceDepth = Math.Min(findingsAdds, 10) * 0.015;
        var branchDepth = Math.Min(conditionals + catches, 12) * 0.008;
        var methodBreadth = Math.Min(httpMethodSet.Count, 4) * 0.02;
        var analysisDepth = Math.Min(analysisSignals, 6) * 0.02;

        var computed = baseWeight + probeDepth + evidenceDepth + branchDepth + methodBreadth + analysisDepth;
        return Math.Clamp(Math.Round(computed, 4), 0.55, 0.95);
    }

    private static int CountOccurrences(string text, string token)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(token))
        {
            return 0;
        }

        var count = 0;
        var index = 0;
        while (true)
        {
            index = text.IndexOf(token, index, StringComparison.Ordinal);
            if (index < 0)
            {
                break;
            }

            count++;
            index += token.Length;
        }

        return count;
    }

    private static double CalculateAppliedCodeCoverageScore(
    IReadOnlyList<string> functions,
    IReadOnlyList<string> signals,
    string confidence)
    {
        if (functions.Count == 0)
        {
            return 0.28;
        }

        var baselineOnly = new HashSet<string>(functions, StringComparer.Ordinal)
        .SetEquals(new[]
        {
                    "RunDISASTIGSRGSecurityMisconfigurationTestsAsync",
                    "RunInformationDisclosureTestsAsync",
                    "RunAuthAndAccessControlTestsAsync"
        });

        var weights = functions
        .Select(GetEffectiveFunctionWeight)
        .OrderByDescending(x => x)
        .ToArray();

        // Diminishing returns: additional tests add value, but less than the primary targeted test.
        var diminishing = new[] { 1.00, 0.72, 0.55, 0.42, 0.34, 0.28, 0.23, 0.19, 0.16, 0.14 };
        var weightedSum = 0.0;
        var weightNorm = 0.0;
        for (var i = 0; i < weights.Length; i++)
        {
            var f = i < diminishing.Length ? diminishing[i] : 0.12;
            weightedSum += weights[i] * f;
            weightNorm += f;
        }

        var precisionCore = weightNorm <= 0.0 ? 0.62 : (weightedSum / weightNorm);

        var categories = functions.Select(GetFunctionCategory).ToArray();
        var uniqueCategories = new HashSet<string>(categories, StringComparer.Ordinal);
        var categoryBreadthBoost = Math.Min(uniqueCategories.Count, 5) * 0.025;

        var redundancyPenalty = 0.0;
        foreach (var grp in categories.GroupBy(x => x, StringComparer.Ordinal))
        {
            if (grp.Count() > 2)
            {
                redundancyPenalty += Math.Min((grp.Count() - 2) * 0.02, 0.08);
            }
        }

        var hasCweSignal = signals.Any(s => s.StartsWith("cwe:", StringComparison.Ordinal));
        var hasDescSignal = signals.Any(s => s.StartsWith("desc:", StringComparison.Ordinal));
        var heuristics = signals.Count(s => s.StartsWith("heuristic:", StringComparison.Ordinal));
        var evidenceBoost = hasCweSignal ? 0.06 : hasDescSignal ? 0.03 : 0.0;
        var heuristicPenalty = !hasCweSignal && !hasDescSignal ? Math.Min(heuristics * 0.01, 0.04) : 0.0;
        var realismAdjustment = ComputeRealismAdjustment(functions, hasCweSignal, hasDescSignal);
        var domainAdjustment = ComputeDomainSpecificAdjustment(functions, hasCweSignal, hasDescSignal);
        var calibrationUncertaintyPenalty = ComputeCalibrationUncertaintyPenalty(functions);

        // Allow one very strong, precise test mapping to rank high when evidence supports it.
        var singleTestPrecisionBonus = functions.Count == 1 && (hasCweSignal || hasDescSignal) && weights[0] >= 0.84
        ? 0.06
        : 0.0;

        // Penalize broad bundles when evidence is weak (common source of inflated-looking scores).
        var broadWeakEvidencePenalty = functions.Count >= 5 && !hasCweSignal && !hasDescSignal
        ? 0.06
        : 0.0;

        var confidenceAdjustment = confidence switch
        {
            "high" => 0.02,
            "medium" => 0.0,
            _ => -0.015
        };

        var baselinePenalty = baselineOnly ? 0.22 : 0.0;

        var raw = precisionCore
        + categoryBreadthBoost
        + evidenceBoost
        + singleTestPrecisionBonus
        + confidenceAdjustment
        + realismAdjustment
        + domainAdjustment
        - redundancyPenalty
        - heuristicPenalty
        - broadWeakEvidencePenalty
        - calibrationUncertaintyPenalty
        - baselinePenalty;
        return Math.Clamp(Math.Round(raw, 4), 0.18, 0.98);
    }

    private static string GetFunctionCategory(string functionName)
    {
        if (functionName.Contains("Auth", StringComparison.Ordinal) ||
        functionName.Contains("Jwt", StringComparison.Ordinal) ||
        functionName.Contains("OAuth", StringComparison.Ordinal) ||
        functionName.Contains("Oidc", StringComparison.Ordinal) ||
        functionName.Contains("Bola", StringComparison.Ordinal) ||
        functionName.Contains("Privilege", StringComparison.Ordinal))
        {
            return "identity-access";
        }

        if (functionName.Contains("Sql", StringComparison.Ordinal) ||
        functionName.Contains("Xss", StringComparison.Ordinal) ||
        functionName.Contains("Injection", StringComparison.Ordinal) ||
        functionName.Contains("Xxe", StringComparison.Ordinal) ||
        functionName.Contains("Deserialization", StringComparison.Ordinal) ||
        functionName.Contains("Traversal", StringComparison.Ordinal))
        {
            return "input-injection";
        }

        if (functionName.Contains("Tls", StringComparison.Ordinal) ||
        functionName.Contains("Transport", StringComparison.Ordinal) ||
        functionName.Contains("Header", StringComparison.Ordinal) ||
        functionName.Contains("Cors", StringComparison.Ordinal) ||
        functionName.Contains("Certificate", StringComparison.Ordinal) ||
        functionName.Contains("Mtls", StringComparison.Ordinal))
        {
            return "transport-config";
        }

        if (functionName.Contains("Smuggling", StringComparison.Ordinal) ||
        functionName.Contains("RateLimit", StringComparison.Ordinal) ||
        functionName.Contains("GraphQl", StringComparison.Ordinal) ||
        functionName.Contains("Grpc", StringComparison.Ordinal) ||
        functionName.Contains("WebSocket", StringComparison.Ordinal) ||
        functionName.Contains("Payload", StringComparison.Ordinal))
        {
            return "protocol-abuse";
        }

        if (functionName.Contains("Docker", StringComparison.Ordinal) ||
        functionName.Contains("Port", StringComparison.Ordinal) ||
        functionName.Contains("Cloud", StringComparison.Ordinal) ||
        functionName.Contains("EnvFile", StringComparison.Ordinal) ||
        functionName.Contains("Subdomain", StringComparison.Ordinal))
        {
            return "infra-exposure";
        }

        if (functionName.Contains("Mobile", StringComparison.Ordinal) ||
        functionName.Contains("DeepLink", StringComparison.Ordinal) ||
        functionName.Contains("Pinning", StringComparison.Ordinal))
        {
            return "mobile-client";
        }

        return "general";
    }

    private static double ComputeRealismAdjustment(
    IReadOnlyList<string> functions,
    bool hasCweSignal,
    bool hasDescSignal)
    {
        var exploitDriven = 0;
        var passiveSignal = 0;
        var envDependent = 0;

        foreach (var function in functions)
        {
            if (IsExploitDrivenFunction(function))
            {
                exploitDriven++;
            }

            if (IsPassiveSignalFunction(function))
            {
                passiveSignal++;
            }

            if (IsEnvironmentDependentFunction(function))
            {
                envDependent++;
            }
        }

        var exploitBoost = Math.Min(exploitDriven * 0.012, 0.07);
        var passivePenalty = Math.Min(passiveSignal * 0.014, 0.08);
        var weakEvidence = !hasCweSignal && !hasDescSignal;
        var envPenalty = weakEvidence ? Math.Min(envDependent * 0.015, 0.07) : Math.Min(envDependent * 0.008, 0.04);

        return exploitBoost - passivePenalty - envPenalty;
    }

    private static bool IsExploitDrivenFunction(string functionName)
    {
        return functionName.Contains("Injection", StringComparison.Ordinal) ||
        functionName.Contains("Sql", StringComparison.Ordinal) ||
        functionName.Contains("Xss", StringComparison.Ordinal) ||
        functionName.Contains("Bola", StringComparison.Ordinal) ||
        functionName.Contains("Traversal", StringComparison.Ordinal) ||
        functionName.Contains("Desync", StringComparison.Ordinal) ||
        functionName.Contains("Smuggling", StringComparison.Ordinal) ||
        functionName.Contains("Jwt", StringComparison.Ordinal) ||
        functionName.Contains("OAuth", StringComparison.Ordinal) ||
        functionName.Contains("Oidc", StringComparison.Ordinal) ||
        functionName.Contains("Xxe", StringComparison.Ordinal) ||
        functionName.Contains("FileUpload", StringComparison.Ordinal) ||
        functionName.Contains("PrivilegeEscalation", StringComparison.Ordinal);
    }

    private static bool IsPassiveSignalFunction(string functionName)
    {
        return functionName.Contains("Signal", StringComparison.Ordinal) ||
        functionName.Contains("Inventory", StringComparison.Ordinal) ||
        functionName.Contains("Discovery", StringComparison.Ordinal) ||
        functionName.Contains("Fingerprint", StringComparison.Ordinal) ||
        functionName.Contains("Posture", StringComparison.Ordinal) ||
        functionName.Contains("Header", StringComparison.Ordinal) ||
        functionName.Contains("Exposure", StringComparison.Ordinal);
    }

    private static bool IsEnvironmentDependentFunction(string functionName)
    {
        return functionName.Contains("Docker", StringComparison.Ordinal) ||
        functionName.Contains("Cloud", StringComparison.Ordinal) ||
        functionName.Contains("Mobile", StringComparison.Ordinal) ||
        functionName.Contains("Mtls", StringComparison.Ordinal) ||
        functionName.Contains("Grpc", StringComparison.Ordinal) ||
        functionName.Contains("WebSocket", StringComparison.Ordinal);
    }

    private static double ComputeDomainSpecificAdjustment(
    IReadOnlyList<string> functions,
    bool hasCweSignal,
    bool hasDescSignal)
    {
        var hasStrongEvidence = hasCweSignal || hasDescSignal;

        // Cert/transport validation can be very high confidence when directly mapped.
        var certFamilyCount = functions.Count(f =>
        f.Contains("CertificateTrustChain", StringComparison.Ordinal) ||
        f.Contains("TlsPosture", StringComparison.Ordinal) ||
        f.Contains("TransportSecurity", StringComparison.Ordinal) ||
        f.Contains("MtlsRequired", StringComparison.Ordinal));

        var certAdjustment = 0.0;
        if (certFamilyCount > 0 && hasStrongEvidence)
        {
            certAdjustment += certFamilyCount >= 2 ? 0.05 : 0.03;
        }

        // SQL/injection should not look "complete" from a single narrow probe.
        var sqlFamilyCount = functions.Count(f =>
        f.Contains("SqlInjection", StringComparison.Ordinal) ||
        f.Contains("CommandInjection", StringComparison.Ordinal) ||
        f.Contains("ContentTypeValidation", StringComparison.Ordinal) ||
        f.Contains("ParameterPollution", StringComparison.Ordinal) ||
        f.Contains("OpenApiSchemaMismatch", StringComparison.Ordinal) ||
        f.Contains("TokenParserFuzz", StringComparison.Ordinal));

        var sqlSingleProbePenalty = sqlFamilyCount == 1 ? 0.06 : 0.0;
        var sqlBreadthBoost = sqlFamilyCount >= 3 ? 0.03 : sqlFamilyCount == 2 ? 0.015 : 0.0;

        return certAdjustment + sqlBreadthBoost - sqlSingleProbePenalty;
    }

    private static double ComputeCalibrationUncertaintyPenalty(IReadOnlyList<string> functions)
    {
        if (functions.Count == 0)
        {
            return 0.04;
        }

        var calibration = Calibration.Value;
        if (calibration is null || calibration.Functions.Count == 0)
        {
            // Conservative when no benchmark calibration is available.
            return 0.035;
        }

        var reliabilities = new List<double>(functions.Count);
        foreach (var function in functions.Distinct(StringComparer.Ordinal))
        {
            if (calibration.Functions.TryGetValue(function, out var stats))
            {
                var reliability = Math.Clamp(stats.Samples / (stats.Samples + 30.0), 0.0, 1.0);
                reliabilities.Add(reliability);
            }
            else
            {
                reliabilities.Add(0.0);
            }
        }

        var avgReliability = reliabilities.Count == 0 ? 0.0 : reliabilities.Average();
        var penalty = (1.0 - avgReliability) * 0.06;
        return Math.Clamp(Math.Round(penalty, 4), 0.0, 0.07);
    }

    private static CalibrationModel? LoadCalibrationModel()
    {
        var path = TryResolveCalibrationPath();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        try
        {
            var json = File.ReadAllText(path);
            var parsed = JsonSerializer.Deserialize<CoverageCalibrationDocument>(json);
            if (parsed?.Functions is null || parsed.Functions.Count == 0)
            {
                return null;
            }

            var functions = new Dictionary<string, CalibrationStats>(StringComparer.Ordinal);
            foreach (var kv in parsed.Functions)
            {
                if (string.IsNullOrWhiteSpace(kv.Key) || kv.Value is null)
                {
                    continue;
                }

                var rate = Math.Clamp(kv.Value.SuccessRate, 0.0, 1.0);
                var samples = Math.Max(0, kv.Value.Samples);
                functions[kv.Key.Trim()] = new CalibrationStats(rate, samples);
            }

            return functions.Count == 0 ? null : new CalibrationModel(functions);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryResolveCalibrationPath()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 14 && current is not null; i++)
        {
            var cachePath = Path.Combine(current.FullName, "cache", "coverage-calibration.json");
            if (File.Exists(cachePath))
            {
                return cachePath;
            }

            var localPath = Path.Combine(current.FullName, "coverage-calibration.json");
            if (File.Exists(localPath))
            {
                return localPath;
            }

            current = current.Parent;
        }

        return null;
    }

    private sealed record CalibrationStats(double SuccessRate, int Samples);

    private sealed record CalibrationModel(
    IReadOnlyDictionary<string, CalibrationStats> Functions);

    private sealed class CoverageCalibrationDocument
    {
        public Dictionary<string, CoverageCalibrationFunction>? Functions { get; set; }
    }

    private sealed class CoverageCalibrationFunction
    {
        public double SuccessRate { get; set; }
        public int Samples { get; set; }
    }
}

