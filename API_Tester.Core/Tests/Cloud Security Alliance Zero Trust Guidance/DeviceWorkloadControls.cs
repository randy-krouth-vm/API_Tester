namespace API_Tester;

public partial class MainPage
{
    /*
    CSA Zero Trust Device & Workload Controls Payloads

    Purpose:
    Provides predefined payloads for testing device and workload 
    security controls in a Zero Trust architecture, following CSA (Cloud 
    Security Alliance) recommendations. These payloads simulate various 
    device and workload states to evaluate security enforcement.

    Threat Model:
    In a Zero Trust environment, devices and workloads may be compromised 
    or misconfigured. Attackers could exploit insufficient verification 
    of device posture, workload permissions, or trust levels to:

        - Gain unauthorized access to resources
        - Execute unauthorized workloads
        - Circumvent security policies
        - Introduce malicious agents or configurations

    Typical payload scenarios include:

        - Unknown or untrusted devices
        - Legacy or improperly configured workloads
        - Disabled or missing security agents
        - Test platforms or non-standard environments

    Test Strategy:
    The method returns an array of strings representing payloads that can 
    be sent to the system under test. Each payload mimics a specific 
    device or workload condition to verify:

        - Enforcement of trust and compliance policies
        - Proper handling of legacy or non-compliant workloads
        - Security agent validation
        - Platform recognition and isolation

    Potential Impact:
    If controls are weak or absent, attackers may be able to:

        - Access protected resources from untrusted devices
        - Run unauthorized workloads in sensitive environments
        - Bypass agent-based or workload-level security checks
        - Introduce vulnerabilities or manipulate system behavior

    Expected Behavior:
    Systems should:

        - Validate all devices and workloads against trust and compliance policies
        - Reject or restrict actions from non-compliant devices/workloads
        - Ensure agents are active and enforce security posture
        - Isolate unknown platforms and prevent unauthorized access
    */
    private static string[] GetCsaZeroTrustDeviceWorkloadControlsPayloads() =>
    [
        "device=unknown;trust=high",
        "workload=legacy;allow=true",
        "agent=disabled",
        "platform=test-bed",
        "device=compliant;trust=high",
        "device=non-compliant;trust=low",
        "device=managed;trust=medium",
        "workload=production;allow=true",
        "workload=development;allow=false",
        "agent=enabled;security=high",
        "agent=enabled;security=low",
        "agent=disabled;security=none",
        "platform=mobile;trust=medium",
        "platform=server;trust=high",
        "platform=desktop;trust=medium",
        "network=secure;allow=true",
        "network=untrusted;allow=false",
        "user=admin;access=full",
        "user=guest;access=restricted"
    ];

    private HttpRequestMessage FormatCsaZeroTrustDeviceWorkloadControlsRequest(Uri baseUri, string payload)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
        req.Headers.TryAddWithoutValidation("X-Device-Context", payload);
        req.Headers.TryAddWithoutValidation("X-Workload-Context", payload);
        return req;
    }

    private async Task<string> RunCsaZeroTrustDeviceWorkloadControlsTestsAsync(Uri baseUri)
    {
        var payloads = GetCsaZeroTrustDeviceWorkloadControlsPayloads();
        var findings = new List<string>();

        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatCsaZeroTrustDeviceWorkloadControlsRequest(baseUri, payload));
            findings.Add($"Payload '{payload}': {FormatStatus(response)}");
        }

        findings.Insert(0, $"Payload variants tested: {payloads.Length}");
        return FormatSection("CSA Zero Trust Device Workload Controls", baseUri, findings);
    }
}

