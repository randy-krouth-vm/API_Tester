namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Shared Responsibility Controls Tests

        Purpose:
        Performs automated tests to evaluate the implementation and enforcement 
        of shared responsibility security controls, ensuring that both the 
        application and underlying infrastructure comply with defined roles 
        and responsibilities for protecting data and resources.

        Threat Model:
        Weak or unclear shared responsibility controls may allow attackers to:

            - Exploit gaps between application and infrastructure security
            - Access sensitive data due to mismanaged responsibilities
            - Circumvent security controls by targeting unmonitored areas
            - Operate undetected where responsibility is ambiguous

        Common vulnerabilities include:

            - Misalignment between application and infrastructure security policies
            - Unclear division of responsibilities for access control or monitoring
            - Insufficient enforcement of shared security obligations
            - Inconsistent application of controls across cloud or hybrid environments
            - Lack of monitoring or auditing for shared responsibilities

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Verify that responsibilities for security controls are properly assigned
            - Assess enforcement of access, monitoring, and protection controls
            - Detect gaps where security obligations may be overlooked
            - Ensure consistent application of shared responsibility policies
            - Inspect logging and auditing mechanisms for compliance verification

        Potential Impact:
        If shared responsibility controls are weak, attackers may:

            - Exploit mismanaged security responsibilities to gain access
            - Compromise data or systems undetected
            - Circumvent security policies due to unclear enforcement
            - Increase risk of breaches and non-compliance

        Expected Behavior:
        Applications and systems should:

            - Clearly define and enforce shared security responsibilities
            - Ensure all parties understand and implement their security obligations
            - Monitor compliance with shared responsibility policies
            - Maintain logging and auditing to verify proper enforcement
            - Align technical controls with organizational and contractual responsibilities
        */
        
        private async Task<string> RunSharedResponsibilityControlsTestsAsync(Uri baseUri)
        {
            var activeKey = _activeStandardTestKey.Value;
            var findings = new List<string>();
            findings.Add($"Probe profile: {(string.IsNullOrWhiteSpace(activeKey) ? "default" : activeKey)}");
            var probes = BuildAuthProbeRequests(baseUri, activeKey);
            var accepted = 0;
            var blocked = 0;
            var noResponse = 0;

            foreach (var probe in probes)
            {
                var response = await SafeSendAsync(() => probe.BuildRequest());
                if (response is null)
                {
                    noResponse++;
                    findings.Add($"{probe.Name}: no response");
                    continue;
                }

                var status = (int)response.StatusCode;
                findings.Add($"{probe.Name}: HTTP {status} {response.StatusCode}");
                if (status is >= 200 and < 300)
                {
                    accepted++;
                }
                else if (status is 401 or 403)
                {
                    blocked++;
                }
            }

            findings.Add(accepted > 0
            ? $"Potential risk: {accepted}/{probes.Count} auth probes were accepted."
            : blocked > 0
            ? $"Auth barrier observed in {blocked}/{probes.Count} probes."
            : noResponse == probes.Count
            ? "No auth probe responses received."
            : "No obvious auth barrier signal from current probes.");
            return FormatSection("Authentication and Access Control", baseUri, findings);
        }
    }
}

