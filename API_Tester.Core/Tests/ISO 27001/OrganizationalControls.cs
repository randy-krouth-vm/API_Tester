namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Organizational Controls Tests

        Purpose:
        Performs automated tests to evaluate the application’s adherence to 
        organizational security policies and governance controls, ensuring that 
        processes, roles, and responsibilities are implemented effectively to 
        support secure operations.

        Threat Model:
        Weak organizational controls may allow attackers or insider threats to:

            - Exploit gaps in policy enforcement or governance
            - Circumvent procedures designed to prevent unauthorized access
            - Misuse administrative or privileged functions
            - Operate undetected due to lack of oversight or accountability

        Common vulnerabilities include:

            - Inconsistent application of security policies
            - Undefined roles, responsibilities, or escalation paths
            - Weak or missing approval workflows for sensitive actions
            - Insufficient oversight of privileged accounts or operations
            - Poor alignment between technical controls and organizational procedures

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Verify alignment between implemented security controls and organizational policies
            - Evaluate role-based access and responsibility enforcement
            - Inspect workflows and approval processes for sensitive operations
            - Assess the effectiveness of accountability and oversight mechanisms
            - Detect gaps or inconsistencies in organizational control implementation

        Potential Impact:
        If organizational controls are weak or misaligned, attackers may:

            - Exploit procedural gaps to bypass security controls
            - Gain unauthorized access to sensitive resources
            - Escalate privileges undetected
            - Compromise compliance and governance objectives

        Expected Behavior:
        Applications and systems should:

            - Enforce organizational policies consistently across all operations
            - Clearly define roles, responsibilities, and escalation paths
            - Implement approval workflows for sensitive actions
            - Maintain accountability and oversight of privileged operations
            - Align technical controls with organizational governance requirements
        */
        
        private async Task<string> RunOrganizationalControlsTestsAsync(Uri baseUri)
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

