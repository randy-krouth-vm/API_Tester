namespace API_Tester
{
    public partial class MainPage
    {
        /*
        PII Processing Transparency Controls Tests

        Purpose:
        Performs automated tests to evaluate the application’s controls for 
        ensuring transparency in the processing of personally identifiable 
        information (PII), verifying that data usage is clear, accountable, 
        and compliant with privacy regulations.

        Threat Model:
        Lack of transparency in PII processing may allow attackers or internal 
        actors to:

            - Process personal data without user consent or awareness
            - Misuse PII without detection or accountability
            - Violate privacy regulations (e.g., GDPR, CCPA)
            - Exploit unclear data flows for malicious purposes

        Common vulnerabilities include:

            - Processing PII without explicit user consent
            - Lack of clear data usage notifications or disclosures
            - Inconsistent or undocumented handling of sensitive data
            - Inadequate logging or audit trails for PII processing
            - Failure to inform users about how their data is used, shared, or retained

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Inspect application behavior for proper disclosure of data usage
            - Verify logging and auditing of PII processing events
            - Evaluate mechanisms for obtaining and respecting user consent
            - Detect inconsistencies or gaps in transparency controls
            - Ensure compliance with regulatory requirements for PII processing

        Potential Impact:
        If PII processing transparency controls are weak, attackers or 
        unauthorized actors may:

            - Exploit data without user knowledge or consent
            - Perform unauthorized operations on personal data
            - Cause regulatory violations and reputational damage
            - Evade accountability and auditing mechanisms

        Expected Behavior:
        Applications should:

            - Clearly inform users of data collection, processing, and retention
            - Respect user consent and provide options for data management
            - Maintain comprehensive logs of PII processing activities
            - Ensure consistency in data handling and transparency practices
            - Comply with privacy regulations and organizational policies
        */
        
        private async Task<string> RunPiiProcessingTransparencyControlsTestsAsync(Uri baseUri)
        {
            var malformed = AppendQuery(baseUri, new Dictionary<string, string> { ["malformed"] = "%ZZ%YY" });
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, malformed));
            var body = await ReadBodyAsync(response);

            var findings = new List<string>
            {
                $"HTTP {FormatStatus(response)}",
                ContainsAny(body, "exception", "stack trace", "at ", "innerexception")
                ? "Potential risk: exception or stack-trace details exposed."
                : "No obvious stack-trace leakage detected."
            };

            return FormatSection("Error Handling Leakage", malformed, findings);
        }
    }
}

