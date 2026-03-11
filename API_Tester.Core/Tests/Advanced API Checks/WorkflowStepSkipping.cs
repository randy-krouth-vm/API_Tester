namespace API_Tester;

public partial class MainPage
{
    /*
    Workflow Step Skipping Test

    Purpose:
    Checks whether the application enforces the correct sequence of
    workflow steps or allows clients to jump directly to later stages
    without completing required intermediate steps.

    Threat Model:
    Many business processes rely on ordered state transitions to ensure
    that validation, approvals, or prerequisite actions occur before
    sensitive operations. If the server trusts client-supplied state
    values or identifiers without verifying the current server-side
    state, an attacker may skip required steps.

    Common workflow examples:

        Account lifecycle:
            REGISTERED → VERIFIED → ACTIVE

        Order processing:
            CREATED → PAID → SHIPPED → DELIVERED

        Approval flow:
            SUBMITTED → REVIEWED → APPROVED → EXECUTED

    If the server accepts requests that move directly from an early state
    to a later one (e.g., CREATED → SHIPPED), it may bypass validation
    checks or business rules tied to the missing steps.

    Attack scenarios include:

        - skipping payment verification before order fulfillment
        - bypassing identity verification during account activation
        - moving directly to privileged workflow states
        - executing actions that should require prior approval

    Test Strategy:
    The scanner attempts to invoke workflow actions or state changes that
    would normally require prior steps. It observes whether the server
    accepts the transition or correctly rejects it based on the current
    server-side state.

    Potential Impact:
    If workflow step skipping is possible, attackers may be able to:

        - bypass business logic protections
        - gain unauthorized access or privileges
        - trigger actions that should require prior approval
        - create inconsistent or invalid workflow states

    Expected Behavior:
    Applications should enforce workflow state transitions strictly on the
    server side. Each request should verify the current state of the
    resource and only allow transitions that follow the defined workflow.
    Client-supplied state values should never be trusted without validation.
    */
    
    private async Task<string> RunWorkflowStepSkippingTestsAsync(Uri baseUri)
    {
        var approvalUri = new Uri(baseUri, "/approve");
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, approvalUri);
            req.Content = new StringContent("{\"id\":\"12345\",\"status\":\"approved\"}", Encoding.UTF8, "application/json");
            return req;
        });

        var findings = new List<string>
        {
            $"Approve-without-create request: {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: workflow step-skipping may be possible."
            : "No obvious step-skipping acceptance."
        };

        return FormatSection("Workflow Step Skipping", approvalUri, findings);
    }

}

