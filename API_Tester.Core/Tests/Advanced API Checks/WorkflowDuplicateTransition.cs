namespace API_Tester;

public partial class MainPage
{
    /*
    Workflow Duplicate Transition Test

    Purpose:
    Checks whether the application improperly allows the same workflow
    transition to be executed multiple times, which may lead to inconsistent
    state changes or business logic abuse.

    Threat Model:
    Many applications rely on workflow states to control how resources
    move through a process. Examples include order processing, payment
    approval, ticket systems, or account verification flows.

    If workflow transitions are not properly validated, attackers may
    trigger the same transition repeatedly or out of order, causing the
    application to process actions more than once.

    Attack scenarios include:

        - executing the same approval step multiple times
        - triggering duplicate order fulfillment
        - applying discounts or credits repeatedly
        - forcing a workflow into an inconsistent state

    Example scenario:

        Order workflow:
            CREATED → PAID → SHIPPED → DELIVERED

    If the system allows the transition:

            PAID → SHIPPED

    to be executed multiple times, an attacker may trigger duplicate
    shipping events or repeated downstream processing.

    Test Strategy:
    The scanner sends repeated workflow transition requests to determine
    whether the application allows the same state change to occur multiple
    times without verifying the current workflow state.

    Potential Impact:
    If duplicate transitions are possible, attackers may be able to:

        - manipulate business processes
        - cause duplicate financial or operational actions
        - bypass workflow controls
        - create inconsistent or corrupted system state

    Expected Behavior:
    Applications should enforce strict workflow state validation and
    reject requests that attempt to repeat or skip workflow transitions
    once a state change has already occurred.
    */
    
    private async Task<string> RunWorkflowDuplicateTransitionTestsAsync(Uri baseUri)
    {
        var transitionUri = new Uri(baseUri, "/transition");
        const string payload = "{\"id\":\"12345\",\"state\":\"approved\"}";

        var first = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, transitionUri);
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });

        var second = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, transitionUri);
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });

        var findings = new List<string>
        {
            $"First transition: {FormatStatus(first)}",
            $"Duplicate transition: {FormatStatus(second)}",
            first is not null && second is not null && first.StatusCode == HttpStatusCode.OK && second.StatusCode == HttpStatusCode.OK
            ? "Potential risk: duplicate transition accepted without idempotency guard."
            : "No obvious duplicate-transition acceptance."
        };

        return FormatSection("Workflow Duplicate Transition", transitionUri, findings);
    }

}

