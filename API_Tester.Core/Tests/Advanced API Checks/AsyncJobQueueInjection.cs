namespace API_Tester;

public partial class MainPage
{
    /*
    Async Job Queue Injection Test

    Purpose:
    Detects whether API endpoints accept user-controlled job definitions
    that are forwarded to asynchronous background workers or task queues.

    Threat Model:
    Many applications use background job systems (e.g., Hangfire, Celery,
    Sidekiq, Bull, RabbitMQ workers) where an API endpoint submits tasks
    to a queue that are executed later by worker processes.

    If the API allows clients to control fields such as:
        job
        task
        queue
        worker
        action
        type

    an attacker may be able to enqueue unintended internal tasks.

    Test Strategy:
    The scanner submits crafted JSON payloads containing common job control
    fields to potential task endpoints and observes whether the server
    accepts or queues the request.

    Indicators of queue processing include response messages containing:
        "queued"
        "accepted"
        "job"
        "task"
        "worker"
        "scheduled"

    Potential Impact:
    If user input is directly mapped to job execution logic, an attacker
    may trigger internal operations such as administrative jobs, system
    maintenance tasks, or privileged worker actions.

    Expected Behavior:
    The server should validate job types, restrict allowed task names,
    and require proper authorization before accepting or scheduling
    background jobs.
    */
    
    private async Task<string> RunAsyncJobQueueInjectionTestsAsync(Uri baseUri)
    {
        var openApi = await GetOpenApiProbeContextAsync(baseUri);
        var scanDepth = GetScanDepthProfile();
        var endpoints = (openApi.TargetEndpoints.Count > 0 ? openApi.TargetEndpoints : new List<Uri> { baseUri })
        .Take(scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8)
        .ToList();
        var fields = new[] { "job", "task", "queue", "worker", "action", "type" };
        var findings = new List<string>();
        var suspicious = 0;
        var attempts = 0;

        foreach (var endpoint in endpoints)
        {
            var payload = fields.ToDictionary(k => k, _ => "deleteAllUsers", StringComparer.OrdinalIgnoreCase);
            var response = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
                req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                return req;
            });
            var body = await ReadBodyAsync(response);
            attempts++;
            if (response is not null && (int)response.StatusCode is >= 200 and < 300 &&
            ContainsAny(body, "job", "queued", "accepted", "task", "worker", "delete"))
            {
                suspicious++;
            }
        }
        findings.Add(suspicious > 0
        ? $"Potential risk: async job queue injection signals observed on {suspicious}/{attempts} probes."
        : "No obvious async job queue abuse acceptance observed.");
        return FormatSection("Async Job Queue Injection", baseUri, findings);
    }

}

