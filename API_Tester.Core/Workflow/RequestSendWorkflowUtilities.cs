namespace ApiTester.Core;

public static class RequestSendWorkflowUtilities
{
    private const string TestKeyHeader = "X-ApiTester-TestKey";
    private const string PayloadHeader = "X-ApiTester-Payload";

    public static async Task<HttpResponseMessage?> SafeSendAsync(
        Func<HttpRequestMessage> requestFactory,
        int delayMs,
        Func<HttpRequestMessage, Task> applySingleTargetRequestOverridesAsync,
        Func<Uri?, (bool IsViolation, string Message)> strictSingleScopeEvaluator,
        AuthProfile? activeAuthProfile,
        Func<HttpRequestMessage, Task<HttpResponseMessage>> sendAsync,
        Func<AuditCaptureContext?> getAuditCaptureContext,
        Func<string?>? getTestKey = null,
        Func<string?>? getPayload = null)
    {
        try
        {
            if (delayMs > 0)
            {
                await Task.Delay(delayMs);
            }

            using var request = requestFactory();
            await applySingleTargetRequestOverridesAsync(request);

            var scope = strictSingleScopeEvaluator(request.RequestUri);
            if (scope.IsViolation)
            {
                if (getAuditCaptureContext() is { } blockedCapture)
                {
                    blockedCapture.Exchanges.Add(new HttpExchangeEvidence(
                        request.Method.Method,
                        request.RequestUri?.ToString() ?? string.Empty,
                        HttpEvidenceUtilities.FormatRequestHeaders(request),
                        string.Empty,
                        null,
                        string.Empty,
                        string.Empty,
                        string.Empty,
                        scope.Message,
                        DateTime.UtcNow.ToString("O")));
                }

                return null;
            }

            RequestExecutionUtilities.ApplyAuthProfileToRequest(request, activeAuthProfile);
            RequestExecutionUtilities.EnsureBodyForWriteMethod(request);

            var testKey = getTestKey?.Invoke();
            if (!string.IsNullOrWhiteSpace(testKey) && !request.Headers.Contains(TestKeyHeader))
            {
                request.Headers.TryAddWithoutValidation(TestKeyHeader, testKey);
            }

            var payload = getPayload?.Invoke();
            if (!string.IsNullOrWhiteSpace(payload) && !request.Headers.Contains(PayloadHeader))
            {
                request.Headers.TryAddWithoutValidation(PayloadHeader, payload);
            }

            RequestContractPipeline.NormalizeRoutePlaceholders(request);

            var requestBody = await HttpEvidenceUtilities.ReadRequestBodyAsync(request);
            var requestHeaders = HttpEvidenceUtilities.FormatRequestHeaders(request);
            var response = await sendAsync(request);

            if (getAuditCaptureContext() is { } capture)
            {
                var responseBody = await HttpEvidenceUtilities.ReadBodyAsync(response);
                capture.Exchanges.Add(new HttpExchangeEvidence(
                    request.Method.Method,
                    request.RequestUri?.ToString() ?? string.Empty,
                    requestHeaders,
                    HttpEvidenceUtilities.TrimForEvidence(requestBody, 1200),
                    (int)response.StatusCode,
                    response.ReasonPhrase ?? string.Empty,
                    HttpEvidenceUtilities.FormatResponseHeaders(response),
                    HttpEvidenceUtilities.TrimForEvidence(responseBody, 1800),
                    string.Empty,
                    DateTime.UtcNow.ToString("O")));
            }

            return response;
        }
        catch (Exception ex)
        {
            if (getAuditCaptureContext() is { } capture)
            {
                capture.Exchanges.Add(new HttpExchangeEvidence(
                    string.Empty,
                    string.Empty,
                    string.Empty,
                    string.Empty,
                    null,
                    string.Empty,
                    string.Empty,
                    string.Empty,
                    ex.Message,
                    DateTime.UtcNow.ToString("O")));
            }

            return null;
        }
    }
}
