namespace API_Tester;

public partial class MainPage
{
    private sealed class PayloadProbeOptions
    {
        public HttpMethod Method { get; init; } = HttpMethod.Get;
        public string[] QueryPayloadParameters { get; init; } = [];
        public Dictionary<string, string>? QueryParameters { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public string? RawBodyTemplate { get; init; }
        public string ContentType { get; init; } = "application/json";
        public Func<Uri, HttpRequestMessage>? RequestFactory { get; init; }
    }

    private async Task<string> RunPayloadProbeAsync(
        Uri baseUri,
        string sectionName,
        IEnumerable<string> payloads,
        PayloadProbeOptions options,
        Func<string, HttpResponseMessage?, string>? findingFormatter = null)
    {
        var findings = new List<string>();
        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() =>
            {
                var requestUri = BuildPayloadRequestUri(baseUri, payload, options);
                var request = options.RequestFactory is null
                    ? new HttpRequestMessage(options.Method, requestUri)
                    : options.RequestFactory(requestUri);

                if (options.Headers is not null)
                {
                    foreach (var (name, value) in options.Headers)
                    {
                        request.Headers.TryAddWithoutValidation(name, value);
                    }
                }

                if (!string.IsNullOrEmpty(options.RawBodyTemplate))
                {
                    var body = options.RawBodyTemplate.Replace("{{payload}}", payload, StringComparison.Ordinal);
                    request.Content = new StringContent(body, Encoding.UTF8, options.ContentType);
                }

                return request;
            });

            findings.Add(findingFormatter is null
                ? $"{payload}: {FormatStatus(response)}"
                : findingFormatter(payload, response));
        }

        return FormatSection(sectionName, baseUri, findings);
    }

    private Uri BuildPayloadRequestUri(Uri baseUri, string payload, PayloadProbeOptions options)
    {
        var query = new Dictionary<string, string>(StringComparer.Ordinal);
        if (options.QueryParameters is not null)
        {
            foreach (var (key, value) in options.QueryParameters)
            {
                query[key] = value;
            }
        }

        foreach (var key in options.QueryPayloadParameters)
        {
            query[key] = payload;
        }

        return query.Count == 0 ? baseUri : AppendQuery(baseUri, query);
    }
}
