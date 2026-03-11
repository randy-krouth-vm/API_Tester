using Microsoft.Extensions.Logging;
using System.Security.Authentication;

namespace API_Tester;

public sealed class ApiTesterVerboseHttpLogger : DelegatingHandler
{
    private readonly ILogger<ApiTesterVerboseHttpLogger> _logger;

    public ApiTesterVerboseHttpLogger(ILogger<ApiTesterVerboseHttpLogger> logger)
    {
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri is not null)
        {
            _logger.LogInformation("ApiTester request {Method} {Uri}", request.Method, request.RequestUri);
        }

        HttpResponseMessage response;
        try
        {
            response = await base.SendAsync(request, cancellationToken);
        }
        catch (TaskCanceledException ex)
        {
            if (request.RequestUri is not null)
            {
                _logger.LogWarning(ex, "ApiTester request timed out {Method} {Uri}", request.Method, request.RequestUri);
            }

            response = new HttpResponseMessage(System.Net.HttpStatusCode.RequestTimeout)
            {
                RequestMessage = request,
                ReasonPhrase = "Request timed out"
            };
        }
        catch (HttpRequestException ex)
        {
            if (request.RequestUri is not null)
            {
                _logger.LogWarning(ex, "ApiTester request failed {Method} {Uri}", request.Method, request.RequestUri);
            }

            response = new HttpResponseMessage(
                cancellationToken.IsCancellationRequested
                    ? System.Net.HttpStatusCode.RequestTimeout
                    : System.Net.HttpStatusCode.BadGateway)
            {
                RequestMessage = request,
                ReasonPhrase = DescribeHttpRequestFailure(ex, cancellationToken)
            };
        }
        catch (Exception ex)
        {
            if (request.RequestUri is not null)
            {
                _logger.LogWarning(ex, "ApiTester request crashed {Method} {Uri}", request.Method, request.RequestUri);
            }

            response = new HttpResponseMessage(System.Net.HttpStatusCode.BadGateway)
            {
                RequestMessage = request,
                ReasonPhrase = ex.GetType().Name
            };
        }

        if (request.RequestUri is not null)
        {
            _logger.LogInformation("ApiTester response {StatusCode} {Uri}", (int)response.StatusCode, request.RequestUri);
        }

        return response;
    }

    private static string DescribeHttpRequestFailure(HttpRequestException ex, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return "Request canceled";
        }

        if (ex.InnerException is AuthenticationException)
        {
            return "TLS handshake failed";
        }

        return "Request failed";
    }
}
