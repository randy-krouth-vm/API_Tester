# API_Validator

`API_Validator` is a lightweight ASP.NET Core middleware package for capturing what the API tester actually sent to a route and what the route returned.

It is intended for local validation targets such as `TestAPI`, where you want to confirm:

- which request hit the route
- which `TestKey` triggered it
- which payload was used
- which route template matched
- which route values were bound
- what status code and response body came back

## What It Captures

For each request the middleware can retain:

- request method
- request path and query string
- route template
- route values
- endpoint metadata
- request headers
- request body
- response status code
- response headers
- response body
- tester metadata headers such as `X-ApiTester-TestKey` and `X-ApiTester-Payload`

The tester already sends the metadata headers. You do not need to invent new headers for basic integration.

## Basic Setup

1. Add a project reference from your API project to `API_Validator`.
2. Register the validator services.
3. Add the middleware before your route mappings or before the endpoints you want to observe.

## Example Project Reference

In your API `.csproj`:

```xml
<ItemGroup>
  <ProjectReference Include="..\API_Validator\API_Validator.csproj" />
</ItemGroup>
```

## Example `Program.cs`

```csharp
using ApiValidator;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Register validator services.
builder.Services.AddSingleton<ApiTestAttachmentStore>();
builder.Services.AddSingleton<API_Validator>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Add validator middleware.
// This captures tester metadata, request details, and response details.
var apiValidatorMiddlewareType = Type.GetType("ApiValidator.ApiValidatorMiddleware, API_Validator");
if (apiValidatorMiddlewareType is null)
{
    throw new InvalidOperationException("ApiValidator middleware type could not be resolved.");
}

app.UseMiddleware(apiValidatorMiddlewareType, app.Services.GetRequiredService<API_Validator>());

app.MapGet("/products/{id:int}", (int id) =>
{
    return Results.Ok(new
    {
        Id = id,
        Name = "Notebook"
    });
});

// Optional metadata endpoint for the tester.
app.MapGet("/_apitester/endpoints", (EndpointDataSource dataSource) =>
{
    var endpoints = dataSource.Endpoints
        .OfType<RouteEndpoint>()
        .Select(endpoint => new
        {
            Route = endpoint.RoutePattern.RawText ?? endpoint.DisplayName ?? string.Empty,
            Methods = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? Array.Empty<string>()
        });

    return Results.Ok(endpoints);
});

app.Run();
```

## Minimal Endpoint Metadata Route

If you want the tester to become more route-aware without requiring OpenAPI input, expose a metadata route such as:

```csharp
app.MapGet("/_apitester/endpoints", (EndpointDataSource dataSource) =>
{
    var endpoints = dataSource.Endpoints
        .OfType<RouteEndpoint>()
        .Select(endpoint => new
        {
            Route = endpoint.RoutePattern.RawText ?? endpoint.DisplayName ?? string.Empty,
            Methods = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? Array.Empty<string>(),
            Params = Array.Empty<object>()
        });

    return Results.Ok(endpoints);
});
```

The richer the metadata you return, the more accurately the tester can shape path, query, and body payloads.

## How the Tester Identifies Requests

The tester uses these headers:

- `X-ApiTester-TestKey`
- `X-ApiTester-Payload`

The middleware reads those headers automatically and includes them in the captured attachment/log entry.

## Logging Behavior

By default the middleware:

- stores attachments in memory through `ApiTestAttachmentStore`
- logs a readable request/response summary to the console

File output is optional and can stay disabled if you only want console logging plus in-memory retention.

## Notes

- Runtime endpoint metadata is strong for route discovery and path parameter typing.
- OpenAPI is still the best source for full query/body schema typing.
- You can use both together: runtime metadata for live route discovery, OpenAPI for deeper request shaping.
