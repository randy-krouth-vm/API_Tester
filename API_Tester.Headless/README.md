# API_Tester.Headless

`API_Tester.Headless` is the non-UI runner for the API tester engine.

Use it when you want:

- command-line execution
- CI/CD integration
- repeatable route-aware scans
- JSON output without launching the MAUI app

## What It Uses

`API_Tester.Headless` hosts `API_Tester.Core` and executes the same scan logic without the GUI.

It supports:

- single-target runs
- OpenAPI-scoped runs
- route-aware execution
- standards and advanced probe coverage

## Basic Usage

Run against a local target:

```powershell
dotnet run --project ..\API_Tester.Headless\API_Tester.Headless.csproj -- --target http://127.0.0.1:5006
```

Run using OpenAPI scope:

```powershell
dotnet run --project ..\API_Tester.Headless\API_Tester.Headless.csproj -- --target http://127.0.0.1:5006 --scope openapi --openapi http://127.0.0.1:5006/openapi/v1.json
```

Run with HTTP trace output:

```powershell
dotnet run --project ..\API_Tester.Headless\API_Tester.Headless.csproj -- --target http://127.0.0.1:5006 --http-trace
```

## Common Use Cases

- validate that route-aware request shaping is working
- run all standards/probes in automation
- execute scans in environments where the MAUI UI is not practical
- generate machine-readable output for later review

## Metadata and Accuracy

For best route/type awareness:

1. expose an OpenAPI document, or
2. expose `/_apitester/endpoints` metadata from the target API, or
3. provide both

OpenAPI is the best source for body/query schema detail. Runtime metadata is very good for live route discovery and path typing.

## Build

```powershell
dotnet build ..\API_Tester.Headless\API_Tester.Headless.csproj -nologo
```

## Notes

- Headless uses the same core scan engine as the GUI.
- If a target is flaky or intentionally weak, many findings may be expected.
- Network failures and protocol edge cases should be handled more safely than before, but the quality of the target still affects scan stability and result quality.
