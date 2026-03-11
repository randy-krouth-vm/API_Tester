# API_Tester.Core

`API_Tester.Core` is the shared scanning engine used by the MAUI tester and the headless runner.

It contains:

- standards and suite test implementations
- route-aware request shaping
- OpenAPI and runtime metadata utilities
- workflow orchestration for discovery, overrides, and evidence capture

## What It Does

The core library is responsible for:

- building and executing test probes
- resolving OpenAPI contracts
- consuming runtime endpoint metadata from `/_apitester/endpoints`
- applying route-aware and type-aware request overrides
- collecting request/response evidence for reports

## Route-Aware Behavior

`API_Tester.Core` can use two metadata sources:

- OpenAPI documents for route, query, and body schema detail
- runtime endpoint metadata for live route discovery and path parameter typing

When available, it uses this data to:

- replace route placeholders with type-safe values
- keep integer route parameters integer-safe
- shape query and body inputs more accurately
- avoid sending the same generic payload to every field blindly

## Main Areas

- `Tests/`
  Contains standards-aligned and advanced technical probes.

- `Workflow/`
  Contains orchestration utilities for OpenAPI resolution, scope handling, request overrides, spidering, and report execution.

- `RequestContractPipeline.cs`
  Applies contract-aware path, query, and body shaping.

- `MainPage.TestHost.cs`
  Lightweight host wrapper used by non-UI execution paths and tests.

## Referencing the Core Library

In another `.csproj`:

```xml
<ItemGroup>
  <ProjectReference Include="..\API_Tester.Core\API_Tester.Core.csproj" />
</ItemGroup>
```

## Typical Usage

This project is usually consumed by:

- `API_Tester`
  The MAUI GUI application.

- `API_Tester.Headless`
  The command-line/headless execution host.

You normally do not call most workflow helpers directly unless you are building another host around the engine.

## Build

```powershell
dotnet build ..\API_Tester.Core\API_Tester.Core.csproj -nologo
```

## Notes

- OpenAPI gives the strongest query/body type accuracy.
- Runtime endpoint metadata is strongest for live route discovery and path parameter typing.
- The core library is designed to preserve test coverage while improving request accuracy, not to reduce the test set.
