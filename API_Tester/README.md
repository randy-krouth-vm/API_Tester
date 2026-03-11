# API_Tester

`API_Tester` is the .NET MAUI GUI for the API security testing platform.

Use it when you want:

- interactive scanning
- standards and suite selection from the UI
- manual payload mode
- OpenAPI file/url input
- route-aware testing with visible results

## What This Project Is

This project is the front-end host for `API_Tester.Core`.

It provides:

- the MAUI user interface
- scan configuration controls
- framework and suite execution buttons
- OpenAPI and route-scope selection
- visible request/response reporting

## Main Features

- single-target, spider, and OpenAPI route scopes
- automatic route-aware request shaping
- manual payload mode
- standards-aligned execution across many security frameworks
- maximum coverage and composite report runs
- headless-compatible workflow paths for automation scenarios

## OpenAPI and Metadata

The UI can drive route-aware scans from:

- an OpenAPI URL
- a local OpenAPI JSON file
- runtime endpoint metadata exposed by the target API

For the most accurate automatic request shaping:

- provide an OpenAPI document when possible
- optionally expose `/_apitester/endpoints` from your target API

## Run

Build:

```powershell
dotnet build API_Tester.csproj -nologo
```

Run on Windows:

```powershell
dotnet run --project API_Tester.csproj -f net10.0-windows10.0.19041.0
```

## Manual Payload Mode

Manual payload mode lets you:

- append extra payloads to existing test families
- send direct HTTP/HTTPS requests as standalone manual tests
- target specific override/route payloads without replacing the full test pipeline

If the manual payload starts with `http://` or `https://`, it is treated as a direct request.

## Related Projects

- `..\API_Tester.Core`
  Shared scan engine and workflow logic.

- `..\API_Tester.Headless`
  Command-line/headless execution host.

- `..\API_Validator`
  Middleware package for validating what the tester actually sent to your API routes.

## Notes

- This project is the UI host, not the full engine by itself.
- OpenAPI/spec fetches and metadata fetches are intentionally separated from normal probe overrides to avoid recursive request-shaping issues.
- If behavior seems stale after a crash or fix, fully close the running app and relaunch it so the latest binaries are loaded.
