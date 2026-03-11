using System.Text.RegularExpressions;

namespace ApiTester.Core;

public sealed record ApiEndpointParameterDescriptor(
    string Name,
    string Type,
    string Source);

public sealed record ApiEndpointDescriptor(
    string Route,
    List<string> Methods,
    List<ApiEndpointParameterDescriptor> Params);

public static class EndpointMetadataUtilities
{
    public static OpenApiProbeContext BuildProbeContext(
        Uri baseUri,
        IReadOnlyList<ApiEndpointDescriptor> descriptors)
    {
        var endpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var bodyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var nonStringQueryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var nonStringBodyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pathNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var operationProfiles = new List<OpenApiOperationProfile>();

        foreach (var descriptor in descriptors)
        {
            var route = string.IsNullOrWhiteSpace(descriptor.Route) ? "/" : descriptor.Route;
            if (!route.StartsWith("/", StringComparison.Ordinal))
            {
                route = "/" + route;
            }

            var routeParamTypeMap = BuildRouteParamTypeMap(descriptor.Params);
            var queryParamTypeMap = BuildParamTypeMap(descriptor.Params, "query");
            var bodyParamTypeMap = BuildParamTypeMap(descriptor.Params, "body");
            var concretePaths = ExpandRouteTemplateCandidates(route, routeParamTypeMap).ToList();
            var pathParamNames = descriptor.Params
                .Where(p => string.Equals(p.Source, "route", StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Name)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var queryParamNames = descriptor.Params
                .Where(p => string.Equals(p.Source, "query", StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Name)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var bodyParamNames = descriptor.Params
                .Where(p => string.Equals(p.Source, "body", StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Name)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var name in pathParamNames)
            {
                pathNames.Add(name);
            }

            foreach (var name in queryParamNames)
            {
                queryNames.Add(name);
                if (queryParamTypeMap.TryGetValue(name, out var typeHint) && IsNonStringType(typeHint))
                {
                    nonStringQueryNames.Add(name);
                }
            }

            foreach (var name in bodyParamNames)
            {
                bodyNames.Add(name);
                if (bodyParamTypeMap.TryGetValue(name, out var typeHint) && IsNonStringType(typeHint))
                {
                    nonStringBodyNames.Add(name);
                }
            }

            foreach (var path in concretePaths)
            {
                Uri endpoint;
                try
                {
                    endpoint = new Uri(baseUri, path);
                }
                catch
                {
                    continue;
                }

                endpoints.Add(endpoint.ToString());
                operationProfiles.Add(new OpenApiOperationProfile(
                    endpoint,
                    descriptor.Methods ?? new List<string>(),
                    queryParamNames,
                    bodyParamNames,
                    pathParamNames,
                    new Dictionary<string, string>(queryParamTypeMap, StringComparer.OrdinalIgnoreCase),
                    new Dictionary<string, string>(bodyParamTypeMap, StringComparer.OrdinalIgnoreCase),
                    new Dictionary<string, string>(routeParamTypeMap, StringComparer.OrdinalIgnoreCase)));
            }
        }

        if (endpoints.Count == 0)
        {
            endpoints.Add(baseUri.ToString());
        }

        return new OpenApiProbeContext(
            endpoints.Select(u => new Uri(u)).ToList(),
            queryNames.ToList(),
            bodyNames.ToList(),
            nonStringQueryNames.ToList(),
            nonStringBodyNames.ToList(),
            pathNames.ToList(),
            operationProfiles);
    }

    private static IEnumerable<string> ExpandRouteTemplateCandidates(
        string pathTemplate,
        IReadOnlyDictionary<string, string> routeParamTypes)
    {
        if (string.IsNullOrWhiteSpace(pathTemplate))
        {
            yield break;
        }

        var normalized = pathTemplate.StartsWith("/", StringComparison.Ordinal) ? pathTemplate : "/" + pathTemplate;
        var concrete = Regex.Replace(normalized, "\\{(?<name>[^}/]+)\\}", match =>
        {
            var name = match.Groups["name"].Value.Trim().ToLowerInvariant();
            if (routeParamTypes.TryGetValue(name, out var typeHint))
            {
                return ResolveSampleValueForType(typeHint, name);
            }

            return ResolveSampleValueForType(string.Empty, name);
        });

        yield return concrete;
    }

    private static Dictionary<string, string> BuildRouteParamTypeMap(IEnumerable<ApiEndpointParameterDescriptor> parameters)
        => BuildParamTypeMap(parameters, "route");

    private static Dictionary<string, string> BuildParamTypeMap(IEnumerable<ApiEndpointParameterDescriptor> parameters, string source)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var param in parameters)
        {
            if (!string.Equals(param.Source, source, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(param.Name))
            {
                continue;
            }

            map[param.Name.Trim().ToLowerInvariant()] = param.Type ?? string.Empty;
        }

        return map;
    }

    private static bool IsNonStringType(string typeHint)
    {
        var normalized = (typeHint ?? string.Empty).ToLowerInvariant();
        return normalized.Contains("int", StringComparison.Ordinal) ||
               normalized.Contains("uint", StringComparison.Ordinal) ||
               normalized.Contains("long", StringComparison.Ordinal) ||
               normalized.Contains("ulong", StringComparison.Ordinal) ||
               normalized.Contains("short", StringComparison.Ordinal) ||
               normalized.Contains("ushort", StringComparison.Ordinal) ||
               normalized.Contains("sbyte", StringComparison.Ordinal) ||
               normalized.Contains("byte", StringComparison.Ordinal) ||
               normalized.Contains("decimal", StringComparison.Ordinal) ||
               normalized.Contains("double", StringComparison.Ordinal) ||
               normalized.Contains("float", StringComparison.Ordinal) ||
               normalized.Contains("number", StringComparison.Ordinal) ||
               normalized.Contains("char", StringComparison.Ordinal) ||
               normalized.Contains("bool", StringComparison.Ordinal) ||
               normalized.Contains("date", StringComparison.Ordinal) ||
               normalized.Contains("time", StringComparison.Ordinal) ||
               normalized.Contains("guid", StringComparison.Ordinal) ||
               normalized.Contains("uuid", StringComparison.Ordinal);
    }

    private static string ResolveSampleValueForType(string typeHint, string nameHint)
    {
        var normalizedType = (typeHint ?? string.Empty).ToLowerInvariant();
        if (normalizedType.Contains("guid", StringComparison.Ordinal))
        {
            return Guid.Empty.ToString("D");
        }

        if (normalizedType.Contains("int", StringComparison.Ordinal) ||
            normalizedType.Contains("uint", StringComparison.Ordinal) ||
            normalizedType.Contains("long", StringComparison.Ordinal) ||
            normalizedType.Contains("ulong", StringComparison.Ordinal) ||
            normalizedType.Contains("short", StringComparison.Ordinal) ||
            normalizedType.Contains("ushort", StringComparison.Ordinal) ||
            normalizedType.Contains("sbyte", StringComparison.Ordinal) ||
            normalizedType.Contains("byte", StringComparison.Ordinal))
        {
            return "1";
        }

        if (normalizedType.Contains("decimal", StringComparison.Ordinal) ||
            normalizedType.Contains("double", StringComparison.Ordinal) ||
            normalizedType.Contains("float", StringComparison.Ordinal) ||
            normalizedType.Contains("number", StringComparison.Ordinal))
        {
            return "1.5";
        }

        if (normalizedType.Contains("char", StringComparison.Ordinal))
        {
            return "a";
        }

        if (normalizedType.Contains("bool", StringComparison.Ordinal))
        {
            return "true";
        }

        if (normalizedType.Contains("timeonly", StringComparison.Ordinal))
        {
            return "12:00:00";
        }

        if (normalizedType.Contains("dateonly", StringComparison.Ordinal))
        {
            return "2026-03-01";
        }

        if (normalizedType.Contains("date", StringComparison.Ordinal) ||
            normalizedType.Contains("time", StringComparison.Ordinal))
        {
            return "2026-03-01T00:00:00Z";
        }

        return nameHint switch
        {
            "id" or "userid" or "orderid" or "productid" => "1",
            "username" or "user" => "apitester",
            "path" or "filepath" => "sample.txt",
            _ when nameHint.Contains("id", StringComparison.Ordinal) => "1",
            _ when nameHint.Contains("user", StringComparison.Ordinal) => "apitester",
            _ => "test"
        };
    }
}
