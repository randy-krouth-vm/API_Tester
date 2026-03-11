using System.Text;

namespace ApiTester.Core;

public static class DescriptorUtilities
{
    public static List<FrameworkTestDescriptor> BuildFrameworkTestDescriptors(
        string categoryName,
        IReadOnlyList<string> frameworks,
        IReadOnlyList<Func<Uri, Task<string>>> fallbackTests,
        Func<string, IReadOnlyList<string>> frameworkControlKeyResolver,
        Func<string, (string TestName, Func<Uri, Task<string>>? Test)> testResolver,
        Func<string, Func<Uri, Task<string>>, Func<Uri, Task<string>>> wrapWithStandardContext)
    {
        var descriptors = new List<FrameworkTestDescriptor>();
        foreach (var framework in frameworks)
        {
            foreach (var key in frameworkControlKeyResolver(framework))
            {
                var resolved = testResolver(key);
                if (resolved.Test is null)
                {
                    continue;
                }

                descriptors.Add(new FrameworkTestDescriptor(
                    framework,
                    key,
                    resolved.TestName,
                    wrapWithStandardContext(key, resolved.Test)));
            }
        }

        if (descriptors.Count > 0)
        {
            return descriptors;
        }

        var fallbackFramework = frameworks.FirstOrDefault() ?? categoryName;
        return fallbackTests
            .Select(test => new FrameworkTestDescriptor(
                fallbackFramework,
                $"CUSTOM.{test.Method.Name}",
                test.Method.Name,
                test))
            .ToList();
    }

    public static async Task<string> BuildRemainingAdvancedProbeReportAsync(
        Uri uri,
        HashSet<string> alreadyExecutedMethodNames,
        IEnumerable<DynamicProbe> probes)
    {
        var sb = new StringBuilder();
        sb.AppendLine("11) Additional Advanced Probes (deduped)");
        sb.AppendLine($"Target: {uri}");

        var remaining = probes
            .Where(p => !alreadyExecutedMethodNames.Contains(p.Name))
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .ToList();

        sb.AppendLine($"Probes executed: {remaining.Count}");
        sb.AppendLine();

        foreach (var probe in remaining)
        {
            try
            {
                sb.AppendLine(await probe.Execute(uri));
            }
            catch (Exception ex)
            {
                sb.AppendLine($"[{probe.Name}]");
                sb.AppendLine($"Target: {uri}");
                sb.AppendLine($"- Execution error: {ex.Message}");
            }

            sb.AppendLine();
        }

        if (remaining.Count == 0)
        {
            sb.AppendLine("- No remaining probes after standards/suite dedupe.");
        }

        return sb.ToString().TrimEnd();
    }
}

