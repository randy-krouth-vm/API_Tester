namespace ApiTester.Core;

public static class FrameworkResolutionWorkflowUtilities
{
    public static (string TestName, Func<Uri, Task<string>>? Test) ResolveTestByKey(object host, string testKey)
    {
        var metadata = Mappings.GetTestMethodMetadata(testKey);
        var resolved = metadata.MethodName is null
            ? null
            : DelegateResolutionUtilities.TryResolveRunTestDelegate(host, metadata.MethodName);
        return (metadata.TestName, resolved);
    }

    public static (string Category, Func<Uri, Task<string>>[] Tests)? GetFrameworkPackFor(object host, string frameworkName)
    {
        var mapping = Mappings.GetFrameworkPackMapping(frameworkName);
        if (mapping is null)
        {
            return null;
        }

        var tests = Mappings.GetFrameworkControlKeys(frameworkName)
            .Select(testKey => ResolveTestByKey(host, testKey).Test)
            .Where(test => test is not null)
            .Cast<Func<Uri, Task<string>>>()
            .Distinct()
            .ToArray();

        return (mapping.Category, tests);
    }

    public static IEnumerable<(string CategoryName, string[] Frameworks, Func<Uri, Task<string>>[] Tests)> GetStandardFrameworkPacks(object host)
    {
        foreach (var pack in SuiteCatalogMappings.GetStandardFrameworkPacks())
        {
            var resolvedTests = DelegateResolutionUtilities.ResolveTestDelegates(host, pack.TestMethodNames);
            if (resolvedTests.Length == 0)
            {
                continue;
            }

            yield return (pack.CategoryName, pack.Frameworks, resolvedTests);
        }
    }

    public static (string Name, Func<Uri, Task<string>>[] Tests)? GetNamedSuite(object host, string suiteKey)
    {
        var definition = SuiteCatalogMappings.GetNamedSuite(suiteKey);
        if (definition is null)
        {
            return null;
        }

        var resolvedTests = DelegateResolutionUtilities.ResolveTestDelegates(host, definition.TestMethodNames);
        if (resolvedTests.Length == 0)
        {
            return null;
        }

        return (definition.Name, resolvedTests);
    }

    public static ResolvedNamedSuiteRun? TryGetNamedSuiteRun(object host, string suiteKey)
    {
        var suite = GetNamedSuite(host, suiteKey);
        if (suite is null)
        {
            return null;
        }

        return new ResolvedNamedSuiteRun(suite.Value.Name, suite.Value.Tests);
    }
}
