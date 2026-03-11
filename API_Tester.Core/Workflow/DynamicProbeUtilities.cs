using System.Reflection;

namespace ApiTester.Core;

public static class DynamicProbeUtilities
{
    public static IEnumerable<DynamicProbe> BuildDynamicProbes(object owner, IReadOnlySet<string> excludedMethodNames)
    {
        var methods = owner.GetType()
            .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic)
            .Where(m =>
                m.Name.StartsWith("Run", StringComparison.Ordinal) &&
                m.Name.EndsWith("TestsAsync", StringComparison.Ordinal) &&
                !excludedMethodNames.Contains(m.Name) &&
                m.ReturnType == typeof(Task<string>))
            .Where(m =>
            {
                var p = m.GetParameters();
                return p.Length == 1 && p[0].ParameterType == typeof(Uri);
            })
            .OrderBy(m => m.Name, StringComparer.Ordinal)
            .ToList();

        return methods.Select(method => new DynamicProbe(
            method.Name,
            uri => (Task<string>)method.Invoke(owner, new object[] { uri })!));
    }
}
