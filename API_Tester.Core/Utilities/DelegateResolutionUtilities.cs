using System.Reflection;

namespace ApiTester.Core;

public static class DelegateResolutionUtilities
{
    public static Func<Uri, Task<string>>[] ResolveTestDelegates(object instance, IEnumerable<string> methodNames)
    {
        return methodNames
            .Select(name => TryResolveRunTestDelegate(instance, name))
            .Where(static d => d is not null)
            .Cast<Func<Uri, Task<string>>>()
            .ToArray();
    }

    public static Func<Uri, Task<string>>? TryResolveRunTestDelegate(object instance, string methodName)
    {
        if (string.IsNullOrWhiteSpace(methodName))
        {
            return null;
        }

        var method = instance.GetType().GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic);
        if (method is null || method.ReturnType != typeof(Task<string>))
        {
            return null;
        }

        var parameters = method.GetParameters();
        if (parameters.Length != 1 || parameters[0].ParameterType != typeof(Uri))
        {
            return null;
        }

        return uri => (Task<string>)method.Invoke(instance, new object[] { uri })!;
    }
}
