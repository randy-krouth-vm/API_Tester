namespace ApiTester.Core;

public sealed record DynamicProbe(string Name, Func<Uri, Task<string>> Execute);

public sealed record FrameworkTestDescriptor(
    string FrameworkName,
    string TestKey,
    string TestName,
    Func<Uri, Task<string>> Execute);
