using System;
using System.Collections.Generic;
using System.Linq;

namespace API_Tester;

public partial class MainPage
{
    private static string[] ExpandHttpToHttps(IEnumerable<string> payloads)
        => payloads.SelectMany(ExpandHttpToHttps).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    private static IEnumerable<string> ExpandHttpToHttps(string payload)
    {
        if (payload.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            yield return payload;
            yield return "https://" + payload["http://".Length..];
            yield break;
        }

        if (payload.StartsWith("ws://", StringComparison.OrdinalIgnoreCase))
        {
            yield return payload;
            yield return "wss://" + payload["ws://".Length..];
            yield break;
        }

        if (payload.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase))
        {
            yield return payload;
            yield return "ftps://" + payload["ftp://".Length..];
            yield break;
        }

        if (payload.StartsWith("ldap://", StringComparison.OrdinalIgnoreCase))
        {
            yield return payload;
            yield return "ldaps://" + payload["ldap://".Length..];
            yield break;
        }

        yield return payload;
    }
}
