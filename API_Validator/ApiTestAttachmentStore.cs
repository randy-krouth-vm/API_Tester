using System.Collections.Concurrent;

namespace ApiValidator;

public sealed class ApiTestAttachmentStore
{
    private readonly ConcurrentQueue<ApiTestAttachment> _items = new();
    private readonly int _maxEntries;

    public ApiTestAttachmentStore(int maxEntries = 2000)
    {
        _maxEntries = Math.Max(1, maxEntries);
    }

    public void Add(ApiTestAttachment attachment)
    {
        _items.Enqueue(attachment);
        while (_items.Count > _maxEntries && _items.TryDequeue(out _))
        {
        }
    }

    public IReadOnlyList<ApiTestAttachment> GetAll()
        => _items.ToArray();

    public void Clear()
    {
        while (_items.TryDequeue(out _))
        {
        }
    }
}
