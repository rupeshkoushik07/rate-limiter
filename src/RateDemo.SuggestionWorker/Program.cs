// Suggestion worker: the only component that talks to the LLM.
// No ingress, no staff sessions, no Mews tokens, no Service Bus rights: if a prompt injection ever
// worked, it could only write a suggestion row, which still has to pass the guardrail.
// Triggers: webhook-driven requests (availability changed), staff clicks, and a timer for quiet rooms.
using Npgsql;
using RateDemo.Core;

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();
builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);
builder.Services.AddHttpClient();
builder.Services.AddSingleton<Claude>();
builder.Services.AddHostedService<SuggestionWorker>();
builder.Build().Run();

sealed class SuggestionWorker(Claude claude, ILogger<SuggestionWorker> log) : BackgroundService
{
    private static readonly TimeSpan Poll = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan QuietRoomInterval = TimeSpan.FromMinutes(30);

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        log.LogInformation("Suggestion worker started");
        var nextTimer = DateTime.UtcNow;
        while (!stop.IsCancellationRequested)
        {
            foreach (var hotel in Hotels.All)
            {
                try
                {
                    if (DateTime.UtcNow >= nextTimer) await QueueQuietRoomsAsync(hotel);
                    await ProcessRequestsAsync(hotel);
                }
                catch (Exception ex)
                {
                    log.LogWarning("Worker round for {Hotel} failed: {Error}", hotel, ex.GetType().Name);
                }
            }
            if (DateTime.UtcNow >= nextTimer) nextTimer = DateTime.UtcNow + QuietRoomInterval;
            await Task.Delay(Poll, stop);
        }
    }

    /// <summary>One suggestion per room per batch: many webhooks for the same room collapse into one LLM call.</summary>
    private async Task ProcessRequestsAsync(string hotel)
    {
        var pending = await Db.InHotelAsync(hotel, async (conn, tx) =>
        {
            await using var cmd = new NpgsqlCommand("""
                UPDATE suggestion_requests SET processed_at = now()
                WHERE processed_at IS NULL
                RETURNING room_type, trigger
                """, conn, tx);
            var rows = new List<(string Room, string Trigger)>();
            await using var r = await cmd.ExecuteReaderAsync();
            while (await r.ReadAsync()) rows.Add((r.GetString(0), r.GetString(1)));
            return rows;
        });
        foreach (var group in pending.GroupBy(p => p.Room))
        {
            var trigger = group.Select(g => g.Trigger).FirstOrDefault(t => t.StartsWith("staff")) ?? group.First().Trigger;
            var result = await Pricing.SuggestAsync(hotel, group.Key, trigger, claude, log);
            log.LogInformation("Request for {Hotel}/{Room} ({Count} triggers) -> {Result}", hotel, group.Key, group.Count(), result);
        }
    }

    /// <summary>Timer: rooms with data but no suggestion for a while get one (covers missed webhooks).</summary>
    private static Task QueueQuietRoomsAsync(string hotel) => Db.InHotelAsync(hotel, async (conn, tx) =>
    {
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO suggestion_requests (hotel_id, room_type, trigger)
            SELECT a.hotel_id, a.room_type, 'timer' FROM availability a
            WHERE NOT EXISTS (SELECT 1 FROM suggestions s WHERE s.room_type = a.room_type AND s.created_at > now() - @quiet)
              AND NOT EXISTS (SELECT 1 FROM suggestion_requests q WHERE q.room_type = a.room_type AND q.processed_at IS NULL)
            """, conn, tx);
        cmd.Parameters.AddWithValue("quiet", QuietRoomInterval);
        await cmd.ExecuteNonQueryAsync();
    });
}
