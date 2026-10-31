// Webhook receiver: Mews tells us something changed.
// 1. Check the secret token in the URL with a constant-time compare.
// 2. Take IDs only from the body; never trust data in it.
// 3. Re-read the real data from Mews with this hotel's own AccessToken (from Key Vault).
// 4. Write Mews's answer to the database.
// So a forged webhook can at most cause one extra read. Reply fast: Mews waits 5 seconds.
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Npgsql;
using RateDemo.Core;

var builder = WebApplication.CreateBuilder(args);
// One JSON object per log line, so KQL can parse it. HttpClient request logs are off: they print full
// URLs, and a webhook URL carries its secret token in the query string.
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();
builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);   // request logs would include the URL token
builder.Services.AddHttpClient<MewsClient>(c => c.BaseAddress = new Uri(Settings.Get("MEWS_BASE_URL") + "/"));
var work = Channel.CreateBounded<(string Hotel, string Room)>(1000);
builder.Services.AddSingleton(work);
builder.Services.AddHostedService<Rereader>();
var app = builder.Build();

var recent = new ConcurrentDictionary<string, Queue<DateTime>>();

app.MapGet("/health", () => Results.Ok(new { ok = true }));

app.MapPost("/webhooks/mews", async (HttpContext ctx, string? token, ILogger<Program> log) =>
{
    var expected = (await Vault.GetAsync("mews-webhook-secret")).Reveal();
    // FixedTimeEquals takes the same time whether the first or the last character is wrong.
    if (token is null || !CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(token), Encoding.UTF8.GetBytes(expected)))
    {
        log.LogWarning("Webhook rejected: bad token");   // never log the URL: it carries the secret
        return Results.Unauthorized();
    }

    var body = await JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body);
    var hotel = body.TryGetProperty("EnterpriseId", out var e) ? e.GetString() : null;
    if (hotel is null || !Hotels.All.Contains(hotel))
    {
        log.LogWarning("Webhook ignored: unknown or missing EnterpriseId");   // visible to detection, not silent
        return Results.Accepted();
    }

    var q = recent.GetOrAdd(hotel, _ => new Queue<DateTime>());
    lock (q)
    {
        while (q.Count > 0 && DateTime.UtcNow - q.Peek() > TimeSpan.FromMinutes(1)) q.Dequeue();
        if (q.Count >= 60) return Results.StatusCode(429);
        q.Enqueue(DateTime.UtcNow);
    }

    if (body.TryGetProperty("Events", out var events) && events.ValueKind == JsonValueKind.Array)
        foreach (var ev in events.EnumerateArray().Take(20))
            if (ev.TryGetProperty("RoomType", out var r) && r.GetString() is { } room && Hotels.Rooms.Contains(room))
                work.Writer.TryWrite((hotel, room));   // reply now, re-read in the background
    return Results.Accepted();
});

app.Run();

sealed class Rereader(Channel<(string Hotel, string Room)> work, MewsClient mews, ILogger<Rereader> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        await foreach (var (hotel, room) in work.Reader.ReadAllAsync(stop))
        {
            try
            {
                var (price, occupancy) = await mews.GetPricingAsync(hotel, room, stop);
                await Db.InHotelAsync(hotel, async (conn, tx) =>
                {
                    await using var cmd = new NpgsqlCommand("""
                        INSERT INTO availability (hotel_id, room_type, occupancy_pct, current_price)
                        VALUES (@h, @r, @o, @p)
                        ON CONFLICT (hotel_id, room_type) DO UPDATE
                        SET occupancy_pct = EXCLUDED.occupancy_pct, current_price = EXCLUDED.current_price, updated_at = now()
                        """, conn, tx);
                    cmd.Parameters.AddWithValue("h", hotel);
                    cmd.Parameters.AddWithValue("r", room);
                    cmd.Parameters.AddWithValue("o", occupancy);
                    cmd.Parameters.AddWithValue("p", price);
                    await cmd.ExecuteNonQueryAsync(stop);
                    // Numbers changed: ask the suggestion worker for a fresh suggestion (same transaction).
                    await Pricing.RequestSuggestionAsync(conn, tx, hotel, room, "webhook");
                });
                log.LogInformation("Availability for {Hotel}/{Room} refreshed from Mews", hotel, room);
            }
            catch (Exception ex)
            {
                log.LogWarning("Re-read for {Hotel}/{Room} failed: {Error}", hotel, room, ex.GetType().Name);
            }
        }
    }
}
