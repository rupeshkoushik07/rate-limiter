// A tiny fake of the Mews Connector API, so every failure case can be triggered on demand.
// Like Mews where it matters: POST only, ClientToken + AccessToken in the JSON body, one AccessToken
// per hotel, 200 requests per AccessToken per 30 s (sliding window) -> 429 + Retry-After, a Request-Id
// on every response, and webhooks that carry IDs only, sent to a URL with a secret token in it.
// POST /chaos forces 409, 429, slow replies or "applied but the reply is lost".
using System.Collections.Concurrent;
using System.Text.Json;
using RateDemo.Core;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();
var app = builder.Build();

var prices = new ConcurrentDictionary<(string, string), decimal>
{
    [("barcelona", "double")] = 100m, [("barcelona", "suite")] = 220m,
    [("madrid", "double")] = 120m, [("madrid", "suite")] = 260m,
};
var occupancy = new ConcurrentDictionary<(string, string), int>(prices.Keys.Select(k => KeyValuePair.Create(k, 40)));
var windows = new ConcurrentDictionary<string, Queue<DateTime>>();
var chaos = new ConcurrentDictionary<string, int>(new[] { "conflict", "rate_limit", "slow", "lose_reply" }
    .Select(k => KeyValuePair.Create(k, 0)));

IResult Reply(HttpContext ctx, int status, object body, int? retryAfter = null)
{
    ctx.Response.Headers["Request-Id"] = Guid.NewGuid().ToString();
    if (retryAfter is not null) ctx.Response.Headers.RetryAfter = retryAfter.ToString();
    return Results.Json(body, statusCode: status);
}

bool Consume(string key)
{
    while (true)
    {
        var v = chaos[key];
        if (v <= 0) return false;
        if (chaos.TryUpdate(key, v - 1, v)) return true;
    }
}

async Task<(string? Hotel, JsonElement Body, IResult? Error)> Authenticate(HttpContext ctx)
{
    var body = await JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body);
    var client = (await Vault.GetAsync("mews-client-token")).Reveal();
    if (!body.TryGetProperty("ClientToken", out var ct) || ct.GetString() != client)
        return (null, body, Reply(ctx, 401, new { Message = "Invalid ClientToken." }));

    var access = body.TryGetProperty("AccessToken", out var at) ? at.GetString() ?? "" : "";
    string? hotel = null;
    foreach (var h in Hotels.All)
        if ((await Vault.GetAsync($"mews-access-token-{h}")).Reveal() == access) hotel = h;
    if (hotel is null)
        return (null, body, Reply(ctx, 401, new { Message = "Invalid AccessToken." }));

    var q = windows.GetOrAdd(access, _ => new Queue<DateTime>());
    lock (q)
    {
        while (q.Count > 0 && DateTime.UtcNow - q.Peek() > TimeSpan.FromSeconds(30)) q.Dequeue();
        if (q.Count >= 200 || Consume("rate_limit"))
            return (null, body, Reply(ctx, 429, new { Message = "Too many requests." }, retryAfter: 5));
        q.Enqueue(DateTime.UtcNow);
    }
    return (hotel, body, null);
}

app.MapGet("/health", () => Results.Ok(new { ok = true }));

app.MapPost("/api/connector/v1/rates/getPricing", async (HttpContext ctx) =>
{
    var (hotel, body, error) = await Authenticate(ctx);
    if (error is not null) return error;
    var room = body.GetProperty("RoomType").GetString()!;
    return prices.TryGetValue((hotel!, room), out var price)
        ? Reply(ctx, 200, new { RoomType = room, Price = price, OccupancyPct = occupancy[(hotel!, room)] })
        : Reply(ctx, 400, new { Message = "Unknown room type." });
});

app.MapPost("/api/connector/v1/rates/updatePrice", async (HttpContext ctx, ILogger<Program> log) =>
{
    var (hotel, body, error) = await Authenticate(ctx);
    if (error is not null) return error;
    var key = (hotel!, body.GetProperty("RoomType").GetString()!);
    if (!prices.ContainsKey(key)) return Reply(ctx, 400, new { Message = "Unknown room type." });

    if (Consume("conflict"))
    {
        prices[key] = Math.Round(prices[key] * 0.95m, 2);   // someone else changed the price meanwhile
        return Reply(ctx, 409, new { Message = "The data has changed. Refresh and resubmit." });
    }
    if (Consume("slow")) await Task.Delay(TimeSpan.FromSeconds(15));

    prices[key] = body.GetProperty("Price").GetDecimal();
    log.LogInformation("Price updated for {Hotel}/{Room}", key.Item1, key.Item2);
    if (Consume("lose_reply")) await Task.Delay(TimeSpan.FromSeconds(60));   // applied, caller times out
    return Reply(ctx, 200, new { });
});

app.MapPost("/chaos", async (HttpContext ctx) =>
{
    var body = await JsonSerializer.DeserializeAsync<Dictionary<string, int>>(ctx.Request.Body) ?? new();
    foreach (var (k, v) in body) if (chaos.ContainsKey(k)) chaos[k] = v;
    return Results.Ok(chaos);
});

app.MapGet("/state", () => Results.Ok(prices.Select(p => new
{
    hotel = p.Key.Item1, room = p.Key.Item2, price = p.Value, occupancy = occupancy[p.Key],
})));

// The hotel's public booking page: what guests see. Prices come straight from "Mews", so an approved
// discount shows up here once the rate writer has applied it.
app.MapGet("/hotel/{hotel}", (string hotel) =>
{
    if (!Hotels.All.Contains(hotel)) return Results.NotFound();
    var name = System.Net.WebUtility.HtmlEncode(char.ToUpper(hotel[0]) + hotel[1..]);
    var rows = string.Concat(prices.Where(p => p.Key.Item1 == hotel).Select(p =>
        $"<tr><td>{System.Net.WebUtility.HtmlEncode(p.Key.Item2)}</td><td>€{p.Value:0.00}</td><td>{100 - occupancy[p.Key]}% of rooms left</td></tr>"));
    return Results.Content($$"""
        <!doctype html><html><head><meta charset="utf-8"><title>Hotel {{name}}</title><meta http-equiv="refresh" content="5">
        <style>body{font-family:Georgia,serif;max-width:640px;margin:40px auto;padding:0 16px}
        table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #ddd;padding:10px;text-align:left}</style></head>
        <body><h1>Hotel {{name}}</h1><p>Book a room for tonight. Prices update live.</p>
        <table><tr><th>Room</th><th>Price per night</th><th>Availability</th></tr>{{rows}}</table></body></html>
        """, "text/html; charset=utf-8");
});

// Pretend a guest booked: occupancy rises and Mews sends a webhook that carries IDs only.
app.MapPost("/simulate/booking", async (HttpContext ctx, IHttpClientFactory factory) =>
{
    var body = await JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body);
    var key = (body.GetProperty("hotel").GetString()!, body.GetProperty("room").GetString()!);
    occupancy[key] = Math.Min(100, occupancy[key] + 10);
    var secret = (await Vault.GetAsync("mews-webhook-secret")).Reveal();
    var url = $"{Settings.Get("WEBHOOK_URL")}?token={Uri.EscapeDataString(secret)}";
    var payload = new { EnterpriseId = key.Item1, Events = new[] { new { Type = "RateChanged", RoomType = key.Item2 } } };
    var response = await factory.CreateClient().PostAsJsonAsync(url, payload);
    return Results.Ok(new { webhookStatus = (int)response.StatusCode, occupancy = occupancy[key] });
});

app.Run();
