// Dashboard + API + Guardrail. Internet-facing (behind an IP allow-list), so it holds no Mews tokens
// and can't read them: its identity may read only the Anthropic key and the Entra client secret.
using System.Text.Json;
using Azure.Messaging.ServiceBus;
using Npgsql;
using RateDemo.Api;
using RateDemo.Core;

var builder = WebApplication.CreateBuilder(args);
// One JSON object per log line, so KQL can parse it. HttpClient request logs are off: they print full
// URLs, and a webhook URL carries its secret token in the query string.
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();
builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
builder.Services.AddHttpClient();
builder.Services.AddSingleton<OidcLogin>();
builder.Services.AddSingleton(_ => new ServiceBusClient(Settings.Get("SERVICEBUS_FQDN"), Settings.Credential));
builder.Services.AddHostedService<OutboxRelay>();
var app = builder.Build();

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'";
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next();
});

app.MapGet("/health", () => Results.Ok(new { ok = true }));

// ---------- Login (OIDC + PKCE) ----------
app.MapGet("/login", (OidcLogin oidc) => Results.Redirect(oidc.BeginLogin()));

app.MapGet("/signin-oidc", async (string? code, string? state, string? error, OidcLogin oidc, HttpContext ctx) =>
{
    if (error is not null || code is null || state is null)
        return Results.Content(Pages.Message("Sign-in failed", error ?? "missing code"), "text/html; charset=utf-8", statusCode: 401);
    try
    {
        var session = await oidc.CompleteLoginAsync(code, state);
        ctx.Response.Cookies.Append(OidcLogin.CookieName, session.Id, new CookieOptions
        {
            HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = "/", Expires = session.ExpiresAt,
        });
        return Results.Redirect("/");
    }
    catch (Exception ex)
    {
        app.Logger.LogWarning("Login rejected: {Error}", ex.Message);
        return Results.Content(Pages.Message("Sign-in rejected", ex.Message), "text/html; charset=utf-8", statusCode: 401);
    }
});

app.MapPost("/logout", async (HttpContext ctx) =>
{
    if (ctx.Request.Cookies.TryGetValue(OidcLogin.CookieName, out var id)) await OidcLogin.DeleteAsync(id);
    ctx.Response.Cookies.Delete(OidcLogin.CookieName, new CookieOptions { Secure = true, Path = "/" });
    // Single sign-out: also end the Microsoft session, or the next sign-in is silent (shared front-desk PCs).
    return Results.Redirect($"https://login.microsoftonline.com/{Settings.Get("ENTRA_TENANT_ID")}/oauth2/v2.0/logout");
});

// ---------- Pages ----------
app.MapGet("/", async (HttpContext ctx) =>
{
    var s = await OidcLogin.FromRequestAsync(ctx);
    if (s is null) return Results.Content(Pages.SignIn(), "text/html; charset=utf-8");
    var hotels = new List<Pages.HotelView>();
    foreach (var hotel in s.Hotels) hotels.Add(await Pages.LoadHotelAsync(hotel));
    return Results.Content(Pages.Dashboard(s, hotels), "text/html; charset=utf-8");
});

app.MapGet("/me", async (HttpContext ctx) =>
{
    var s = await OidcLogin.FromRequestAsync(ctx);
    return s is null ? Results.Redirect("/") : Results.Content(Pages.Me(s), "text/html; charset=utf-8");
});

// ---------- Actions (JSON, called by the dashboard) ----------
// Every action: session from the cookie, JWT re-validated, hotel must be in the token, role must allow it.
// The hotel in the URL is only a request; RLS + HasHotel decide.
// The API never calls the LLM: it records a request and the suggestion worker answers within seconds.
app.MapPost("/api/hotels/{hotel}/rooms/{room}/suggest", async (string hotel, string room, HttpContext ctx) =>
{
    var s = await AuthorizeAsync(ctx, hotel);
    if (s is null) return Results.Forbid();
    if (!Hotels.Rooms.Contains(room)) return Results.BadRequest();
    await Pricing.RequestSuggestionAsync(hotel, room, $"staff: {s.Name}");
    return Results.Ok(new { queued = true, note = "the suggestion worker will add it in a few seconds" });
});

app.MapPost("/api/suggestions/{id:long}/approve", async (long id, string hotel, HttpContext ctx) =>
{
    var s = await AuthorizeAsync(ctx, hotel);
    if (s is null) return Results.Forbid();
    if (!s.CanApprove) return Results.Json(new { error = "your role can't approve" }, statusCode: 403);
    var row = await Db.InHotelAsync(hotel, async (conn, tx) =>
    {
        await using var cmd = new NpgsqlCommand("""
            SELECT room_type, based_on, new_price, discount_pct FROM suggestions
            WHERE id = @id AND guardrail = 'ok' AND rejected_by IS NULL
            """, conn, tx);
        cmd.Parameters.AddWithValue("id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        return await r.ReadAsync() ? (r.GetString(0), r.GetDecimal(1), r.GetDecimal(2), r.GetInt32(3)) : ((string, decimal, decimal, int)?)null;
    });
    // RLS means another hotel's suggestion simply isn't found (no IDOR).
    if (row is not { } sg) return Results.NotFound(new { error = "no approvable suggestion with that id for this hotel" });
    if (sg.Item4 > s.MaxApprovablePct) return Results.Json(new { error = $"your role can approve up to {s.MaxApprovablePct}%" }, statusCode: 403);
    var approvalId = await Pricing.EnqueueApprovalAsync(hotel, id, sg.Item1, sg.Item2, sg.Item3, s.Oid, s.Name);
    return Results.Ok(new { approvalId, status = "pending" });
});

// Kill switch: anyone who can approve may PAUSE auto-apply (the safe direction); only a Manager may resume.
app.MapPost("/api/hotels/{hotel}/auto-apply/{action}", async (string hotel, string action, HttpContext ctx) =>
{
    var s = await AuthorizeAsync(ctx, hotel);
    if (s is null) return Results.Forbid();
    if (action == "pause" && s.CanApprove)
        await Pricing.SetPausedAsync(hotel, true, $"paused by {s.Name}");
    else if (action == "resume" && s.Roles.Contains("Manager"))
        await Pricing.SetPausedAsync(hotel, false, "");
    else
        return Results.Json(new { error = "pausing needs Approver; resuming needs Manager" }, statusCode: 403);
    app.Logger.LogWarning("Auto-apply {Action} for {Hotel} by {Oid}", action, hotel, s.Oid);
    return Results.Ok(new { hotel, action });
});

app.MapPost("/api/suggestions/{id:long}/reject", async (long id, string hotel, HttpContext ctx) =>
{
    var s = await AuthorizeAsync(ctx, hotel);
    if (s is null) return Results.Forbid();
    if (!s.CanApprove) return Results.Json(new { error = "your role can't reject" }, statusCode: 403);
    var updated = await Db.InHotelAsync(hotel, async (conn, tx) =>
    {
        await using var cmd = new NpgsqlCommand(
            "UPDATE suggestions SET rejected_by = @who WHERE id = @id AND rejected_by IS NULL", conn, tx);
        cmd.Parameters.AddWithValue("who", s.Name);
        cmd.Parameters.AddWithValue("id", id);
        return await cmd.ExecuteNonQueryAsync();
    });
    app.Logger.LogInformation("Suggestion {Id} for {Hotel} rejected by {Oid}", id, hotel, s.Oid);
    return updated == 1 ? Results.Ok(new { rejected = id }) : Results.NotFound();
});

// CODEQL CANARY: deliberately vulnerable, never merge. SQL injection + open redirect.
app.MapGet("/api/canary/search", async (HttpContext ctx) =>
{
    string room = ctx.Request.Query["room"]!;
    var count = await Db.InHotelAsync("barcelona", async (conn, tx) =>
    {
        await using var cmd = new NpgsqlCommand { Connection = conn, Transaction = tx };
        cmd.CommandText = "SELECT count(*) FROM availability WHERE room = '" + room + "'";
        return await cmd.ExecuteScalarAsync();
    });
    return Results.Ok(new { count });
});
app.MapGet("/api/canary/go", (HttpContext ctx) =>
{
    ctx.Response.Redirect(ctx.Request.Query["next"]!);
    return Task.CompletedTask;
});

// The hotels' public booking pages (what guests see), served by "Mews". No login: it's the public website.
app.MapGet("/hotel/{hotel}", async (string hotel, IHttpClientFactory factory) =>
{
    if (!Hotels.All.Contains(hotel)) return Results.NotFound();
    var html = await factory.CreateClient().GetStringAsync($"{Settings.Get("FAKE_MEWS_URL")}/hotel/{hotel}");
    return Results.Content(html, "text/html; charset=utf-8");
});

// Demo-only controls that poke the fake Mews (simulate a booking, force failures). Not part of the real design.
app.MapPost("/api/demo/{action}", async (string action, HttpContext ctx, IHttpClientFactory factory) =>
{
    var s = await OidcLogin.FromRequestAsync(ctx);
    if (s is null || !ctx.Request.Headers.ContainsKey("X-Requested-With")) return Results.Forbid();
    var body = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
    var path = action switch { "booking" => "simulate/booking", "chaos" => "chaos", _ => null };
    if (path is null) return Results.NotFound();
    var r = await factory.CreateClient().PostAsync($"{Settings.Get("FAKE_MEWS_URL")}/{path}",
        new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
    return Results.Content(await r.Content.ReadAsStringAsync(), "application/json");
});

app.Run();

static async Task<StaffSession?> AuthorizeAsync(HttpContext ctx, string hotel)
{
    if (!ctx.Request.Headers.ContainsKey("X-Requested-With")) return null;   // CSRF: forms can't set this header
    var s = await OidcLogin.FromRequestAsync(ctx);
    return s is not null && s.HasHotel(hotel) ? s : null;                    // hotel must be in the token
}

/// <summary>
/// The relay: every 2 s, publish unsent outbox rows to Service Bus with this identity's Sender role, then mark
/// them sent. A crash after sending means a resend with the SAME MessageId, which duplicate detection drops.
/// </summary>
sealed class OutboxRelay(ServiceBusClient bus, ILogger<OutboxRelay> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        await using var sender = bus.CreateSender(Settings.Get("QUEUE_NAME"));
        while (!stop.IsCancellationRequested)
        {
            try
            {
                await Db.InHotelAsync(null, async (conn, tx) =>
                {
                    await using var cmd = new NpgsqlCommand("""
                        SELECT approval_id, hotel_id, payload::text FROM outbox
                        WHERE sent_at IS NULL ORDER BY approval_id LIMIT 20 FOR UPDATE SKIP LOCKED
                        """, conn, tx);
                    var rows = new List<(Guid, string, string)>();
                    await using (var r = await cmd.ExecuteReaderAsync(stop))
                        while (await r.ReadAsync(stop)) rows.Add((r.GetGuid(0), r.GetString(1), r.GetString(2)));
                    foreach (var (id, hotel, payload) in rows)
                    {
                        await sender.SendMessageAsync(new ServiceBusMessage(payload)
                        {
                            MessageId = id.ToString(),          // = approval ID -> duplicate detection works on resends
                            SessionId = hotel,                  // one session per hotel -> in order per hotel
                            TimeToLive = TimeSpan.FromMinutes(20),
                            ContentType = "application/json",
                        }, stop);
                        await using var done = new NpgsqlCommand("UPDATE outbox SET sent_at = now() WHERE approval_id = @id", conn, tx);
                        done.Parameters.AddWithValue("id", id);
                        await done.ExecuteNonQueryAsync(stop);
                        log.LogInformation("Relay published approval {ApprovalId} for {Hotel}", id, hotel);
                    }
                }, user: "relay_user");
            }
            catch (Exception ex) when (!stop.IsCancellationRequested)
            {
                log.LogWarning("Relay round failed ({Error}); will retry", ex.GetType().Name);
            }
            await Task.Delay(TimeSpan.FromSeconds(2), stop);
        }
    }
}
