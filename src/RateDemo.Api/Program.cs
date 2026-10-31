// Dashboard + API + Guardrail. Internet-facing (behind an IP allow-list), so it holds no Mews tokens
// and can't read them: its identity may read only the Anthropic key and the Entra client secret.
using System.Text.Json;
using Azure.Messaging.ServiceBus;
using Npgsql;
using RateDemo.Api;
using RateDemo.Core;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
builder.Services.AddHttpClient();
builder.Services.AddSingleton<OidcLogin>();
builder.Services.AddSingleton<Claude>();
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
        return Results.Content(Pages.Message("Sign-in failed", error ?? "missing code"), "text/html", statusCode: 401);
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
        return Results.Content(Pages.Message("Sign-in rejected", ex.Message), "text/html", statusCode: 401);
    }
});

app.MapPost("/logout", async (HttpContext ctx) =>
{
    if (ctx.Request.Cookies.TryGetValue(OidcLogin.CookieName, out var id)) await OidcLogin.DeleteAsync(id);
    ctx.Response.Cookies.Delete(OidcLogin.CookieName, new CookieOptions { Secure = true, Path = "/" });
    return Results.Redirect("/");
});

// ---------- Pages ----------
app.MapGet("/", async (HttpContext ctx) =>
{
    var s = await OidcLogin.FromRequestAsync(ctx);
    if (s is null) return Results.Content(Pages.SignIn(), "text/html");
    var hotels = new List<Pages.HotelView>();
    foreach (var hotel in s.Hotels) hotels.Add(await Pages.LoadHotelAsync(hotel));
    return Results.Content(Pages.Dashboard(s, hotels), "text/html");
});

app.MapGet("/me", async (HttpContext ctx) =>
{
    var s = await OidcLogin.FromRequestAsync(ctx);
    return s is null ? Results.Redirect("/") : Results.Content(Pages.Me(s), "text/html");
});

// ---------- Actions (JSON, called by the dashboard) ----------
// Every action: session from the cookie, JWT re-validated, hotel must be in the token, role must allow it.
// The hotel in the URL is only a request; RLS + HasHotel decide.
app.MapPost("/api/hotels/{hotel}/rooms/{room}/suggest", async (string hotel, string room, HttpContext ctx, Claude claude) =>
{
    var s = await AuthorizeAsync(ctx, hotel);
    if (s is null) return Results.Forbid();
    if (!Hotels.Rooms.Contains(room)) return Results.BadRequest();
    return Results.Ok(await Suggestions.CreateAsync(hotel, room, claude, app.Logger));
});

app.MapPost("/api/suggestions/{id:long}/approve", async (long id, string hotel, HttpContext ctx) =>
{
    var s = await AuthorizeAsync(ctx, hotel);
    if (s is null) return Results.Forbid();
    if (!s.CanApprove) return Results.Json(new { error = "your role can't approve" }, statusCode: 403);
    return await Suggestions.ApproveAsync(hotel, id, s.Oid, s.Name, s.MaxApprovablePct);
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

static class Suggestions
{
    public static async Task<object> CreateAsync(string hotel, string room, Claude claude, ILogger log)
    {
        var (rules, avail, changesToday) = await Db.InHotelAsync(hotel, async (conn, tx) =>
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT r.min_price, r.max_discount_pct, r.auto_apply_max_pct, r.max_changes_per_day,
                       a.occupancy_pct, a.current_price,
                       (SELECT count(*) FROM approvals p WHERE p.room_type = @room AND p.created_at > now() - interval '1 day')
                FROM hotel_rules r LEFT JOIN availability a ON a.hotel_id = r.hotel_id AND a.room_type = @room
                """, conn, tx);
            cmd.Parameters.AddWithValue("room", room);
            await using var r = await cmd.ExecuteReaderAsync();
            await r.ReadAsync();
            var rules = new HotelRules(r.GetDecimal(0), r.GetInt32(1), r.GetInt32(2), r.GetInt32(3));
            (int Occ, decimal Price)? avail = r.IsDBNull(4) ? null : (r.GetInt32(4), r.GetDecimal(5));
            return (rules, avail, (int)r.GetInt64(6));
        });
        if (avail is null) return new { error = "no availability yet: simulate a booking so Mews sends a webhook" };

        // Only Mews numbers go into the prompt, for this one hotel. No free text from anywhere.
        var raw = await claude.SuggestAsync(avail.Value.Occ, avail.Value.Price, rules.MinPrice, rules.MaxDiscountPct);
        var verdict = raw is { } json ? Guardrail.Check(json, avail.Value.Price, rules, changesToday)
                                      : Verdict.Reject("LLM answer was not JSON");
        log.LogInformation("Suggestion for {Hotel}/{Room}: guardrail {Result}", hotel, room, verdict.Reason);

        int? pct = raw is { } j && j.ValueKind == JsonValueKind.Object && j.TryGetProperty("discount_pct", out var p)
                   && p.TryGetInt32(out var v) ? v : null;
        string? reason = raw is { } k && k.ValueKind == JsonValueKind.Object && k.TryGetProperty("reason", out var rs)
                   && rs.ValueKind == JsonValueKind.String ? rs.GetString()![..Math.Min(200, rs.GetString()!.Length)] : null;

        var id = await Db.InHotelAsync(hotel, async (conn, tx) =>
        {
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO suggestions (hotel_id, room_type, based_on, discount_pct, new_price, reason, guardrail)
                VALUES (@h, @r, @b, @pct, @np, @reason, @g) RETURNING id
                """, conn, tx);
            cmd.Parameters.AddWithValue("h", hotel);
            cmd.Parameters.AddWithValue("r", room);
            cmd.Parameters.AddWithValue("b", avail.Value.Price);
            cmd.Parameters.AddWithValue("pct", (object?)pct ?? DBNull.Value);
            cmd.Parameters.AddWithValue("np", (object?)verdict.NewPrice ?? DBNull.Value);
            cmd.Parameters.AddWithValue("reason", (object?)reason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("g", verdict.Reason);
            return (long)(await cmd.ExecuteScalarAsync())!;
        });

        if (verdict.Ok && verdict.AutoApply)   // hotel opted in and the discount is inside its auto-apply range
            await EnqueueApprovalAsync(hotel, id, room, avail.Value.Price, verdict.NewPrice!.Value, "auto-apply", "Auto-apply");
        return new { id, verdict.Ok, verdict.Reason, verdict.NewPrice, verdict.AutoApply };
    }

    public static async Task<IResult> ApproveAsync(string hotel, long suggestionId, string oid, string name, int maxPct)
    {
        var row = await Db.InHotelAsync(hotel, async (conn, tx) =>
        {
            await using var cmd = new NpgsqlCommand(
                "SELECT room_type, based_on, new_price, discount_pct FROM suggestions WHERE id = @id AND guardrail = 'ok'", conn, tx);
            cmd.Parameters.AddWithValue("id", suggestionId);
            await using var r = await cmd.ExecuteReaderAsync();
            return await r.ReadAsync() ? (r.GetString(0), r.GetDecimal(1), r.GetDecimal(2), r.GetInt32(3)) : ((string, decimal, decimal, int)?)null;
        });
        // RLS means another hotel's suggestion simply isn't found (no IDOR).
        if (row is not { } s) return Results.NotFound(new { error = "no approvable suggestion with that id for this hotel" });
        if (s.Item4 > maxPct) return Results.Json(new { error = $"your role can approve up to {maxPct}%" }, statusCode: 403);
        var approvalId = await EnqueueApprovalAsync(hotel, suggestionId, s.Item1, s.Item2, s.Item3, oid, name);
        return Results.Ok(new { approvalId, status = "pending" });
    }

    /// <summary>The outbox: approval and its outgoing message in ONE transaction, so neither exists without the other.</summary>
    private static async Task<Guid> EnqueueApprovalAsync(string hotel, long suggestionId, string room, decimal basedOn,
        decimal newPrice, string oid, string name)
    {
        var approvalId = Guid.NewGuid();   // fixed now; becomes the Service Bus MessageId, the same on every resend
        var message = new ApprovedRate(approvalId, hotel, room, basedOn, newPrice, DateTimeOffset.UtcNow.AddMinutes(20));
        await Db.InHotelAsync(hotel, async (conn, tx) =>
        {
            await using var a = new NpgsqlCommand("""
                INSERT INTO approvals (approval_id, hotel_id, room_type, based_on, new_price, suggestion_id, approver_oid, approver_name)
                VALUES (@id, @h, @r, @b, @n, @s, @oid, @name)
                """, conn, tx);
            a.Parameters.AddWithValue("id", approvalId);
            a.Parameters.AddWithValue("h", hotel);
            a.Parameters.AddWithValue("r", room);
            a.Parameters.AddWithValue("b", basedOn);
            a.Parameters.AddWithValue("n", newPrice);
            a.Parameters.AddWithValue("s", suggestionId);
            a.Parameters.AddWithValue("oid", oid);
            a.Parameters.AddWithValue("name", name);
            await a.ExecuteNonQueryAsync();
            await using var o = new NpgsqlCommand(
                "INSERT INTO outbox (approval_id, hotel_id, payload) VALUES (@id, @h, @p::jsonb)", conn, tx);
            o.Parameters.AddWithValue("id", approvalId);
            o.Parameters.AddWithValue("h", hotel);
            o.Parameters.AddWithValue("p", JsonSerializer.Serialize(message));
            await o.ExecuteNonQueryAsync();
        });
        return approvalId;
    }
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
