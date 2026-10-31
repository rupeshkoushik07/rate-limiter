using System.Text.Json;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace RateDemo.Core;

/// <summary>
/// The pricing flow shared by the API (staff approvals) and the suggestion worker (AI + auto-apply):
/// suggestion requests, suggestions through the guardrail, approvals into the outbox, and the
/// auto-apply safety switches (per-hotel limit, kill switch, circuit breaker).
/// </summary>
public static class Pricing
{
    public const int CircuitBreakerMaxAutoChangesPerHour = 3;

    /// <summary>Ask for a suggestion. The worker picks it up; the API itself never calls the LLM.</summary>
    public static Task RequestSuggestionAsync(NpgsqlConnection conn, NpgsqlTransaction tx, string hotel, string room, string trigger) =>
        Exec(conn, tx, "INSERT INTO suggestion_requests (hotel_id, room_type, trigger) VALUES (@h, @r, @t)",
            ("h", hotel), ("r", room), ("t", trigger));

    public static Task RequestSuggestionAsync(string hotel, string room, string trigger) =>
        Db.InHotelAsync(hotel, (conn, tx) => RequestSuggestionAsync(conn, tx, hotel, room, trigger));

    /// <summary>Numbers in, guardrail verdict out, saved. Auto-applies only inside every safety switch.</summary>
    public static async Task<string> SuggestAsync(string hotel, string room, string trigger, Claude claude, ILogger log)
    {
        var state = await Db.InHotelAsync(hotel, async (conn, tx) =>
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT r.min_price, r.max_discount_pct, r.auto_apply_max_pct, r.max_changes_per_day, r.auto_apply_paused,
                       a.occupancy_pct, a.current_price,
                       (SELECT count(*) FROM approvals p WHERE p.room_type = @room AND p.created_at > now() - interval '1 day')
                FROM hotel_rules r LEFT JOIN availability a ON a.hotel_id = r.hotel_id AND a.room_type = @room
                """, conn, tx);
            cmd.Parameters.AddWithValue("room", room);
            await using var r = await cmd.ExecuteReaderAsync();
            await r.ReadAsync();
            var rules = new HotelRules(r.GetDecimal(0), r.GetInt32(1), r.GetInt32(2), r.GetInt32(3));
            (int Occ, decimal Price)? avail = r.IsDBNull(5) ? null : (r.GetInt32(5), r.GetDecimal(6));
            return (rules, Paused: r.GetBoolean(4), avail, Changes: (int)r.GetInt64(7));
        });
        if (state.avail is not { } avail) return "no availability yet";

        // Only Mews numbers go into the prompt, for this one hotel. No free text from anywhere.
        var raw = await claude.SuggestAsync(avail.Occ, avail.Price, state.rules.MinPrice, state.rules.MaxDiscountPct);
        var verdict = raw is { } json ? Guardrail.Check(json, avail.Price, state.rules, state.Changes)
                                      : Verdict.Reject("LLM answer was not JSON");

        int? pct = raw is { ValueKind: JsonValueKind.Object } j && j.TryGetProperty("discount_pct", out var p)
                   && p.ValueKind == JsonValueKind.Number && p.TryGetInt32(out var v) ? v : null;
        string? reason = raw is { ValueKind: JsonValueKind.Object } k && k.TryGetProperty("reason", out var rs)
                   && rs.ValueKind == JsonValueKind.String ? rs.GetString()![..Math.Min(200, rs.GetString()!.Length)] : null;

        var id = await Db.InHotelAsync(hotel, async (conn, tx) =>
        {
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO suggestions (hotel_id, room_type, based_on, discount_pct, new_price, reason, guardrail, trigger)
                VALUES (@h, @r, @b, @pct, @np, @reason, @g, @t) RETURNING id
                """, conn, tx);
            cmd.Parameters.AddWithValue("h", hotel);
            cmd.Parameters.AddWithValue("r", room);
            cmd.Parameters.AddWithValue("b", avail.Price);
            cmd.Parameters.AddWithValue("pct", (object?)pct ?? DBNull.Value);
            cmd.Parameters.AddWithValue("np", (object?)verdict.NewPrice ?? DBNull.Value);
            cmd.Parameters.AddWithValue("reason", (object?)reason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("g", verdict.Reason);
            cmd.Parameters.AddWithValue("t", trigger);
            return (long)(await cmd.ExecuteScalarAsync())!;
        });
        log.LogInformation("Suggestion {Id} for {Hotel}/{Room} ({Trigger}): {Pct}% guardrail {Result}",
            id, hotel, room, trigger, pct, verdict.Reason);

        if (!verdict.Ok || !verdict.AutoApply || pct == 0) return verdict.Reason;
        if (state.Paused)
        {
            log.LogWarning("Auto-apply skipped for {Hotel}: paused", hotel);
            return "ok (auto-apply paused: waiting for staff)";
        }
        if (await TripCircuitBreakerAsync(hotel, log)) return "ok (circuit breaker tripped: waiting for staff)";

        var approvalId = await EnqueueApprovalAsync(hotel, id, room, avail.Price, verdict.NewPrice!.Value,
            "system:auto-apply", "Auto-apply");
        log.LogInformation("Auto-applied suggestion {Id} for {Hotel}/{Room} as approval {ApprovalId}", id, hotel, room, approvalId);
        return "ok (auto-applied)";
    }

    /// <summary>Too many automatic changes in an hour: pause auto-apply for this hotel until a human resumes it.</summary>
    private static async Task<bool> TripCircuitBreakerAsync(string hotel, ILogger log)
    {
        var recent = await Db.InHotelAsync(hotel, async (conn, tx) =>
        {
            await using var cmd = new NpgsqlCommand(
                "SELECT count(*) FROM approvals WHERE approver_oid = 'system:auto-apply' AND created_at > now() - interval '1 hour'", conn, tx);
            return (long)(await cmd.ExecuteScalarAsync())!;
        });
        if (recent < CircuitBreakerMaxAutoChangesPerHour) return false;
        await SetPausedAsync(hotel, true, $"circuit breaker: {recent} automatic changes in the last hour");
        log.LogWarning("CIRCUIT BREAKER tripped for {Hotel}: {Count} automatic changes in 1h; auto-apply paused", hotel, recent);
        return true;
    }

    public static Task SetPausedAsync(string hotel, bool paused, string reason) =>
        Db.InHotelAsync(hotel, (conn, tx) => Exec(conn, tx,
            "UPDATE hotel_rules SET auto_apply_paused = @p, paused_reason = @r WHERE hotel_id = @h",
            ("p", paused), ("r", paused ? reason : (object)DBNull.Value), ("h", hotel)));

    /// <summary>The outbox: approval and its outgoing message in ONE transaction, so neither exists without the other.</summary>
    public static async Task<Guid> EnqueueApprovalAsync(string hotel, long suggestionId, string room, decimal basedOn,
        decimal newPrice, string approverOid, string approverName)
    {
        var approvalId = Guid.NewGuid();   // fixed now; becomes the Service Bus MessageId, the same on every resend
        var message = new ApprovedRate(approvalId, hotel, room, basedOn, newPrice, DateTimeOffset.UtcNow.AddMinutes(20));
        await Db.InHotelAsync(hotel, async (conn, tx) =>
        {
            await Exec(conn, tx, """
                INSERT INTO approvals (approval_id, hotel_id, room_type, based_on, new_price, suggestion_id, approver_oid, approver_name)
                VALUES (@id, @h, @r, @b, @n, @s, @oid, @name)
                """, ("id", approvalId), ("h", hotel), ("r", room), ("b", basedOn), ("n", newPrice), ("s", suggestionId),
                ("oid", approverOid), ("name", approverName));
            await Exec(conn, tx, "INSERT INTO outbox (approval_id, hotel_id, payload) VALUES (@id, @h, @p::jsonb)",
                ("id", approvalId), ("h", hotel), ("p", JsonSerializer.Serialize(message)));
        });
        return approvalId;
    }

    private static async Task Exec(NpgsqlConnection conn, NpgsqlTransaction tx, string sql, params (string Name, object Value)[] ps)
    {
        await using var cmd = new NpgsqlCommand(sql, conn, tx);
        foreach (var (name, value) in ps) cmd.Parameters.AddWithValue(name, value);
        await cmd.ExecuteNonQueryAsync();
    }
}
