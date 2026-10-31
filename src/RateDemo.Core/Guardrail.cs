using System.Text.Json;

namespace RateDemo.Core;

public sealed record HotelRules(decimal MinPrice, int MaxDiscountPct, int AutoApplyMaxPct, int MaxChangesPerDay);

public sealed record Verdict(bool Ok, string Reason, decimal? NewPrice = null, bool AutoApply = false)
{
    public static Verdict Reject(string reason) => new(false, reason);
}

/// <summary>
/// Decides whether an AI suggestion may become a price. A pure function: no I/O, no clock,
/// no randomness, so every rule is unit-tested. The LLM only suggests; this code decides.
/// </summary>
public static class Guardrail
{
    public const int MaxReasonLength = 200;

    public static Verdict Check(JsonElement raw, decimal currentPrice, HotelRules rules, int changesToday)
    {
        if (raw.ValueKind != JsonValueKind.Object)
            return Verdict.Reject("schema: expected a JSON object");
        var names = raw.EnumerateObject().Select(p => p.Name).OrderBy(n => n).ToArray();
        if (!names.SequenceEqual(new[] { "discount_pct", "reason" }))
            return Verdict.Reject("schema: expected exactly {discount_pct, reason}");

        var pctElement = raw.GetProperty("discount_pct");
        if (pctElement.ValueKind != JsonValueKind.Number || !pctElement.TryGetInt32(out var pct))
            return Verdict.Reject("schema: discount_pct must be an integer");

        var reasonElement = raw.GetProperty("reason");
        var reason = reasonElement.ValueKind == JsonValueKind.String ? reasonElement.GetString()! : "";
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > MaxReasonLength)
            return Verdict.Reject("schema: reason must be 1-200 characters");
        if (reason.IndexOfAny(new[] { '<', '>', '{', '}', '`' }) >= 0 ||
            reason.Contains("http", StringComparison.OrdinalIgnoreCase))
            return Verdict.Reject("reason contains markup or links");

        if (pct < 0 || pct > rules.MaxDiscountPct)
            return Verdict.Reject($"range: discount must be 0-{rules.MaxDiscountPct}%");

        var newPrice = Math.Round(currentPrice * (100 - pct) / 100m, 2);
        if (newPrice < rules.MinPrice)
            return Verdict.Reject($"floor: {newPrice} is below the minimum {rules.MinPrice}");

        if (changesToday >= rules.MaxChangesPerDay)
            return Verdict.Reject("daily cap: too many changes today");

        var autoApply = pct > 0 && pct <= rules.AutoApplyMaxPct;
        return new Verdict(true, "ok", newPrice, autoApply);
    }
}
