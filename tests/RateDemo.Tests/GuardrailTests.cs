using System.Text.Json;
using RateDemo.Core;
using Xunit;

namespace RateDemo.Tests;

public class GuardrailTests
{
    private static readonly HotelRules Rules = new(MinPrice: 80m, MaxDiscountPct: 30, AutoApplyMaxPct: 0, MaxChangesPerDay: 5);

    private static Verdict Check(string json, int changesToday = 0, HotelRules? rules = null) =>
        Guardrail.Check(JsonDocument.Parse(json).RootElement, 100m, rules ?? Rules, changesToday);

    [Fact] public void Valid_suggestion_passes()
    {
        var v = Check("""{"discount_pct": 10, "reason": "Low occupancy"}""");
        Assert.True(v.Ok);
        Assert.Equal(90.00m, v.NewPrice);
        Assert.False(v.AutoApply);
    }

    [Fact] public void Extra_field_rejected() => Assert.False(Check("""{"discount_pct": 10, "reason": "x", "price": 1}""").Ok);
    [Fact] public void Decimal_discount_rejected() => Assert.False(Check("""{"discount_pct": 10.5, "reason": "x"}""").Ok);
    [Fact] public void Bool_discount_rejected() => Assert.False(Check("""{"discount_pct": true, "reason": "x"}""").Ok);
    [Fact] public void Above_max_rejected() => Assert.False(Check("""{"discount_pct": 31, "reason": "x"}""").Ok);
    [Fact] public void Negative_rejected() => Assert.False(Check("""{"discount_pct": -5, "reason": "x"}""").Ok);
    [Fact] public void Not_an_object_rejected() => Assert.False(Check("""[10]""").Ok);
    [Fact] public void Link_in_reason_rejected() => Assert.False(Check("""{"discount_pct": 5, "reason": "see http://evil"}""").Ok);
    [Fact] public void Markup_in_reason_rejected() => Assert.False(Check("""{"discount_pct": 5, "reason": "<script>"}""").Ok);
    [Fact] public void Daily_cap_enforced() => Assert.False(Check("""{"discount_pct": 5, "reason": "x"}""", changesToday: 5).Ok);

    [Fact] public void Floor_enforced()
    {
        var v = Check("""{"discount_pct": 25, "reason": "x"}""");
        Assert.False(v.Ok);
        Assert.StartsWith("floor", v.Reason);
    }

    [Fact] public void Auto_apply_only_inside_range()
    {
        var rules = Rules with { AutoApplyMaxPct = 5 };
        Assert.True(Check("""{"discount_pct": 5, "reason": "x"}""", rules: rules).AutoApply);
        Assert.False(Check("""{"discount_pct": 6, "reason": "x"}""", rules: rules).AutoApply);
    }
}
