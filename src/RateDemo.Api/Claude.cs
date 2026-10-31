using System.Net.Http.Json;
using System.Text.Json;
using RateDemo.Core;

namespace RateDemo.Api;

/// <summary>
/// Calls Claude with numbers only and returns its raw answer for the guardrail to judge.
/// The answer is never trusted: it only goes to Guardrail.Check, never to Mews or straight to the page.
/// </summary>
public sealed class Claude(IHttpClientFactory http, ILogger<Claude> log)
{
    private static readonly string Model = Environment.GetEnvironmentVariable("CLAUDE_MODEL") ?? "claude-haiku-5-5";

    private const string System =
        "You suggest a discount for one hotel room type. You receive numbers only. " +
        "Reply with a single JSON object and nothing else: {\"discount_pct\": <integer>, \"reason\": <string, max 120 chars>}.";

    public async Task<JsonElement?> SuggestAsync(int occupancyPct, decimal currentPrice, decimal minPrice, int maxDiscountPct)
    {
        var prompt = $"occupancy_pct={occupancyPct}; current_price_eur={currentPrice}; " +
                     $"min_price_eur={minPrice}; max_discount_pct={maxDiscountPct}";
        var client = http.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(30);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages")
        {
            Content = JsonContent.Create(new
            {
                model = Model,
                max_tokens = 200,
                system = System,
                messages = new[] { new { role = "user", content = prompt } },
            }),
        };
        request.Headers.Add("x-api-key", (await Vault.GetAsync("anthropic-api-key")).Reveal());
        request.Headers.Add("anthropic-version", "2023-06-01");

        using var response = await client.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            log.LogWarning("Claude returned {Status}", (int)response.StatusCode);
            return null;
        }
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var text = body.GetProperty("content")[0].GetProperty("text").GetString() ?? "";
        text = text.Trim().Trim('`');
        if (text.StartsWith("json")) text = text[4..];
        try { return JsonDocument.Parse(text).RootElement.Clone(); }
        catch (JsonException) { return null; }
    }
}
