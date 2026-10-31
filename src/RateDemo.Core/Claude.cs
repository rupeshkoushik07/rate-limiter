using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace RateDemo.Core;

/// <summary>
/// Calls Claude with numbers only and returns its raw answer for the guardrail to judge.
/// The answer is never trusted: it only goes to Guardrail.Check, never to Mews or straight to the page.
/// </summary>
public sealed class Claude(IHttpClientFactory http, ILogger<Claude> log)
{
    private static readonly string Model = Environment.GetEnvironmentVariable("CLAUDE_MODEL") ?? "claude-haiku-5-5";

    private const string System =
        "You suggest a discount for one hotel room type. You receive numbers only. " +
        "Answer by calling the suggest_discount tool.";

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
                max_tokens = 300,
                system = System,
                messages = new[] { new { role = "user", content = prompt } },
                // Structured output: Claude must answer through this tool, so the reply is schema-shaped data,
                // not free text to parse. The guardrail still checks every value.
                tools = new[]
                {
                    new
                    {
                        name = "suggest_discount",
                        description = "Suggest a discount for this room type.",
                        input_schema = new
                        {
                            type = "object",
                            properties = new Dictionary<string, object>
                            {
                                ["discount_pct"] = new { type = "integer", minimum = 0, maximum = maxDiscountPct },
                                ["reason"] = new { type = "string", maxLength = 120 },
                            },
                            required = new[] { "discount_pct", "reason" },
                            additionalProperties = false,
                        },
                    },
                },
                tool_choice = new { type = "tool", name = "suggest_discount" },
            }),
        };
        request.Headers.Add("x-api-key", (await Vault.GetAsync("anthropic-api-key")).Reveal());
        request.Headers.Add("anthropic-version", "2023-06-01");

        try
        {
            using var response = await client.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                log.LogWarning("Claude returned {Status}", (int)response.StatusCode);
                return null;
            }
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            // The answer arrives as the tool call's input: already JSON, no text parsing.
            var blocks = body.TryGetProperty("content", out var c) && c.ValueKind == JsonValueKind.Array
                ? c.EnumerateArray().ToList() : [];
            var call = blocks.FirstOrDefault(b => b.TryGetProperty("type", out var t) && t.GetString() == "tool_use");
            if (call.ValueKind != JsonValueKind.Object || !call.TryGetProperty("input", out var input))
            {
                log.LogWarning("Claude reply had no tool call (blocks: {Types}, stop_reason: {Stop})",
                    string.Join(",", blocks.Select(b => b.TryGetProperty("type", out var t) ? t.GetString() : "?")),
                    body.TryGetProperty("stop_reason", out var sr) ? sr.ToString() : "?");
                return null;
            }
            return input.Clone();
        }
        catch (Exception ex)
        {
            // Fail closed: any odd LLM reply becomes a guardrail rejection, never an error page or a price.
            log.LogWarning("Claude call failed: {Error}", ex.GetType().Name);
            return null;
        }
    }
}
