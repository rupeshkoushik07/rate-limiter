using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace RateDemo.Core;

public sealed record MewsReply(int Status, JsonElement Body, string? RequestId, TimeSpan? RetryAfter);

/// <summary>
/// Client for the (fake) Mews Connector API, used only by the rate writer and webhook receiver.
/// Mews puts ClientToken and AccessToken in the JSON body. Logging tools mask Authorization headers
/// but not body fields, so this client never logs a request body: it logs the Request-Id instead.
/// </summary>
public sealed class MewsClient(HttpClient http, ILogger<MewsClient> log)
{
    public async Task<MewsReply> CallAsync(string operation, string hotelId, object parameters, CancellationToken ct = default)
    {
        var body = new Dictionary<string, object?>
        {
            ["ClientToken"] = (await Vault.GetAsync("mews-client-token")).Reveal(),
            // Hotel A's token is only ever fetched for hotel A.
            ["AccessToken"] = (await Vault.GetAsync($"mews-access-token-{hotelId}")).Reveal(),
            ["Client"] = "RateDiscountDemo 1.0",
        };
        foreach (var p in JsonSerializer.SerializeToElement(parameters).EnumerateObject())
            body[p.Name] = p.Value;

        using var response = await http.PostAsJsonAsync($"api/connector/v1/{operation}", body, ct);
        var requestId = response.Headers.TryGetValues("Request-Id", out var ids) ? ids.First() : null;
        var retryAfter = response.Headers.RetryAfter?.Delta;
        log.LogInformation("Mews {Operation} for {Hotel}: {Status}, Request-Id {RequestId}",
            operation, hotelId, (int)response.StatusCode, requestId);

        var text = await response.Content.ReadAsStringAsync(ct);
        var json = string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone();
        return new MewsReply((int)response.StatusCode, json, requestId, retryAfter);
    }

    public async Task<(decimal Price, int OccupancyPct)> GetPricingAsync(string hotelId, string room, CancellationToken ct = default)
    {
        var r = await CallAsync("rates/getPricing", hotelId, new { RoomType = room }, ct);
        if (r.Status != 200)
            throw new MewsException($"getPricing returned {r.Status}", r.RequestId);
        return (r.Body.GetProperty("Price").GetDecimal(), r.Body.GetProperty("OccupancyPct").GetInt32());
    }
}

public sealed class MewsException(string message, string? requestId) : Exception(message)
{
    public string? RequestId { get; } = requestId;
}
