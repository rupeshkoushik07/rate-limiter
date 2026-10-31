// Rate writer: the only component that changes prices in Mews.
// Keeps an open connection to Service Bus with its own managed identity (Receiver role only).
// Sessions = one hotel per session, so each hotel's price changes apply in order.
using Azure.Messaging.ServiceBus;
using Npgsql;
using RateDemo.Core;

var builder = Host.CreateApplicationBuilder(args);
// One JSON object per log line, so KQL can parse it. HttpClient request logs are off: they print full
// URLs, and a webhook URL carries its secret token in the query string.
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();
builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);
builder.Services.AddHttpClient<MewsClient>(c =>
{
    c.BaseAddress = new Uri(Settings.Get("MEWS_BASE_URL") + "/");
    c.Timeout = TimeSpan.FromSeconds(8);
});
builder.Services.AddSingleton(_ => new ServiceBusClient(Settings.Get("SERVICEBUS_FQDN"), Settings.Credential));
builder.Services.AddHostedService<RateWriter>();
builder.Build().Run();

sealed class RateWriter(ServiceBusClient bus, MewsClient mews, ILogger<RateWriter> log) : BackgroundService
{
    private const int MaxAttempts = 4;

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        var processor = bus.CreateSessionProcessor(Settings.Get("QUEUE_NAME"), new ServiceBusSessionProcessorOptions
        {
            AutoCompleteMessages = false,
            MaxConcurrentSessions = 4,          // up to 4 hotels in parallel, each in order
            MaxConcurrentCallsPerSession = 1,
            SessionIdleTimeout = TimeSpan.FromSeconds(10),
        });
        processor.ProcessMessageAsync += async args =>
        {
            var rate = args.Message.Body.ToObjectFromJson<ApprovedRate>()!;
            try
            {
                await ProcessAsync(rate, args.CancellationToken);
                await args.CompleteMessageAsync(args.Message);   // "done": the queue deletes it
            }
            catch (Exception ex)
            {
                log.LogWarning("Approval {ApprovalId} failed ({Error}), delivery {Count}; abandoning for redelivery",
                    rate.ApprovalId, ex.GetType().Name, args.Message.DeliveryCount);
                await args.AbandonMessageAsync(args.Message);    // after MaxDeliveryCount it goes to dead-letter
            }
        };
        processor.ProcessErrorAsync += args =>
        {
            log.LogWarning("Service Bus error: {Error}", args.Exception.GetType().Name);
            return Task.CompletedTask;
        };
        await processor.StartProcessingAsync(stop);
        log.LogInformation("Rate writer listening on the queue");
        await Task.Delay(Timeout.Infinite, stop).ContinueWith(_ => { });
        await processor.StopProcessingAsync();
    }

    private async Task ProcessAsync(ApprovedRate rate, CancellationToken ct)
    {
        if (rate.ExpiresAt < DateTimeOffset.UtcNow)
        {
            await RecordAsync(rate, "expired", "approval older than its expiry; approve again");
            return;
        }

        var (status, minPrice) = await Db.InHotelAsync(rate.HotelId, async (conn, tx) =>
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT a.status, r.min_price FROM approvals a JOIN hotel_rules r USING (hotel_id)
                WHERE a.approval_id = @id
                """, conn, tx);
            cmd.Parameters.AddWithValue("id", rate.ApprovalId);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            return await reader.ReadAsync(ct) ? (reader.GetString(0), reader.GetDecimal(1)) : ((string?)null, 0m);
        });
        if (status is null) { log.LogWarning("Unknown approval {ApprovalId} ignored", rate.ApprovalId); return; }
        if (status == "applied") { log.LogInformation("Duplicate delivery of {ApprovalId} skipped", rate.ApprovalId); return; }

        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            // Re-read the live price before every attempt.
            var (live, _) = await mews.GetPricingAsync(rate.HotelId, rate.RoomType, ct);
            if (live == rate.NewPrice)
            {
                await RecordAsync(rate, "applied", "already live in Mews (an earlier attempt landed)");
                return;
            }
            if (live != rate.BasedOn)
            {
                await RecordAsync(rate, "stopped", $"price changed to {live} since approval (was {rate.BasedOn}); review again");
                return;
            }
            if (rate.NewPrice < minPrice)
            {
                await RecordAsync(rate, "stopped", $"below the minimum {minPrice}");
                return;
            }

            MewsReply reply;
            try
            {
                reply = await mews.CallAsync("rates/updatePrice", rate.HotelId,
                    new { RoomType = rate.RoomType, Price = rate.NewPrice }, ct);
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested)
            {
                log.LogWarning("Timeout on {ApprovalId}: outcome unknown, re-reading before any retry", rate.ApprovalId);
                continue;
            }

            switch (reply.Status)
            {
                case 200:
                    var (after, _) = await mews.GetPricingAsync(rate.HotelId, rate.RoomType, ct);   // read back
                    await RecordAsync(rate, after == rate.NewPrice ? "applied" : "failed",
                        after == rate.NewPrice ? "live in Mews" : "read-back mismatch", reply.RequestId);
                    return;
                case 409:
                    await RecordAsync(rate, "stopped", "Mews says the data changed (409); review again", reply.RequestId);
                    return;
                case 429:
                    var wait = reply.RetryAfter ?? TimeSpan.FromSeconds(Math.Pow(2, attempt));
                    log.LogWarning("429 on {ApprovalId}: waiting {Wait}s as Mews asked", rate.ApprovalId, wait.TotalSeconds);
                    await Task.Delay(wait, ct);
                    continue;
                case >= 500:
                    await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt) + Random.Shared.NextDouble()), ct);
                    continue;
                default:
                    await RecordAsync(rate, "failed", $"Mews returned {reply.Status}", reply.RequestId);
                    return;
            }
        }
        throw new InvalidOperationException("retry budget used up");
    }

    private Task RecordAsync(ApprovedRate rate, string status, string detail, string? requestId = null)
    {
        log.LogInformation("Approval {ApprovalId}: {Status} ({Detail}), Request-Id {RequestId}",
            rate.ApprovalId, status, detail, requestId);
        return Db.InHotelAsync(rate.HotelId, async (conn, tx) =>
        {
            await using var cmd = new NpgsqlCommand("""
                UPDATE approvals SET status = @s, detail = @d, mews_request_id = @r, updated_at = now()
                WHERE approval_id = @id
                """, conn, tx);
            cmd.Parameters.AddWithValue("s", status);
            cmd.Parameters.AddWithValue("d", detail);
            cmd.Parameters.AddWithValue("r", (object?)requestId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("id", rate.ApprovalId);
            await cmd.ExecuteNonQueryAsync();
        });
    }
}
