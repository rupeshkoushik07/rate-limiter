using System.Collections.Concurrent;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Npgsql;

namespace RateDemo.Core;

/// <summary>Redacting wrapper: logging or printing it shows ***, never the value.</summary>
public sealed class Secret(string value)
{
    public string Reveal() => value;
    public override string ToString() => "Secret(***)";
}

public static class Settings
{
    public static string Get(string name) =>
        Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException($"missing setting {name}");

    /// <summary>Each container app has its own user-assigned managed identity; AZURE_CLIENT_ID says which.</summary>
    public static TokenCredential Credential { get; } =
        new ManagedIdentityCredential(Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"));
}

/// <summary>
/// Key Vault access. Roles are granted per secret, so each app can read only the secrets it needs:
/// the API can't read hotel tokens, the rate writer can't read the Anthropic key.
/// </summary>
public static class Vault
{
    private static readonly Lazy<SecretClient> Client = new(() =>
        new SecretClient(new Uri(Settings.Get("KEY_VAULT_URL")), Settings.Credential));
    private static readonly ConcurrentDictionary<string, (Secret Value, DateTime Expires)> Cache = new();

    public static async Task<Secret> GetAsync(string name)
    {
        if (Cache.TryGetValue(name, out var hit) && hit.Expires > DateTime.UtcNow)
            return hit.Value;
        var secret = new Secret((await Client.Value.GetSecretAsync(name)).Value.Value);
        Cache[name] = (secret, DateTime.UtcNow.AddMinutes(5));   // short cache: rotation takes effect quickly
        return secret;
    }
}

/// <summary>
/// Database access. Apps connect as app_user, which does not own the tables; FORCE ROW LEVEL
/// SECURITY plus the hotel set per transaction means a query only ever sees one hotel's rows.
/// </summary>
public static class Db
{
    private static readonly ConcurrentDictionary<string, NpgsqlDataSource> Sources = new();

    private static NpgsqlDataSource Source(string user) => Sources.GetOrAdd(user, u =>
        NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder
        {
            Host = Settings.Get("DB_HOST"),
            Database = "ratedemo",
            Username = u,
            Password = Settings.Get(u == "relay_user" ? "DB_RELAY_PASSWORD" : "DB_APP_PASSWORD"),
            SslMode = SslMode.Require,
        }.ConnectionString));

    public static async Task<T> InHotelAsync<T>(string? hotelId, Func<NpgsqlConnection, NpgsqlTransaction, Task<T>> work,
        string user = "app_user")
    {
        await using var conn = await Source(user).OpenConnectionAsync();
        await using var tx = await conn.BeginTransactionAsync();
        if (hotelId is not null)
        {
            await using var set = new NpgsqlCommand("SELECT set_config('app.hotel_id', @h, true)", conn, tx);
            set.Parameters.AddWithValue("h", hotelId);
            await set.ExecuteNonQueryAsync();
        }
        var result = await work(conn, tx);
        await tx.CommitAsync();
        return result;
    }

    public static Task InHotelAsync(string? hotelId, Func<NpgsqlConnection, NpgsqlTransaction, Task> work,
        string user = "app_user") =>
        InHotelAsync<bool>(hotelId, async (c, t) => { await work(c, t); return true; }, user);
}

public static class Hotels
{
    public static readonly string[] All = ["barcelona", "madrid"];
    public static readonly string[] Rooms = ["double", "suite"];
}

/// <summary>The message on the queue: hotel, room, prices and IDs only, never tokens.</summary>
public sealed record ApprovedRate(
    Guid ApprovalId, string HotelId, string RoomType, decimal BasedOn, decimal NewPrice, DateTimeOffset ExpiresAt);
