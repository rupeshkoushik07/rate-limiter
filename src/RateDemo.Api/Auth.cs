using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using RateDemo.Core;

namespace RateDemo.Api;

public sealed record StaffSession(string Id, string Oid, string Tid, string Name, string[] Roles, string[] Hotels,
    string IdToken, DateTimeOffset ExpiresAt, string[] LoginTrace)
{
    public bool HasHotel(string hotel) => Hotels.Contains(hotel);
    public bool CanApprove => Roles.Contains("Approver") || Roles.Contains("Manager");
    public int MaxApprovablePct => Roles.Contains("Manager") ? 100 : Roles.Contains("Approver") ? 15 : 0;
}

/// <summary>
/// Staff login with OpenID Connect + PKCE against Microsoft Entra, written out by hand so each step is visible:
/// /login creates the PKCE secret and sends only its hash; /signin-oidc swaps the one-time code + secret for the
/// ID token (a JWT), validates it, and gives the browser an HttpOnly session cookie. The JWT stays on the server.
/// </summary>
public sealed class OidcLogin(IHttpClientFactory http, ILogger<OidcLogin> log)
{
    public const string CookieName = "__Host-session";
    private static readonly string Tenant = Settings.Get("ENTRA_TENANT_ID");
    private static readonly string ClientId = Settings.Get("ENTRA_CLIENT_ID");
    private static readonly string Authority = $"https://login.microsoftonline.com/{Tenant}/v2.0";
    private static readonly string RedirectUri = Settings.Get("PUBLIC_URL") + "/signin-oidc";

    // Microsoft's public signing keys (JWKS), cached and refreshed automatically, also when an unknown kid appears.
    private static readonly ConfigurationManager<OpenIdConnectConfiguration> Discovery = new(
        $"{Authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever())
    {
        AutomaticRefreshInterval = TimeSpan.FromHours(6),
        RefreshInterval = TimeSpan.FromMinutes(5),
    };

    private sealed record Pending(string Verifier, string Challenge, string Nonce, DateTime Expires);
    private static readonly ConcurrentDictionary<string, Pending> PendingLogins = new();

    private static string Random64(int bytes) => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(bytes));

    /// <summary>Step 1-2: make the PKCE pair, remember the secret, send the browser to Entra with the hash only.</summary>
    public string BeginLogin()
    {
        foreach (var (k, v) in PendingLogins) if (v.Expires < DateTime.UtcNow) PendingLogins.TryRemove(k, out _);

        var verifier = Random64(32);                                                    // the secret ("banana")
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));   // its hash
        var state = Random64(16);                                                       // stops a forged return trip
        var nonce = Random64(16);                                                       // must come back in the token
        PendingLogins[state] = new Pending(verifier, challenge, nonce, DateTime.UtcNow.AddMinutes(10));

        var q = new Dictionary<string, string>
        {
            ["client_id"] = ClientId, ["response_type"] = "code", ["scope"] = "openid profile",
            ["redirect_uri"] = RedirectUri, ["response_mode"] = "query", ["state"] = state, ["nonce"] = nonce,
            ["code_challenge"] = challenge, ["code_challenge_method"] = "S256",
        };
        return $"https://login.microsoftonline.com/{Tenant}/oauth2/v2.0/authorize?" +
               string.Join("&", q.Select(kv => $"{kv.Key}={Uri.EscapeDataString(kv.Value)}"));
    }

    /// <summary>Steps 4-7: check state, swap code + PKCE secret for the JWT, validate it, create the session.</summary>
    public async Task<StaffSession> CompleteLoginAsync(string code, string state)
    {
        if (!PendingLogins.TryRemove(state, out var pending) || pending.Expires < DateTime.UtcNow)
            throw new SecurityTokenException("unknown or expired state");

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = RedirectUri,
            ["client_id"] = ClientId, ["code_verifier"] = pending.Verifier,               // PKCE: the real secret
            ["client_secret"] = (await Vault.GetAsync("entra-client-secret")).Reveal(), // proves it's our backend
        };
        using var response = await http.CreateClient().PostAsync(
            $"https://login.microsoftonline.com/{Tenant}/oauth2/v2.0/token", new FormUrlEncodedContent(form));
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        if (!response.IsSuccessStatusCode)
            throw new SecurityTokenException($"token endpoint said {json.GetProperty("error").GetString()}");
        var idToken = json.GetProperty("id_token").GetString()!;

        var token = await ValidateAsync(idToken);
        if (token.GetClaim("nonce").Value != pending.Nonce)
            throw new SecurityTokenException("nonce mismatch");

        var roles = token.Claims.Where(c => c.Type == "roles").Select(c => c.Value).ToArray();
        var session = new StaffSession(
            Id: Random64(32),
            Oid: token.GetClaim("oid").Value,       // identity = oid + tid, never the email
            Tid: token.GetClaim("tid").Value,
            Name: token.TryGetClaim("name", out var n) ? n.Value : "staff",
            Roles: roles.Where(r => !r.StartsWith("Hotel.")).ToArray(),
            Hotels: roles.Where(r => r.StartsWith("Hotel.")).Select(r => r[6..].ToLowerInvariant()).ToArray(),
            IdToken: idToken,
            ExpiresAt: DateTimeOffset.UtcNow.AddMinutes(30),   // short idle sessions: front-desk PCs are shared
            LoginTrace:
            [
                $"1. Our app made a PKCE secret and sent Entra only its SHA-256 hash: code_challenge={pending.Challenge}",
                "2. You signed in at Microsoft (password + MFA). We never saw your password.",
                $"3. Entra sent your browser back with a one-time code ({code[..12]}...).",
                $"4. Our backend sent Entra the code + the PKCE secret (code_verifier={pending.Verifier[..10]}...) + our client secret.",
                "5. Entra hashed the verifier, matched it to the challenge, and returned the ID token (JWT).",
                "6. We checked signature, algorithm (RS256), issuer, audience, expiry and nonce; then gave you this cookie.",
            ]);
        await SaveAsync(session);
        log.LogInformation("Staff {Oid} signed in with roles {Roles} for hotels {Hotels}",
            session.Oid, string.Join(",", session.Roles), string.Join(",", session.Hotels));
        return session;
    }

    /// <summary>The five checks, run at login and again on every request.</summary>
    public static async Task<JsonWebToken> ValidateAsync(string jwt)
    {
        var config = await Discovery.GetConfigurationAsync(CancellationToken.None);
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(jwt, new TokenValidationParameters
        {
            IssuerSigningKeys = config.SigningKeys,                         // 1 signature (Microsoft's public keys)
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],              // 2 algorithm: no "none", no HS256
            ValidIssuer = Authority,                                       // 3 issuer: our tenant's Entra
            ValidAudience = ClientId,                                      // 4 audience: made for this app
            ValidateLifetime = true,                                       // 5 expiry
            ClockSkew = TimeSpan.FromMinutes(2),
        });
        if (!result.IsValid)
        {
            if (result.Exception is SecurityTokenSignatureKeyNotFoundException) Discovery.RequestRefresh();   // key rotated
            throw result.Exception;
        }
        return (JsonWebToken)result.SecurityToken;
    }

    private static Task SaveAsync(StaffSession s) => Db.InHotelAsync(null, async (conn, tx) =>
    {
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO sessions (id, oid, tid, name, roles, hotels, id_token, expires_at, trace)
            VALUES (@id, @oid, @tid, @name, @roles, @hotels, @tok, @exp, @trace)
            """, conn, tx);
        cmd.Parameters.AddWithValue("id", s.Id);
        cmd.Parameters.AddWithValue("oid", s.Oid);
        cmd.Parameters.AddWithValue("tid", s.Tid);
        cmd.Parameters.AddWithValue("name", s.Name);
        cmd.Parameters.AddWithValue("roles", s.Roles);
        cmd.Parameters.AddWithValue("hotels", s.Hotels);
        cmd.Parameters.AddWithValue("tok", s.IdToken);
        cmd.Parameters.AddWithValue("exp", s.ExpiresAt);
        cmd.Parameters.AddWithValue("trace", s.LoginTrace);
        await cmd.ExecuteNonQueryAsync();
    });

    /// <summary>Every request: find the session from the cookie, then re-validate the stored JWT.</summary>
    public static async Task<StaffSession?> FromRequestAsync(HttpContext ctx)
    {
        if (!ctx.Request.Cookies.TryGetValue(CookieName, out var id)) return null;
        var s = await Db.InHotelAsync<StaffSession?>(null, async (conn, tx) =>
        {
            await using var cmd = new NpgsqlCommand(
                "SELECT oid, tid, name, roles, hotels, id_token, expires_at, trace FROM sessions WHERE id = @id", conn, tx);
            cmd.Parameters.AddWithValue("id", id);
            await using var r = await cmd.ExecuteReaderAsync();
            if (!await r.ReadAsync()) return null;
            return new StaffSession(id, r.GetString(0), r.GetString(1), r.GetString(2), (string[])r[3], (string[])r[4],
                r.GetString(5), r.GetFieldValue<DateTimeOffset>(6), (string[])r[7]);
        });
        if (s is null || s.ExpiresAt < DateTimeOffset.UtcNow) return null;
        try { await ValidateAsync(s.IdToken); } catch { return null; }   // expired or tampered: log in again
        return s;
    }

    public static Task DeleteAsync(string id) => Db.InHotelAsync(null, async (conn, tx) =>
    {
        await using var cmd = new NpgsqlCommand("DELETE FROM sessions WHERE id = @id", conn, tx);
        cmd.Parameters.AddWithValue("id", id);
        await cmd.ExecuteNonQueryAsync();
    });

    /// <summary>The token's payload, for the "what's in my JWT" page. Signature and raw token are not shown.</summary>
    public static IEnumerable<(string, string)> Claims(string jwt) =>
        new JsonWebToken(jwt).Claims.Select(c => (c.Type, c.Value));
}
