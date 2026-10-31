using System.Net;
using System.Text;
using Npgsql;
using RateDemo.Core;

namespace RateDemo.Api;

/// <summary>Server-rendered pages. Everything shown is HTML-encoded, including the LLM's reason text.</summary>
public static class Pages
{
    public sealed record Room(string Name, int? Occupancy, decimal? Price);
    public sealed record Suggestion(long Id, string Room, decimal BasedOn, int? Pct, decimal? NewPrice, string? Reason, string Guardrail, string? RejectedBy);
    public sealed record Approval(string Room, decimal BasedOn, decimal NewPrice, string By, string Status, string? Detail, string? RequestId, DateTime At);
    public sealed record HotelView(string Id, string Name, decimal MinPrice, List<Room> Rooms, List<Suggestion> Suggestions, List<Approval> Approvals);

    private static string E(object? v) => WebUtility.HtmlEncode(v?.ToString() ?? "");

    public static Task<HotelView> LoadHotelAsync(string hotel) => Db.InHotelAsync(hotel, async (conn, tx) =>
    {
        string name = hotel; decimal min = 0;
        await using (var c = new NpgsqlCommand("SELECT name, min_price FROM hotel_rules", conn, tx))
        await using (var r = await c.ExecuteReaderAsync())
            if (await r.ReadAsync()) { name = r.GetString(0); min = r.GetDecimal(1); }

        var avail = new Dictionary<string, (int, decimal)>();
        await using (var c = new NpgsqlCommand("SELECT room_type, occupancy_pct, current_price FROM availability", conn, tx))
        await using (var r = await c.ExecuteReaderAsync())
            while (await r.ReadAsync()) avail[r.GetString(0)] = (r.GetInt32(1), r.GetDecimal(2));
        var rooms = Hotels.Rooms.Select(x => avail.TryGetValue(x, out var a) ? new Room(x, a.Item1, a.Item2) : new Room(x, null, null)).ToList();

        var sugg = new List<Suggestion>();
        await using (var c = new NpgsqlCommand(
            "SELECT id, room_type, based_on, discount_pct, new_price, reason, guardrail, rejected_by FROM suggestions ORDER BY id DESC LIMIT 8", conn, tx))
        await using (var r = await c.ExecuteReaderAsync())
            while (await r.ReadAsync())
                sugg.Add(new(r.GetInt64(0), r.GetString(1), r.GetDecimal(2), r.IsDBNull(3) ? null : r.GetInt32(3),
                    r.IsDBNull(4) ? null : r.GetDecimal(4), r.IsDBNull(5) ? null : r.GetString(5), r.GetString(6),
                    r.IsDBNull(7) ? null : r.GetString(7)));

        var appr = new List<Approval>();
        await using (var c = new NpgsqlCommand("""
            SELECT room_type, based_on, new_price, approver_name, status, detail, mews_request_id, updated_at
            FROM approvals ORDER BY created_at DESC LIMIT 8
            """, conn, tx))
        await using (var r = await c.ExecuteReaderAsync())
            while (await r.ReadAsync())
                appr.Add(new(r.GetString(0), r.GetDecimal(1), r.GetDecimal(2), r.GetString(3), r.GetString(4),
                    r.IsDBNull(5) ? null : r.GetString(5), r.IsDBNull(6) ? null : r.GetString(6), r.GetDateTime(7)));
        return new HotelView(hotel, name, min, rooms, sugg, appr);
    });

    private const string Style = """
        <style>
        body{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1d1d1f;background:#fafafa}
        h1{font-size:22px} h2{font-size:18px;margin-top:28px} table{border-collapse:collapse;width:100%;margin:8px 0;background:#fff}
        td,th{border:1px solid #ddd;padding:6px 8px;font-size:14px;text-align:left} th{background:#f0f0f0}
        button{padding:5px 10px;border:1px solid #888;border-radius:6px;background:#fff;cursor:pointer}
        .ok{color:#0a7d32}.bad{color:#b00020}.muted{color:#666;font-size:13px}.card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:12px 16px;margin:12px 0}
        code{background:#f0f0f0;padding:1px 4px;border-radius:4px;font-size:12px;word-break:break-all}
        </style>
        """;

    private const string Script = """
        <script>
        async function act(url, body){
          const r = await fetch(url,{method:'POST',headers:{'X-Requested-With':'fetch','Content-Type':'application/json'},body:body?JSON.stringify(body):null});
          const t = await r.text(); document.getElementById('out').textContent = r.status + ' ' + t; setTimeout(()=>location.reload(), 1500);
        }
        </script>
        """;

    public static string SignIn() => $"""
        <!doctype html><html><head><title>Rate discount demo</title>{Style}</head><body>
        <h1>Rate discount service (learning build)</h1>
        <div class="card"><p>Staff sign in with their company login (Microsoft Entra), using OpenID Connect + PKCE.</p>
        <p><a href="/login"><button>Sign in with Microsoft</button></a></p></div></body></html>
        """;

    public static string Message(string title, string text) => $"""
        <!doctype html><html><head><title>{E(title)}</title>{Style}</head><body><h1>{E(title)}</h1>
        <div class="card">{E(text)}</div><a href="/">Back</a></body></html>
        """;

    public static string Dashboard(StaffSession s, List<HotelView> hotels)
    {
        var sb = new StringBuilder();
        sb.Append($"""
            <!doctype html><html><head><title>Rate discount dashboard</title>{Style}{Script}</head><body>
            <h1>Rate discount dashboard</h1>
            <p class="muted">Signed in as <b>{E(s.Name)}</b> · roles: {E(string.Join(", ", s.Roles))} · hotels in your token: {E(string.Join(", ", s.Hotels))}
            · <a href="/me">What's in my token?</a></p>
            <form method="post" action="/logout"><button>Sign out</button></form>
            <pre id="out" class="muted"></pre>
            """);
        if (hotels.Count == 0) sb.Append("<div class='card bad'>Your token has no hotel role, so you see nothing (deny by default).</div>");
        foreach (var h in hotels)
        {
            sb.Append($"<h2>{E(h.Name)}</h2><p class='muted'>Minimum price €{E(h.MinPrice)} · <a href='/hotel/{E(h.Id)}' target='_blank'>Guest booking page</a></p>");
            sb.Append("<table><tr><th>Room</th><th>Occupancy</th><th>Price in Mews (last re-read)</th><th></th></tr>");
            foreach (var r in h.Rooms)
                sb.Append($$"""
                    <tr><td>{{E(r.Name)}}</td><td>{{(r.Occupancy is null ? "–" : E(r.Occupancy) + "%")}}</td>
                    <td>{{(r.Price is null ? "– (no webhook yet)" : "€" + E(r.Price))}}</td>
                    <td><button onclick="act('/api/demo/booking',{hotel:'{{E(h.Id)}}',room:'{{E(r.Name)}}'})">Simulate booking (webhook)</button>
                    <button onclick="act('/api/hotels/{{E(h.Id)}}/rooms/{{E(r.Name)}}/suggest')">Ask AI for a discount</button></td></tr>
                    """);
            sb.Append("</table><b>AI suggestions</b><table><tr><th>#</th><th>Room</th><th>Based on</th><th>Discount</th><th>New price</th><th>Reason (LLM)</th><th>Guardrail</th><th></th></tr>");
            foreach (var g in h.Suggestions)
                sb.Append($"""
                    <tr><td>{g.Id}</td><td>{E(g.Room)}</td><td>€{E(g.BasedOn)}</td><td>{E(g.Pct)}%</td><td>{(g.NewPrice is null ? "" : "€" + E(g.NewPrice))}</td>
                    <td>{E(g.Reason)}</td><td class="{(g.Guardrail == "ok" ? "ok" : "bad")}">{E(g.Guardrail)}</td>
                    <td>{(g.RejectedBy is not null ? $"Rejected by {E(g.RejectedBy)}" : g.Guardrail == "ok" && s.CanApprove
                        ? $"<button onclick=\"act('/api/suggestions/{g.Id}/approve?hotel={E(h.Id)}')\">Approve</button> <button onclick=\"act('/api/suggestions/{g.Id}/reject?hotel={E(h.Id)}')\">Reject</button>" : "")}</td></tr>
                    """);
            sb.Append("</table><b>Approvals (audit log + status from the rate writer)</b><table><tr><th>Room</th><th>Price</th><th>By</th><th>Status</th><th>Detail</th><th>Mews Request-Id</th></tr>");
            foreach (var a in h.Approvals)
                sb.Append($"""
                    <tr><td>{E(a.Room)}</td><td>€{E(a.BasedOn)} → €{E(a.NewPrice)}</td><td>{E(a.By)}</td>
                    <td class="{(a.Status == "applied" ? "ok" : a.Status == "pending" ? "" : "bad")}">{E(a.Status)}</td>
                    <td>{E(a.Detail)}</td><td><code>{E(a.RequestId)}</code></td></tr>
                    """);
            sb.Append("</table>");
        }
        sb.Append("""
            <h2>Demo controls: make the fake Mews misbehave on the next call</h2>
            <div class="card">
            <button onclick="act('/api/demo/chaos',{conflict:1})">Next write → 409 (someone else changed the price)</button>
            <button onclick="act('/api/demo/chaos',{rate_limit:1})">Next call → 429 + Retry-After</button>
            <button onclick="act('/api/demo/chaos',{lose_reply:1})">Next write applies but the reply is lost</button>
            <p class="muted">Then approve a suggestion and watch the status column and the logs in Log Analytics.</p></div>
            </body></html>
            """);
        return sb.ToString();
    }

    public static string Me(StaffSession s)
    {
        var sb = new StringBuilder($"""
            <!doctype html><html><head><title>My token</title>{Style}</head><body><h1>What happened when you signed in</h1>
            <div class="card"><ol>{string.Concat(s.LoginTrace.Select(t => $"<li>{E(t)}</li>"))}</ol></div>
            <h2>The JWT payload (claims)</h2><p class="muted">The browser never holds this token; it only has an HttpOnly cookie.
            Identity = <code>oid</code> + <code>tid</code>. Hotels and roles come from <code>roles</code>.</p><table><tr><th>Claim</th><th>Value</th></tr>
            """);
        foreach (var (k, v) in OidcLogin.Claims(s.IdToken))
            sb.Append($"<tr><td><code>{E(k)}</code></td><td>{E(v)}</td></tr>");
        sb.Append("</table><a href='/'>Back</a></body></html>");
        return sb.ToString();
    }
}
