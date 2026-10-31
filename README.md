# Rate-discount service: learning build

A small, real version of the take-home design on Azure, to see how the pieces fit. Not production.

| Design piece | Where it is |
|---|---|
| Staff login: OIDC + PKCE against Microsoft Entra, written by hand | `src/RateDemo.Api/Auth.cs` (`BeginLogin`, `CompleteLoginAsync`) |
| JWT checks: signature, algorithm, issuer, audience, expiry, nonce | `OidcLogin.ValidateAsync`, on login and every request |
| Session: HttpOnly `__Host-` cookie; the JWT stays on the server | `Auth.cs`, `sessions` table |
| Roles + hotel from the token (Entra app roles `Approver`, `Hotel.Barcelona`) | `StaffSession`, `AuthorizeAsync` in `Program.cs` |
| Row-level security, non-owner app role, `FORCE ROW LEVEL SECURITY` | `db/schema.sql`, `Db.InHotelAsync` |
| LLM gets numbers only; answer goes only to the guardrail | `src/RateDemo.Api/Claude.cs` |
| Guardrail as a pure function, unit-tested | `src/RateDemo.Core/Guardrail.cs`, `tests/` |
| Outbox in the same transaction + relay | `EnqueueApprovalAsync`, `OutboxRelay` |
| Service Bus: sessions per hotel, duplicate detection, TTL, dead-letter, keys off | `infra/Program.cs` (`Queue`, `Namespace`) |
| Rate writer: re-read, 409 stop, 429 Retry-After, timeout re-read, read-back | `src/RateDemo.Writer/Program.cs` |
| Webhook: secret in URL, constant-time compare, IDs only, re-read | `src/RateDemo.Webhook/Program.cs` |
| Tokens in the JSON body; never log bodies, log Request-Id | `src/RateDemo.Core/MewsClient.cs` |
| One managed identity per app; Key Vault roles per secret; Service Bus roles per queue | `infra/Program.cs` (`Grant`, `ReadSecrets`) |
| Ingress allow-list on the dashboard | `infra/Program.cs` (`IpSecurityRestrictions`, repo variable `ALLOWED_IPS`) |
| CI/CD: GitHub OIDC to Azure, actions pinned by SHA, no stored cloud secret | `.github/workflows/deploy.yml` |
| Fake Mews with switches for 409, 429, lost replies, webhooks | `src/RateDemo.FakeMews/Program.cs` |

## Shortcuts taken to stay cheap (and what production would do)

- Public endpoints + IP allow-list, Postgres "allow Azure services" → VNet + private endpoints (needs Service Bus Premium).
- No WAF / Front Door in front of the dashboard and webhook.
- No egress allow-list (needs Azure Firewall); the rate writer only knows the fake Mews URL.
- Entra client secret in Key Vault → certificate or managed identity as a federated credential.

## Setup

1. `scripts/bootstrap-cloudshell.sh` in Azure Cloud Shell (once). Put its output into repo variables.
2. Push to `main` → GitHub Actions tests, runs Pulumi, builds the image, migrates the database, deploys.
3. `scripts/after-first-deploy.sh` in Cloud Shell: redirect URI, Entra client secret and Anthropic key into Key Vault.
