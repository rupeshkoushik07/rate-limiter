// Infrastructure for the rate-discount learning build, in one resource group.
// The point of this file: every app gets its OWN managed identity, and each identity gets only
// the roles it needs, scoped as narrowly as Azure allows (single secret, single queue).
using Pulumi;
using Pulumi.AzureNative.App;
using Pulumi.AzureNative.App.Inputs;
using Pulumi.AzureNative.Authorization;
using Pulumi.AzureNative.ContainerRegistry;
using Pg = Pulumi.AzureNative.DBforPostgreSQL;
using Pulumi.AzureNative.KeyVault;
using Secret = Pulumi.AzureNative.KeyVault.Secret;
using Pulumi.AzureNative.KeyVault.Inputs;
using Pulumi.AzureNative.ManagedIdentity;
using Pulumi.AzureNative.OperationalInsights;
using Pulumi.AzureNative.OperationalInsights.Inputs;
using Pulumi.AzureNative.ServiceBus;
using Pulumi.Random;
using KvSku = Pulumi.AzureNative.KeyVault.Inputs.SkuArgs;
using SbSku = Pulumi.AzureNative.ServiceBus.Inputs.SBSkuArgs;

return await Deployment.RunAsync(() =>
{
    var config = new Config();
    var rg = config.Get("resourceGroup") ?? "rg-ratedemo";
    var location = config.Get("location") ?? "northeurope";
    var tenantId = config.Require("tenantId");
    var staffClientId = config.Require("staffClientId");           // Entra app for staff login
    var deployerObjectId = config.Require("deployerObjectId");     // GitHub Actions identity (push images)
    var imageTag = config.Get("imageTag");                         // empty on the very first run: no apps yet
    var allowedIps = (config.Get("allowedIps") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries);
    var claudeModel = config.Get("claudeModel") ?? "claude-haiku-5-5";

    var client = GetClientConfig.Invoke();
    var sub = client.Apply(c => c.SubscriptionId);
    Output<string> RoleId(string guid) =>
        sub.Apply(s => $"/subscriptions/{s}/providers/Microsoft.Authorization/roleDefinitions/{guid}");
    const string KeyVaultSecretsUser = "4633458b-17de-408a-b874-0445c86b69e6";
    const string ServiceBusSender = "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39";
    const string ServiceBusReceiver = "4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0";
    const string AcrPull = "7f951dda-4ed3-4680-a7ca-43fe172d538d";
    const string AcrPush = "8311e382-0749-4cb8-b61a-1f7be2f8e9a2";

    var suffix = new RandomString("suffix", new RandomStringArgs { Length = 6, Special = false, Upper = false });

    // ---------- Logs ----------
    var logs = new Workspace("logs", new WorkspaceArgs
    {
        ResourceGroupName = rg, Location = location,
        Sku = new WorkspaceSkuArgs { Name = "PerGB2018" }, RetentionInDays = 30,
        WorkspaceCapping = new WorkspaceCappingArgs { DailyQuotaGb = 0.5 },   // cost guard
    });
    var logKey = GetSharedKeys.Invoke(new GetSharedKeysInvokeArgs
    {
        ResourceGroupName = rg, WorkspaceName = logs.Name,
    }).Apply(k => k.PrimarySharedKey!);

    // ---------- Identities: one per app ----------
    UserAssignedIdentity Identity(string name) => new(name, new UserAssignedIdentityArgs
    {
        ResourceGroupName = rg, Location = location, ResourceName = name,
    });
    var idApi = Identity("id-api");
    var idWriter = Identity("id-writer");
    var idWebhook = Identity("id-webhook");
    var idFakeMews = Identity("id-fakemews");
    var allApps = new[] { idApi, idWriter, idWebhook, idFakeMews };

    RoleAssignment Grant(string name, Input<string> principalId, string role, Input<string> scope,
        string principalType = "ServicePrincipal") => new(name, new RoleAssignmentArgs
    {
        PrincipalId = principalId, PrincipalType = principalType, RoleDefinitionId = RoleId(role), Scope = scope,
    });

    // ---------- Container registry: apps pull with their identity, GitHub pushes with its own ----------
    var acr = new Registry("acr", new RegistryArgs
    {
        ResourceGroupName = rg, Location = location,
        RegistryName = suffix.Result.Apply(s => $"acrratedemo{s}"),
        Sku = new Pulumi.AzureNative.ContainerRegistry.Inputs.SkuArgs { Name = "Basic" },
        AdminUserEnabled = false,                      // no shared admin password
    });
    foreach (var id in allApps) Grant($"acrpull-{id.GetResourceName()}", id.PrincipalId, AcrPull, acr.Id);
    Grant("acrpush-github", deployerObjectId, AcrPush, acr.Id);

    // ---------- Key Vault: RBAC mode, roles granted per secret ----------
    var vault = new Vault("kv", new VaultArgs
    {
        ResourceGroupName = rg, Location = location,
        VaultName = suffix.Result.Apply(s => $"kv-ratedemo-{s}"),
        Properties = new VaultPropertiesArgs
        {
            TenantId = tenantId,
            Sku = new KvSku { Family = "A", Name = Pulumi.AzureNative.KeyVault.SkuName.Standard },
            EnableRbacAuthorization = true,
            EnableSoftDelete = true, SoftDeleteRetentionInDays = 7,
        },
    });

    Secret NewSecret(string name, Input<string> value, bool setByHuman = false) => new(name, new Pulumi.AzureNative.KeyVault.SecretArgs
    {
        ResourceGroupName = rg, VaultName = vault.Name, SecretName = name,
        Properties = new SecretPropertiesArgs { Value = value },
    }, new CustomResourceOptions { IgnoreChanges = setByHuman ? ["properties"] : [] });

    RandomPassword Random(string name, int length = 32) =>
        new(name, new RandomPasswordArgs { Length = length, Special = false });

    // Fake Mews credentials: one ClientToken for our integration, one AccessToken per hotel.
    var clientToken = NewSecret("mews-client-token", Random("rnd-client-token").Result);
    var hotelTokens = new[] { "barcelona", "madrid" }
        .Select(h => NewSecret($"mews-access-token-{h}", Random($"rnd-token-{h}").Result)).ToArray();
    var webhookSecret = NewSecret("mews-webhook-secret", Random("rnd-webhook", 40).Result);
    // Set by you, never by the pipeline: placeholders that later runs don't overwrite.
    var anthropicKey = NewSecret("anthropic-api-key", "set-me", setByHuman: true);
    var entraSecret = NewSecret("entra-client-secret", "set-me", setByHuman: true);

    var pgAdmin = Random("rnd-pg-admin");
    var pgApp = Random("rnd-pg-app");
    var pgRelay = Random("rnd-pg-relay");
    var dbAppSecret = NewSecret("db-app-password", pgApp.Result);
    var dbRelaySecret = NewSecret("db-relay-password", pgRelay.Result);

    void ReadSecrets(UserAssignedIdentity who, params Secret[] secrets)
    {
        foreach (var s in secrets)
            Grant($"kv-{who.GetResourceName()}-{s.GetResourceName()}", who.PrincipalId, KeyVaultSecretsUser, s.Id);
    }
    ReadSecrets(idApi, anthropicKey, entraSecret, dbAppSecret, dbRelaySecret);              // no Mews tokens
    ReadSecrets(idWriter, [clientToken, .. hotelTokens, dbAppSecret]);                      // no Anthropic key
    ReadSecrets(idWebhook, [clientToken, .. hotelTokens, webhookSecret, dbAppSecret]);
    ReadSecrets(idFakeMews, [clientToken, .. hotelTokens, webhookSecret]);                 // "Mews" knows its tokens

    // ---------- Service Bus: Standard tier, no keys, roles on the one queue ----------
    var bus = new Namespace("sb", new NamespaceArgs
    {
        ResourceGroupName = rg, Location = location,
        NamespaceName = suffix.Result.Apply(s => $"sb-ratedemo-{s}"),
        Sku = new SbSku { Name = Pulumi.AzureNative.ServiceBus.SkuName.Standard, Tier = Pulumi.AzureNative.ServiceBus.SkuTier.Standard },
        DisableLocalAuth = true,                       // SAS keys off: Entra identities only
        MinimumTlsVersion = "1.2",
    });
    var queue = new Queue("approved-rates", new QueueArgs
    {
        ResourceGroupName = rg, NamespaceName = bus.Name, QueueName = "approved-rates",
        RequiresSession = true,                                       // one session per hotel -> in order
        RequiresDuplicateDetection = true,                            // same MessageId within the window is dropped
        DuplicateDetectionHistoryTimeWindow = "PT30M",
        DefaultMessageTimeToLive = "PT30M",                           // stale prices expire
        DeadLetteringOnMessageExpiration = true,
        MaxDeliveryCount = 5,                                         // then dead-letter
        LockDuration = "PT1M",
    });
    Grant("sb-send-api", idApi.PrincipalId, ServiceBusSender, queue.Id);
    Grant("sb-receive-writer", idWriter.PrincipalId, ServiceBusReceiver, queue.Id);

    // ---------- Postgres (row-level security set up by db/schema.sql) ----------
    var pg = new Pg.Server("pg", new Pg.ServerArgs
    {
        ResourceGroupName = rg, Location = location,
        ServerName = suffix.Result.Apply(s => $"pg-ratedemo-{s}"),
        Version = "16",
        AdministratorLogin = "pgowner",
        AdministratorLoginPassword = pgAdmin.Result,
        Sku = new Pg.Inputs.SkuArgs { Name = "Standard_B1ms", Tier = "Burstable" },
        Storage = new Pg.Inputs.StorageArgs { StorageSizeGB = 32 },
        Network = new Pg.Inputs.NetworkArgs { PublicNetworkAccess = "Enabled" },
        HighAvailability = new Pg.Inputs.HighAvailabilityArgs { Mode = "Disabled" },
        Backup = new Pg.Inputs.BackupArgs { BackupRetentionDays = 7, GeoRedundantBackup = "Disabled" },
    });
    new Pg.Database("db", new Pg.DatabaseArgs
    {
        ResourceGroupName = rg, ServerName = pg.Name, DatabaseName = "ratedemo",
    });
    // Demo shortcut: allow Azure services instead of private networking (that needs a VNet; ~€25-40/day extra).
    new Pg.FirewallRule("allow-azure", new Pg.FirewallRuleArgs
    {
        ResourceGroupName = rg, ServerName = pg.Name, FirewallRuleName = "AllowAzureServices",
        StartIpAddress = "0.0.0.0", EndIpAddress = "0.0.0.0",
    });

    // ---------- Container Apps environment ----------
    var env = new ManagedEnvironment("cae", new ManagedEnvironmentArgs
    {
        ResourceGroupName = rg, Location = location,
        EnvironmentName = "cae-ratedemo",
        AppLogsConfiguration = new AppLogsConfigurationArgs
        {
            Destination = "log-analytics",
            LogAnalyticsConfiguration = new LogAnalyticsConfigurationArgs { CustomerId = logs.CustomerId, SharedKey = logKey },
        },
    });

    var outputs = new Dictionary<string, object?>
    {
        ["acrLoginServer"] = acr.LoginServer,
        ["keyVaultName"] = vault.Name,
        ["pgHost"] = pg.FullyQualifiedDomainName,
        ["pgServerName"] = pg.Name,
        ["pgAdminPassword"] = pgAdmin.Result,
        ["pgAppPassword"] = pgApp.Result,
        ["pgRelayPassword"] = pgRelay.Result,
        ["imageTag"] = imageTag ?? "",
        ["apiUrl"] = env.DefaultDomain.Apply(d => $"https://ca-api.{d}"),
    };
    if (string.IsNullOrEmpty(imageTag)) return outputs;   // first run: infra only, no image pushed yet

    // ---------- The four apps: same image, different entry point, different identity ----------
    var image = Output.Format($"{acr.LoginServer}/ratedemo:{imageTag}");
    var kvUrl = Output.Format($"https://{vault.Name}.vault.azure.net/");
    var internalUrl = new Func<string, Output<string>>(app => env.DefaultDomain.Apply(d => $"https://{app}.internal.{d}"));

    ContainerApp App(string name, UserAssignedIdentity id, string dll, IngressArgs? ingress,
        Dictionary<string, Input<string>> settings, params (string Name, Secret Secret, string Env)[] secrets)
    {
        var envVars = new InputList<EnvironmentVarArgs>
        {
            new EnvironmentVarArgs { Name = "AZURE_CLIENT_ID", Value = id.ClientId },
            new EnvironmentVarArgs { Name = "KEY_VAULT_URL", Value = kvUrl },
            new EnvironmentVarArgs { Name = "DB_HOST", Value = pg.FullyQualifiedDomainName },
        };
        foreach (var (k, v) in settings) envVars.Add(new EnvironmentVarArgs { Name = k, Value = v });
        foreach (var s in secrets) envVars.Add(new EnvironmentVarArgs { Name = s.Env, SecretRef = s.Name });

        return new ContainerApp(name, new ContainerAppArgs
        {
            ResourceGroupName = rg, Location = location, ContainerAppName = name,
            ManagedEnvironmentId = env.Id,
            Identity = new Pulumi.AzureNative.App.Inputs.ManagedServiceIdentityArgs
            {
                Type = Pulumi.AzureNative.App.ManagedServiceIdentityType.UserAssigned,
                UserAssignedIdentities = { id.Id },
            },
            Configuration = new ConfigurationArgs
            {
                Ingress = ingress!,
                Registries = { new RegistryCredentialsArgs { Server = acr.LoginServer, Identity = id.Id } },
                // Key Vault references: the platform fetches the value with the app's own identity.
                Secrets = secrets.Select(s => new Pulumi.AzureNative.App.Inputs.SecretArgs
                {
                    Name = s.Name, KeyVaultUrl = s.Secret.Properties.Apply(p => p.SecretUri), Identity = id.Id,
                }).ToList(),
            },
            Template = new TemplateArgs
            {
                Containers =
                {
                    new ContainerArgs
                    {
                        Name = name, Image = image,
                        Command = { "dotnet", $"/app/{dll}/RateDemo.{dll}.dll" },
                        Env = envVars,
                        Resources = new ContainerResourcesArgs { Cpu = 0.25, Memory = "0.5Gi" },
                    },
                },
                Scale = new ScaleArgs { MinReplicas = 1, MaxReplicas = 1 },
            },
        });
    }

    var fakeMews = App("ca-fakemews", idFakeMews, "FakeMews",
        new IngressArgs { External = false, TargetPort = 8080 },
        new() { ["WEBHOOK_URL"] = internalUrl("ca-webhook").Apply(u => u + "/webhooks/mews") });
    App("ca-webhook", idWebhook, "Webhook",
        new IngressArgs { External = false, TargetPort = 8080 },
        new() { ["MEWS_BASE_URL"] = internalUrl("ca-fakemews") },
        ("db-app-password", dbAppSecret, "DB_APP_PASSWORD"));
    App("ca-writer", idWriter, "Writer", null,
        new()
        {
            ["MEWS_BASE_URL"] = internalUrl("ca-fakemews"),
            ["SERVICEBUS_FQDN"] = Output.Format($"{bus.Name}.servicebus.windows.net"),
            ["QUEUE_NAME"] = queue.Name,
        },
        ("db-app-password", dbAppSecret, "DB_APP_PASSWORD"));
    var api = App("ca-api", idApi, "Api",
        new IngressArgs
        {
            External = true, TargetPort = 8080, AllowInsecure = false,
            // Ingress allow-list: only these IPs reach the dashboard (empty = open, for first sign-in tests).
            IpSecurityRestrictions = allowedIps.Select((ip, i) => new IpSecurityRestrictionRuleArgs
            {
                Name = $"allow-{i}", Action = "Allow", IpAddressRange = ip.Trim(),
            }).ToList(),
        },
        new()
        {
            ["ENTRA_TENANT_ID"] = tenantId,
            ["ENTRA_CLIENT_ID"] = staffClientId,
            ["PUBLIC_URL"] = env.DefaultDomain.Apply(d => $"https://ca-api.{d}"),
            ["SERVICEBUS_FQDN"] = Output.Format($"{bus.Name}.servicebus.windows.net"),
            ["QUEUE_NAME"] = queue.Name,
            ["FAKE_MEWS_URL"] = internalUrl("ca-fakemews"),
            ["CLAUDE_MODEL"] = claudeModel,
        },
        ("db-app-password", dbAppSecret, "DB_APP_PASSWORD"),
        ("db-relay-password", dbRelaySecret, "DB_RELAY_PASSWORD"));

    outputs["apiUrl"] = Output.Format($"https://{api.Configuration.Apply(c => c!.Ingress!.Fqdn)}");
    return outputs;
});
