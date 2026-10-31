using System.Text.Json;
using Pulumi;
using Pulumi.AzureNative.ApplicationInsights;
using Pulumi.AzureNative.Monitor;
using Pulumi.AzureNative.Monitor.Inputs;
using Pulumi.AzureNative.OperationalInsights;

/// <summary>
/// Detection: every log source into one workspace, an operations workbook, and alert rules.
/// Each detection maps to a risk in the design (see the comments on each rule).
/// </summary>
static class Observability
{
    // All app logs are one JSON object per line; these columns make them queryable.
    private const string AppLogs = """
        let L = ContainerAppConsoleLogs_CL
        | extend j = parse_json(Log_s)
        | extend App = ContainerAppName_s, Level = tostring(j.LogLevel), Category = tostring(j.Category),
                 Msg = tostring(j.Message), Exception = tostring(j.Exception);
        """;

    public static void Create(string rg, string location, Workspace logs, Input<string> vaultId, Input<string> busId,
        Input<string> pgId, Input<string> rgId, Output<string> kvAllowedReads, string? alertEmail)
    {
        // ---------- 1. Every source into the workspace ----------
        DiagnosticSetting Diagnostics(string name, Input<string> resourceId, string categoryGroup) =>
            new(name, new DiagnosticSettingArgs
            {
                Name = "to-log-analytics", ResourceUri = resourceId, WorkspaceId = logs.Id,
                LogAnalyticsDestinationType = "Dedicated",
                Logs = { new DiagnosticsLogSettingsArgs { CategoryGroup = categoryGroup, Enabled = true } },
                Metrics = { new DiagnosticsMetricSettingsArgs { Category = "AllMetrics", Enabled = true } },
            });
        Diagnostics("diag-kv", vaultId, "audit");        // who read which secret, and who was denied
        Diagnostics("diag-sb", busId, "allLogs");
        Diagnostics("diag-pg", pgId, "allLogs");

        // ---------- 2. Where alerts go ----------
        ActionGroup? group = string.IsNullOrWhiteSpace(alertEmail) ? null : new ActionGroup("ag-oncall", new Pulumi.AzureNative.Monitor.ActionGroupArgs
        {
            ResourceGroupName = rg, Location = "global", GroupShortName = "ratelimit", Enabled = true,
            EmailReceivers = { new MicrosoftCommonEmailReceiverArgs { Name = "on-call", EmailAddress = alertEmail!, UseCommonAlertSchema = true } },
        });

        // ---------- 3. Log-based detections: the query returns rows only when something is wrong ----------
        void Detect(string name, int severity, string description, Input<string> query, string window = "PT15M")
        {
            new ScheduledQueryRule(name, new ScheduledQueryRuleArgs
            {
                ResourceGroupName = rg, Location = location, RuleName = name,
                DisplayName = name, Description = description, Kind = "LogAlert",
                Severity = severity, Enabled = true, AutoMitigate = false,
                Scopes = { logs.Id }, EvaluationFrequency = "PT5M", WindowSize = window,
                Criteria = new ScheduledQueryRuleCriteriaArgs
                {
                    AllOf =
                    {
                        new ConditionArgs
                        {
                            Query = query, TimeAggregation = "Count", Operator = "GreaterThanOrEqual", Threshold = 1,
                            FailingPeriods = new ConditionFailingPeriodsArgs { NumberOfEvaluationPeriods = 1, MinFailingPeriodsToAlert = 1 },
                        },
                    },
                },
                Actions = group is null ? null! : new ActionsArgs { ActionGroups = { group.Id } },
            });
        }

        // Key Vault: a secret read by an identity that isn't on the allow-list for that secret.
        Detect("kv-unexpected-secret-read", 1,
            "A Key Vault secret was read by an identity that should not read it (e.g. the API reading a hotel token).",
            kvAllowedReads.Apply(allowed => $$"""
                let allowed = datatable(oid:string, secret:string) [{{allowed}}];
                union isfuzzy=true
                  (AZKVAuditLogs | where OperationName == "SecretGet"
                     | extend secret = extract(@"/secrets/([^/?]+)", 1, RequestUri),
                              oid = tostring(Identity.claim.oid)),
                  (AzureDiagnostics | where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName == "SecretGet"
                     | extend secret = extract(@"/secrets/([^/?]+)", 1, tostring(column_ifexists("requestUri_s", ""))),
                              oid = tostring(column_ifexists("identity_claim_oid_g", "")))
                | where isnotempty(oid)
                | join kind=leftanti allowed on oid, secret
                | project TimeGenerated, oid, secret
                """));

        // Key Vault: someone was refused (403): probing for secrets they don't have.
        Detect("kv-denied-secret-read", 2, "A Key Vault request was denied (403).", """
            union isfuzzy=true
              (AZKVAuditLogs | where ResultSignature == "Forbidden" or HttpStatusCode == 403),
              (AzureDiagnostics | where ResourceProvider == "MICROSOFT.KEYVAULT" and tostring(column_ifexists("httpStatusCode_d", "")) == "403")
            | project TimeGenerated
            """);

        // The most important one: a price changed in "Mews" without a matching applied approval.
        Detect("price-change-without-approval", 0,
            "Mews reports more price changes than the rate writer applied: a price was published without an approval.",
            AppLogs + """
            let changed = toscalar(L | where App == "ca-fakemews" and Msg startswith "Price updated" | count);
            let applied = toscalar(L | where App == "ca-writer" and Msg has ": applied" | count);
            print changed, applied
            | where changed > applied
            """);

        // Runaway automation (Amazon 1p / feedback loops).
        Detect("discount-burst", 1, "More than 5 price changes applied in 15 minutes.",
            AppLogs + "L | where App == \"ca-writer\" and Msg has \": applied\" | summarize n = count() | where n > 5");

        // The circuit breaker paused auto-apply: a human must look.
        Detect("circuit-breaker-tripped", 1, "Auto-apply was paused automatically for a hotel.",
            AppLogs + "L | where Msg has \"CIRCUIT BREAKER\" | project TimeGenerated, Msg");

        // The LLM misbehaving or being manipulated: many guardrail rejections.
        Detect("guardrail-rejection-spike", 2, "3+ AI suggestions rejected by the guardrail in 15 minutes.",
            AppLogs + "L | where App == \"ca-worker\" and Msg matches regex @\"^Suggestion \\d+ for \" and Msg !has \"guardrail ok\" | summarize n = count() | where n >= 3");

        // Forged webhooks.
        Detect("webhook-bad-token", 2, "3+ webhooks with a wrong secret token in 5 minutes.",
            AppLogs + "L | where App == \"ca-webhook\" and Msg has \"bad token\" | summarize n = count() | where n >= 3", "PT5M");

        // Credential attacks on staff login.
        Detect("login-rejected", 2, "3+ rejected staff sign-ins in 15 minutes.",
            AppLogs + "L | where App == \"ca-api\" and Msg has \"Login rejected\" | summarize n = count() | where n >= 3");

        // We are hammering Mews (Mews blocks integrations that do this).
        Detect("mews-rate-limited", 2, "3+ HTTP 429 responses from Mews in 15 minutes.",
            AppLogs + "L | where App == \"ca-writer\" and Msg has \"429\" | summarize n = count() | where n >= 3");

        // A secret in the logs (the n8n / Trigger.dev cases; and our own leaked webhook URL).
        Detect("secret-in-logs", 0, "A log line looks like it contains a token.",
            "ContainerAppConsoleLogs_CL | where Log_s has \"token=\" or Log_s has \"\\\"AccessToken\\\"\" or Log_s has \"\\\"ClientToken\\\"\" or Log_s has \"sk-ant-\" | project TimeGenerated, ContainerAppName_s");

        // Crashes.
        Detect("app-errors", 3, "An app logged an error.",
            AppLogs + "L | where Level in (\"Error\", \"Critical\") | project TimeGenerated, App, Msg");

        // ---------- 4. Metric alert: a stuck price ----------
        new MetricAlert("dead-letters", new MetricAlertArgs
        {
            ResourceGroupName = rg, Location = "global", RuleName = "dead-lettered-approvals",
            Description = "An approved price is in the dead-letter queue: neither silently lost nor blindly replayed.",
            Severity = 1, Enabled = true, Scopes = { busId }, EvaluationFrequency = "PT5M", WindowSize = "PT15M",
            Criteria = new MetricAlertSingleResourceMultipleMetricCriteriaArgs
            {
                OdataType = "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                AllOf =
                {
                    new MetricCriteriaArgs
                    {
                        CriterionType = "StaticThresholdCriterion", Name = "dlq", MetricName = "DeadletteredMessages",
                        TimeAggregation = "Maximum", Operator = "GreaterThan", Threshold = 0,
                    },
                },
            },
            Actions = group is null ? [] : new InputList<MetricAlertActionArgs> { new MetricAlertActionArgs { ActionGroupId = group.Id } },
        });

        // ---------- 5. Activity log alert: someone changed who can do what ----------
        new ActivityLogAlert("role-assignment-changed", new ActivityLogAlertArgs
        {
            ResourceGroupName = rg, Location = "global", ActivityLogAlertName = "role-assignment-changed",
            Description = "A role assignment was created or deleted in the resource group (expected during deploys).",
            Enabled = true, Scopes = { rgId },
            Condition = new AlertRuleAllOfConditionArgs
            {
                AllOf =
                {
                    new AlertRuleAnyOfOrLeafConditionArgs { Field = "category", Equals = "Administrative" },
                    new AlertRuleAnyOfOrLeafConditionArgs { Field = "resourceType", Equals = "Microsoft.Authorization/roleAssignments" },
                    // Each change logs "Started" then "Succeeded"; alert once, on the result.
                    new AlertRuleAnyOfOrLeafConditionArgs { Field = "status", Equals = "Succeeded" },
                },
            },
            Actions = new ActionListArgs
            {
                ActionGroups = group is null ? [] : new InputList<Pulumi.AzureNative.Monitor.Inputs.ActionGroupArgs> { new Pulumi.AzureNative.Monitor.Inputs.ActionGroupArgs { ActionGroupId = group.Id } },
            },
        });

        // ---------- 6. The operations workbook ----------
        var uuid = new Pulumi.Random.RandomUuid("workbook-id");
        new Workbook("ops-workbook", new WorkbookArgs
        {
            ResourceGroupName = rg, Location = location, ResourceName = uuid.Result,
            Kind = "shared", Category = "workbook", DisplayName = "Rate limiter: operations",
            SourceId = logs.Id,
            SerializedData = logs.Id.Apply(WorkbookJson),
        });
    }

    private static string WorkbookJson(string workspaceId)
    {
        object Text(string md) => new { type = 1, content = new { json = md } };
        object Kql(string title, string query, string viz = "table") => new
        {
            type = 3,
            content = new
            {
                version = "KqlItem/1.0", query, size = 0, title, timeContext = new { durationMs = 86400000 },
                queryType = 0, resourceType = "microsoft.operationalinsights/workspaces", visualization = viz,
            },
        };
        var items = new[]
        {
            Text("# Rate limiter: operations\nLast 24 hours. Every tile is a KQL query you can open and change."),
            Kql("Approvals by outcome (from the rate writer)", AppLogs +
                "L | where App == \"ca-writer\" and Msg startswith \"Approval \" | extend Status = extract(@\": (\\w+) \\(\", 1, Msg) | summarize count() by Status", "piechart"),
            Kql("Price changes over time", AppLogs +
                "L | where App == \"ca-writer\" and Msg has \": applied\" | summarize changes = count() by bin(TimeGenerated, 15m)", "timechart"),
            Kql("AI suggestions: trigger and guardrail result", AppLogs +
                "L | where App == \"ca-worker\" and Msg startswith \"Suggestion \" | project TimeGenerated, Msg | order by TimeGenerated desc | take 50"),
            Kql("Auto-apply, kill switch and circuit breaker", AppLogs +
                "L | where Msg has_any (\"Auto-applied\", \"CIRCUIT BREAKER\", \"Auto-apply\") | project TimeGenerated, App, Msg | order by TimeGenerated desc"),
            Kql("Who read which Key Vault secret", """
                union isfuzzy=true (AZKVAuditLogs | where OperationName == "SecretGet"
                  | extend secret = extract(@"/secrets/([^/?]+)", 1, RequestUri), oid = tostring(Identity.claim.oid), result = ResultSignature)
                | summarize reads = count() by secret, oid, result | order by secret asc
                """),
            Kql("Webhooks: accepted, rejected, refreshed", AppLogs +
                "L | where App == \"ca-webhook\" and Msg !startswith \"Request\" | summarize count() by Msg = substring(Msg, 0, 60)"),
            Kql("Staff sign-ins", AppLogs +
                "L | where App == \"ca-api\" and Msg has_any (\"signed in\", \"Login rejected\") | project TimeGenerated, Msg | order by TimeGenerated desc"),
            Kql("Mews calls by status (Request-Id logged, bodies never)", AppLogs +
                "L | where Msg startswith \"Mews \" | extend Status = extract(@\": (\\d+),\", 1, Msg) | summarize count() by App, Status"),
            Kql("Errors", AppLogs +
                "L | where Level in (\"Error\", \"Critical\", \"Warning\") | project TimeGenerated, App, Level, Msg, Exception | order by TimeGenerated desc | take 50"),
        };
        return JsonSerializer.Serialize(new { version = "Notebook/1.0", items, fallbackResourceIds = new[] { workspaceId } });
    }
}
