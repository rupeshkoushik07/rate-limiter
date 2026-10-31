"""CrossGuard policy pack: rules every infrastructure change must pass.

Runs with `pulumi preview --policy-pack policy` on pull requests and again before `pulumi up` on main.
MANDATORY rules fail the run, so a change that breaks one can't be merged or deployed.
"""
from pulumi_policy import EnforcementLevel, PolicyPack, ResourceValidationPolicy

MANDATORY = EnforcementLevel.MANDATORY

# Built-in roles that are too broad for any app or pipeline identity in this stack.
BROAD_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c4a72b9d": "User Access Administrator",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
    "090c5cfd-751d-490a-894a-3ce6f1109419": "Azure Service Bus Data Owner",
}


def _props(args, *path):
    value = args.props
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def key_vault_rbac(args, report):
    if args.resource_type == "azure-native:keyvault:Vault":
        if _props(args, "properties", "enableRbacAuthorization") is not True:
            report("Key Vault must use Azure RBAC (per-secret roles), not access policies. "
                   f"(got {_props(args, 'properties', 'enableRbacAuthorization')!r}; keys {sorted((args.props.get('properties') or {}).keys())})")
        if _props(args, "properties", "enableSoftDelete") is False:
            report("Key Vault soft delete must stay on, so a deleted secret can be recovered.")


def service_bus_no_keys(args, report):
    if args.resource_type == "azure-native:servicebus:Namespace":
        if _props(args, "disableLocalAuth") is not True:
            report("Service Bus SAS keys must be off (disableLocalAuth): identities only. "
                   f"(got {_props(args, 'disableLocalAuth')!r}; keys {sorted(args.props.keys())})")


def registry_no_admin(args, report):
    if args.resource_type == "azure-native:containerregistry:Registry":
        if _props(args, "adminUserEnabled") is True:
            report("Container registry admin user must be off: it's a shared password.")


def container_apps_safe(args, report):
    if args.resource_type != "azure-native:app:ContainerApp":
        return
    ingress = _props(args, "configuration", "ingress") or {}
    if ingress.get("allowInsecure"):
        report("Container app ingress must be HTTPS only.")
    for c in _props(args, "template", "containers") or []:
        image = c.get("image") or ""
        if image and "@sha256:" not in image:
            report(f"Container '{c.get('name')}' must deploy by digest (@sha256:...), not a movable tag: {image}")


def no_broad_roles(args, report):
    if args.resource_type == "azure-native:authorization:RoleAssignment":
        role_id = (_props(args, "roleDefinitionId") or "").rsplit("/", 1)[-1].lower()
        if role_id in BROAD_ROLES:
            report(f"Role '{BROAD_ROLES[role_id]}' is too broad; grant a narrow data role on a single resource.")


def no_open_database(args, report):
    if args.resource_type == "azure-native:dbforpostgresql:FirewallRule":
        start, end = _props(args, "startIpAddress"), _props(args, "endIpAddress")
        if start == "0.0.0.0" and end == "255.255.255.255":
            report("Postgres must not be open to the whole internet.")


PolicyPack(
    name="rate-limiter-guardrails",
    enforcement_level=MANDATORY,
    policies=[
        ResourceValidationPolicy(name="key-vault-rbac-and-soft-delete", description="Key Vault uses RBAC and soft delete",
                                 validate=key_vault_rbac),
        ResourceValidationPolicy(name="service-bus-no-sas-keys", description="Service Bus local auth disabled",
                                 validate=service_bus_no_keys),
        ResourceValidationPolicy(name="registry-no-admin-user", description="ACR admin user disabled",
                                 validate=registry_no_admin),
        ResourceValidationPolicy(name="container-apps-https-and-digest", description="HTTPS only, images pinned by digest",
                                 validate=container_apps_safe),
        ResourceValidationPolicy(name="no-broad-role-assignments", description="No Owner/Contributor/UAA-style roles",
                                 validate=no_broad_roles),
        ResourceValidationPolicy(name="no-public-database", description="No Postgres rule open to all IPs",
                                 validate=no_open_database),
    ],
)
