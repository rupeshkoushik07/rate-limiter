"""CrossGuard rules as plain functions, so they can be unit-tested without Pulumi.

Runs with `pulumi preview --policy-pack policy` on pull requests and again before `pulumi up` on main.
MANDATORY rules fail the run, so a change that breaks one can't be merged or deployed.
"""
from collections.abc import Mapping


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
        # Pulumi passes a Mapping, not always a dict: checking for dict made every rule read None.
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def key_vault_rbac(args, report):
    if args.resource_type == "azure-native:keyvault:Vault":
        if _props(args, "properties", "enableRbacAuthorization") is not True:
            report("Key Vault must use Azure RBAC (per-secret roles), not access policies.")
        if _props(args, "properties", "enableSoftDelete") is False:
            report("Key Vault soft delete must stay on, so a deleted secret can be recovered.")


def service_bus_no_keys(args, report):
    if args.resource_type == "azure-native:servicebus:Namespace":
        if _props(args, "disableLocalAuth") is not True:
            report("Service Bus SAS keys must be off (disableLocalAuth): identities only.")


def registry_no_admin(args, report):
    if args.resource_type == "azure-native:containerregistry:Registry":
        if _props(args, "adminUserEnabled") is True:
            report("Container registry admin user must be off: it's a shared password.")


def container_apps_safe(args, report):
    if args.resource_type != "azure-native:app:ContainerApp":
        return
    if _props(args, "configuration", "ingress", "allowInsecure"):
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
