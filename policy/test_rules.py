"""Tests for the CrossGuard rules. Props are wrapped in MappingProxyType because Pulumi passes a Mapping
that isn't a dict; a rule that only handles dicts reads None and silently never fails."""
from types import MappingProxyType, SimpleNamespace

import rules


def run(rule, resource_type, props):
    def freeze(v):
        if isinstance(v, dict):
            return MappingProxyType({k: freeze(x) for k, x in v.items()})
        if isinstance(v, list):
            return [freeze(x) for x in v]
        return v
    found = []
    rule(SimpleNamespace(resource_type=resource_type, props=freeze(props)), found.append)
    return found


VAULT = "azure-native:keyvault:Vault"
BUS = "azure-native:servicebus:Namespace"
APP = "azure-native:app:ContainerApp"
ROLE = "azure-native:authorization:RoleAssignment"
FW = "azure-native:dbforpostgresql:FirewallRule"
ACR = "azure-native:containerregistry:Registry"


def test_vault_with_rbac_passes():
    assert run(rules.key_vault_rbac, VAULT, {"properties": {"enableRbacAuthorization": True, "enableSoftDelete": True}}) == []

def test_vault_with_access_policies_fails():
    assert run(rules.key_vault_rbac, VAULT, {"properties": {"enableRbacAuthorization": False}})

def test_vault_without_soft_delete_fails():
    assert run(rules.key_vault_rbac, VAULT, {"properties": {"enableRbacAuthorization": True, "enableSoftDelete": False}})

def test_service_bus_keys_off_passes():
    assert run(rules.service_bus_no_keys, BUS, {"disableLocalAuth": True}) == []

def test_service_bus_keys_on_fails():
    assert run(rules.service_bus_no_keys, BUS, {"disableLocalAuth": False})

def test_registry_admin_fails():
    assert run(rules.registry_no_admin, ACR, {"adminUserEnabled": True})

def test_image_by_digest_passes():
    props = {"template": {"containers": [{"name": "api", "image": "acr.io/ratedemo@sha256:abc"}]}}
    assert run(rules.container_apps_safe, APP, props) == []

def test_image_by_tag_fails():
    props = {"template": {"containers": [{"name": "api", "image": "acr.io/ratedemo:latest"}]}}
    assert run(rules.container_apps_safe, APP, props)

def test_insecure_ingress_fails():
    assert run(rules.container_apps_safe, APP, {"configuration": {"ingress": {"allowInsecure": True}}})

def test_owner_role_fails():
    props = {"roleDefinitionId": "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}
    assert run(rules.no_broad_roles, ROLE, props)

def test_narrow_role_passes():
    props = {"roleDefinitionId": "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"}
    assert run(rules.no_broad_roles, ROLE, props) == []

def test_open_firewall_fails():
    assert run(rules.no_open_database, FW, {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"})

def test_azure_services_rule_passes():
    assert run(rules.no_open_database, FW, {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}) == []
