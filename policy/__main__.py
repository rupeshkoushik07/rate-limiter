"""CrossGuard policy pack: rules every infrastructure change must pass.

Runs on every `pulumi up` in the deploy pipeline. MANDATORY rules fail the run before anything changes.
The rules themselves live in rules.py and are unit-tested in test_rules.py.
"""
from pulumi_policy import EnforcementLevel, PolicyPack, ResourceValidationPolicy

from rules import (container_apps_safe, key_vault_rbac, no_broad_roles, no_open_database,
                   registry_no_admin, service_bus_no_keys)

PolicyPack(
    name="rate-limiter-guardrails",
    enforcement_level=EnforcementLevel.MANDATORY,
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
