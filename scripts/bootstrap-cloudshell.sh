#!/usr/bin/env bash
# One-time setup, run by a human in Azure Cloud Shell (Bash). Creates only what GitHub Actions
# can't create for itself. It prints IDs only, no secrets.
#   - resource groups, Pulumi state storage, a Key Vault key that encrypts Pulumi secrets
#   - id-github-deploy: a managed identity GitHub Actions signs in as through OIDC (no stored key),
#     trusted only for pushes to main of the repo below
#   - "RateDemo staff login": the Entra app for staff OIDC + PKCE, with app roles
#     (Viewer / Approver / Manager and one role per hotel); you get Approver + Hotel.Barcelona
set -euo pipefail

REPO="rupeshkoushik07/rate-limiter"
LOCATION="${LOCATION:-northeurope}"
STATE_RG="rg-ratedemo-state"
APP_RG="rg-ratedemo"

SUB=$(az account show --query id -o tsv)
TENANT=$(az account show --query tenantId -o tsv)
SUFFIX=$(echo -n "$SUB" | sha1sum | cut -c1-6)
ME=$(az ad signed-in-user show --query id -o tsv)
echo "Subscription $SUB, tenant $TENANT, region $LOCATION"

echo "== Registering resource providers (first time only)"
for ns in Microsoft.App Microsoft.OperationalInsights Microsoft.ServiceBus Microsoft.KeyVault \
          Microsoft.DBforPostgreSQL Microsoft.ContainerRegistry Microsoft.ManagedIdentity Microsoft.Storage; do
  az provider register --namespace "$ns" -o none
done

echo "== Resource groups"
az group create -n "$STATE_RG" -l "$LOCATION" -o none
az group create -n "$APP_RG" -l "$LOCATION" -o none

echo "== Pulumi state: storage account + container"
SA="strdstate$SUFFIX"
az storage account create -n "$SA" -g "$STATE_RG" -l "$LOCATION" --sku Standard_LRS \
  --allow-blob-public-access false --min-tls-version TLS1_2 -o none
az storage container create --account-name "$SA" -n pulumi --auth-mode key -o none

echo "== Key Vault key that encrypts Pulumi secrets"
KV="kv-rdstate-$SUFFIX"
az keyvault create -n "$KV" -g "$STATE_RG" -l "$LOCATION" --enable-rbac-authorization true -o none
KV_ID=$(az keyvault show -n "$KV" --query id -o tsv)
az role assignment create --assignee-object-id "$ME" --assignee-principal-type User \
  --role "Key Vault Crypto Officer" --scope "$KV_ID" -o none
echo "   waiting 60 s for the role to take effect..."; sleep 60
az keyvault key create --vault-name "$KV" -n pulumi --kty RSA --size 2048 -o none

echo "== GitHub Actions identity (OIDC, no stored secret)"
az identity create -n id-github-deploy -g "$STATE_RG" -l "$LOCATION" -o none
GH_CLIENT=$(az identity show -n id-github-deploy -g "$STATE_RG" --query clientId -o tsv)
GH_PRINCIPAL=$(az identity show -n id-github-deploy -g "$STATE_RG" --query principalId -o tsv)
az identity federated-credential create -n github-main --identity-name id-github-deploy -g "$STATE_RG" \
  --issuer https://token.actions.githubusercontent.com --subject "repo:$REPO:ref:refs/heads/main" \
  --audiences api://AzureADTokenExchange -o none
APP_RG_ID=$(az group show -n "$APP_RG" --query id -o tsv)
SA_ID=$(az storage account show -n "$SA" --query id -o tsv)
assign() { az role assignment create --assignee-object-id "$GH_PRINCIPAL" --assignee-principal-type ServicePrincipal \
             --role "$1" --scope "$2" -o none; }
assign "Contributor" "$APP_RG_ID"                                   # create resources in rg-ratedemo only
assign "Role Based Access Control Administrator" "$APP_RG_ID"       # give each app its own narrow roles
assign "Storage Blob Data Contributor" "$SA_ID"                     # Pulumi state
assign "Key Vault Crypto User" "$KV_ID"                             # Pulumi secrets encryption

echo "== Entra app for staff login (OIDC + PKCE) with app roles"
role() { echo "{\"allowedMemberTypes\":[\"User\"],\"description\":\"$2\",\"displayName\":\"$1\",\"id\":\"$(cat /proc/sys/kernel/random/uuid)\",\"isEnabled\":true,\"value\":\"$1\"}"; }
echo "[$(role Viewer 'Can view suggestions'),$(role Approver 'Can approve discounts up to 15%'),$(role Manager 'Can approve any allowed discount'),$(role Hotel.Barcelona 'Works for Hotel Barcelona'),$(role Hotel.Madrid 'Works for Hotel Madrid')]" > /tmp/roles.json
STAFF_APP=$(az ad app create --display-name "RateDemo staff login" --sign-in-audience AzureADMyOrg \
  --app-roles @/tmp/roles.json --web-redirect-uris "https://localhost/signin-oidc" --query appId -o tsv)
az ad sp create --id "$STAFF_APP" -o none
SP_OID=$(az ad sp show --id "$STAFF_APP" --query id -o tsv)
az ad sp update --id "$SP_OID" --set appRoleAssignmentRequired=true   # deny by default: no role, no login
for r in Approver Hotel.Barcelona; do
  RID=$(az ad app show --id "$STAFF_APP" --query "appRoles[?value=='$r'].id" -o tsv)
  az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_OID/appRoleAssignedTo" \
    --body "{\"principalId\":\"$ME\",\"resourceId\":\"$SP_OID\",\"appRoleId\":\"$RID\"}" -o none
done

cat <<EOF

=========== Done. Copy everything below back to Claude (IDs only, no secrets) ===========
AZURE_SUBSCRIPTION_ID=$SUB
AZURE_TENANT_ID=$TENANT
AZURE_CLIENT_ID=$GH_CLIENT
LOCATION=$LOCATION
PULUMI_BACKEND_URL=azblob://pulumi?storage_account=$SA
PULUMI_SECRETS_PROVIDER=azurekeyvault://$KV.vault.azure.net/keys/pulumi
STAFF_APP_CLIENT_ID=$STAFF_APP
STAFF_SP_OBJECT_ID=$SP_OID
============================================================================================
EOF
