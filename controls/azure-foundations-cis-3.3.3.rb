control 'azure-foundations-cis-3.3.3' do
    title "Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults"
    desc "Ensure that all Keys in Role Based Access Control (RBAC) Azure Key Vaults have an
        expiration date set."

    desc 'rationale',
        "The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure
        environment. Secrets in the Azure Key Vault are octet sequences with a maximum size
        of 25k bytes each. The exp (expiration date) attribute identifies the expiration date on or
        after which the secret MUST NOT be used. By default, secrets never expire. It is thus
        recommended to rotate secrets in the key vault and set an explicit expiration date for all
        secrets. This ensures that the secrets cannot be used beyond their assigned lifetimes."

    desc 'impact',
        "Secrets cannot be used beyond their assigned expiry date respectively. Secrets need to
        be rotated periodically wherever they are used."

    desc 'check',
       "Audit from Azure Portal
        1. Go to Key vaults.
        2. For each Key vault, click on Secrets.
        3. In the main pane, ensure that the status of the secret is Enabled.
        4. For each enabled secret, ensure that an appropriate Expiration date is set.
        Audit from Azure CLI
        Ensure that the output of the below command contains ID (id), enabled status as true
        and Expiration date (expires) is not empty or null:
        az keyvault secret list --vault-name <KEYVAULTNAME> --query
        '[*].{'kid':kid,'enabled':attributes.enabled,'expires':attributes.expires}'
        Audit from PowerShell
        Retrieve a list of Key vaults:
        Get-AzKeyVault
        For each Key vault, run the following command to determine which vaults are
        configured to use RBAC:
        Get-AzKeyVault -VaultName <Vault Name>
        For each Key vault with the EnableRbacAuthorization setting set to True, run the
        following command:
        Get-AzKeyVaultSecret -VaultName <Vault Name>
        Make sure the Expires setting is configured with a value as appropriate wherever the
        Enabled setting is set to True.
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 98728c90-32c7-4049-8429-847dc0f4fe37 - Name: 'Key Vault secrets
        should have an expiration date'"

    desc 'fix',
       "Remediate from Azure Portal
        1. Go to Key vaults.
        2. For each Key vault, click on Secrets.
        3. In the main pane, ensure that the status of the secret is Enabled.
        4. For each enabled secret, ensure that an appropriate Expiration date is set.
        Remediate from Azure CLI
        Update the Expiration date for the secret using the below command:
        az keyvault secret set-attributes --name <secret_name> --vault-name
        <vault_name> --expires Y-m-d'T'H:M:S'Z'
        Note: To view the expiration date on all secrets in a Key Vault using Microsoft API, the
        List Secret permission is required.
        To update the expiration date for the secrets:
        1. Go to the Key vault, click on Access Control (IAM).
        2. Click on Add role assignment and assign the role of Key Vault Secrets
        Officer to the appropriate user.
        Remediate from PowerShell
        Set-AzKeyVaultSecretAttribute -VaultName <vault_name> -Name <secret_name> -
        Expires <date_time>"

    impact 0.5
    tag nist: ['AU-11','CM-12','SI-12','AC-1','AC-2','AC-2(1)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['3.1','6.2'] }]

    ref 'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis'
    ref 'https://docs.microsoft.com/en-us/rest/api/keyvault/about-keys--secrets-and-certificates#key-vault-secrets'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-6-use-a-secure-key-management-process'
    ref 'https://docs.microsoft.com/en-us/powershell/module/az.keyvault/set-azkeyvaultkeyattribute?view=azps-0.10.0'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end