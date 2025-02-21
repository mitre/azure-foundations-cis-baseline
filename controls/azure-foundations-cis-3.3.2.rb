control 'azure-foundations-cis-3.3.2' do
  title 'Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults.'
  desc 'Ensure that all Keys in Non Role Based Access Control (RBAC) Azure Key Vaults have an expiration date set.'

  desc 'rationale',
       "Azure Key Vault enables users to store and use cryptographic keys within the Microsoft
        Azure environment. The exp (expiration date) attribute identifies the expiration date on
        or after which the key MUST NOT be used for a cryptographic operation. By default,
        keys never expire. It is thus recommended that keys be rotated in the key vault and set
        an explicit expiration date for all keys. This ensures that the keys cannot be used
        beyond their assigned lifetimes"

  desc 'impact',
       "Keys cannot be used beyond their assigned expiration dates respectively. Keys need to
        be rotated periodically wherever they are used."

  desc 'check',
       "Audit from Azure Portal
        1. Go to Key vaults.
        2. For each Key vault, click on Keys.
        3. In the main pane, ensure that an appropriate Expiration date is set for any
        keys that are Enabled.
        Audit from Azure CLI
        Get a list of all the key vaults in your Azure environment by running the following
        command:
        az keyvault list
        Then for each key vault listed ensure that the output of the below command contains
        Key ID (kid), enabled status as true and Expiration date (expires) is not empty or null:
        az keyvault key list --vault-name <VaultName> --query
        '[*].{'kid':kid,'enabled':attributes.enabled,'expires':attributes.expires}'
        Audit from PowerShell
        Retrieve a list of Azure Key vaults:
        Get-AzKeyVault
        For each Key vault run the following command to determine which vaults are configured
        to use RBAC.
        Get-AzKeyVault -VaultName <VaultName>
        For each Key vault with the EnableRbacAuthorizatoin setting set to True, run the
        following command.
        Get-AzKeyVaultKey -VaultName <VaultName>
        Make sure the Expires setting is configured with a value as appropriate wherever the
        Enabled setting is set to True.
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0 - Name: 'Key Vault keys
        should have an expiration date'"

  desc 'fix',
       "Remediate from Azure Portal
        1. Go to Key vaults.
        2. For each Key vault, click on Keys.
        3. In the main pane, ensure that an appropriate Expiration date is set for any
        keys that are Enabled.
        Remediate from Azure CLI
        Update the Expiration date for the key using the below command:
        az keyvault key set-attributes --name <keyName> --vault-name <vaultName> --
        expires Y-m-d'T'H:M:S'Z'
        Note: To view the expiration date on all keys in a Key Vault using Microsoft API, the
        'List' Key permission is required.
        To update the expiration date for the keys:
        1. Go to the Key vault, click on Access Control (IAM).
        2. Click on Add role assignment and assign the role of Key Vault Crypto Officer to
        the appropriate user.
        Remediate from PowerShell
        Set-AzKeyVaultKeyAttribute -VaultName <VaultName> -Name <KeyName> -Expires
        <DateTime>"

  impact 0.5
  tag nist: ['AU-11', 'CM-12', 'SI-12', 'AC-1', 'AC-2', 'AC-2(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.1', '6.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis'
  ref 'https://docs.microsoft.com/en-us/rest/api/keyvault/about-keys--secrets-and-certificates#key-vault-keys'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-6-use-a-secure-key-management-process'
  ref 'https://docs.microsoft.com/en-us/powershell/module/az.keyvault/set-azkeyvaultkeyattribute?view=azps-0.10.0'

  describe 'benchmark' do
    skip 'The check for this control needs to be done manually'
  end
end
