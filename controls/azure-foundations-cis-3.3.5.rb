control 'azure-foundations-cis-3.3.5' do
  title 'Ensure the Key Vault is Recoverable'
  desc "The Key Vault contains object keys, secrets, and certificates. Accidental unavailability of
        a Key Vault can cause immediate data loss or loss of security functions (authentication,
        validation, verification, non-repudiation, etc.) supported by the Key Vault objects.
        It is recommended the Key Vault be made recoverable by enabling the 'Do Not Purge'
        and 'Soft Delete' functions. This is in order to prevent loss of encrypted data, including
        storage accounts, SQL databases, and/or dependent services provided by Key Vault
        objects (Keys, Secrets, Certificates) etc. This may happen in the case of accidental
        deletion by a user or from disruptive activity by a malicious user.
        NOTE: In February 2025, Microsoft will enable soft-delete protection on all key vaults,
        and users will no longer be able to opt out of or turn off soft-delete.
        WARNING: A current limitation is that role assignments disappearing when Key Vault is
        deleted. All role assignments will need to be recreated after recovery"

  desc 'rationale',
       "There could be scenarios where users accidentally run delete/purge commands on Key
        Vault or an attacker/malicious user deliberately does so in order to cause disruption.
        Deleting or purging a Key Vault leads to immediate data loss, as keys encrypting data
        and secrets/certificates allowing access/services will become non-accessible.
        There is a Key Vault property that plays a role in permanent unavailability of a Key
        Vault:
        enablePurgeProtection: Setting this parameter to 'true' for a Key Vault ensures that
        even if Key Vault is deleted, Key Vault itself or its objects remain recoverable for the
        next 90 days. Key Vault/objects can either be recovered or purged (permanent deletion)
        during those 90 days. If no action is taken, the key vault and its objects will
        subsequently be purged.
        Enabling the enablePurgeProtection parameter on Key Vaults ensures that Key Vaults
        and their objects cannot be deleted/purged permanently."

  desc 'impact',
       'Once purge-protection and soft-delete are enabled for a Key Vault, the action is irreversible.'

  desc 'check',
       "Audit from Azure Portal
        1. Go to Key Vaults.
        2. For each Key Vault.
        3. Click Properties.
        4. Ensure the 'Enable purge protection (enforce a mandatory retention period for
        deleted vaults and vault objects)' is selected for Purge protection option on this
        key vault`.
        Audit from Azure CLI
        1. List all Resources of type Key Vaults:
        az resource list --query '[?type=='Microsoft.KeyVault/vaults']''
        2. For Every Key Vault ID ensure check parameters enablePurgeProtection is
        set to true.
        az resource show --id /subscriptions/xxxxxx-xxxx-xxxx-xxxx-
        xxxxxxxxxxxx/resourceGroups/<resourceGroupName>/providers/Microsoft.KeyVault
        /vaults/<keyVaultName>
        Audit from PowerShell
        Get all Key Vaults.
        Get-AzKeyVault
        For each Key Vault run the following command.
        Get-AzKeyVault -VaultName <Vault Name>
        Examine the results of the above command for the EnablePurgeProtection setting.
        Make sure enablePurgeProtection is set to True.
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 0b60c0b2-2dc2-4e1c-b5c9-abbed971de53 - Name: 'Key vaults should
        have deletion protection enabled'
        • Policy ID: 1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d - Name: 'Key vaults should
        have soft delete enabled'"

  desc 'fix',
       "To enable 'Do Not Purge' and 'Soft Delete' for a Key Vault:
        Remediate from Azure Portal
        1. Go to Key Vaults.
        2. For each Key Vault.
        3. Click Properties.
        4. Ensure the status of Purge protection reads Enable purge protection
        (enforce a mandatory retention period for deleted vaults and
        vault objects).
        Note, once enabled you cannot disable it.
        Remediate from Azure CLI
        az resource update --id /subscriptions/xxxxxx-xxxx-xxxx-xxxx-
        xxxxxxxxxxxx/resourceGroups/<resourceGroupName>/providers/Microsoft.KeyVault
        /vaults/<keyVaultName> --set properties.enablePurgeProtection=true
        Remediate from PowerShell
        Update-AzKeyVault -VaultName <vaultName -ResourceGroupName <resourceGroupName
        -EnablePurgeProtection
        Default Value:
        When a new Key Vault is created,
        • enableSoftDelete is enabled by default, and
        • enablePurgeProtection is disabled by default.
        NOTE: In February 2025, Microsoft will enable soft-delete protection on all key vaults,
        and users will no longer be able to opt out of or turn off soft-delete."

  impact 0.5
  tag nist: ['CP-2', 'CP-10']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['11.1'] }]

  ref 'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-soft-delete-cli'
  ref 'https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-8-define-and-implement-backup-and-recovery-strategy'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-8-ensure-security-of-key-and-certificate-repository'

  vault_script = 'Get-AzKeyVault | ConvertTo-Json'
  vault_output = powershell(vault_script).stdout.strip
  all_vaults = json(content: vault_output).params

  only_if('N/A - No Key Vaults found', impact: 0) do
    case all_vaults
    when Array
      !all_vaults.empty?
    when Hash
      !all_vaults.empty?
    else
      false
    end
  end

  check_key_vault_recoverable_script = %(
      $keyVaults = Get-AzKeyVault
      if ($keyVaults -eq $null){
            Write-Output "No Key Vaults Found"
      }
      foreach ($vault in $keyVaults) {
            $vaultName = $vault.VaultName
            $vaultResourceGroup = $vault.ResourceGroupName

            # Get the Key Vault details
            $vaultDetails = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $vaultResourceGroup

            if ($vaultDetails.EnablePurgeProtection -eq $false) {
                  Write-Host "$vaultName"
            }
      }

  )

  pwsh_output = powershell(check_key_vault_recoverable_script)

  describe "Ensure the number of vaults with EnablePurgeProtection set to 'False'" do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following vaults do not have EnablePurgeProtection set to 'True': #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
