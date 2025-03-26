control 'azure-foundations-cis-3.3.8' do
  title 'Ensure Automatic Key Rotation is Enabled Within Azure Key Vault for the Supported Services '
  desc "Automatic Key Rotation is available in Public Preview. The currently supported
        applications are Key Vault, Managed Disks, and Storage accounts accessing keys
        within Key Vault. The number of supported applications will incrementally increased."

  desc 'rationale',
       "Once set up, Automatic Private Key Rotation removes the need for manual
        administration when keys expire at intervals determined by your organization's policy.
        The recommended key lifetime is 2 years. Your organization should determine its own
        key expiration policy."

  desc 'impact',
       'There are an additional costs per operation in running the needed applications.'

  desc 'check',
       "Audit from Azure Portal
        1. From Azure Portal select the Portal Menu in the top left.
        2. Select Key Vaults.
        3. Select a Key Vault to audit.
        4. Under Objects select Keys.
        5. Select a key to audit.
        6. In the top row select Rotation policy.
        7. Ensure Enable auto rotation is set to Enabled.
        8. Repeat steps 3-7 for each Key Vault and Key.
        Audit from Azure CLI
        Run the following command:
        az keyvault key rotation-policy show --vault-name <vaultName> --name
        <keyName>
        Ensure that the response contains a lifetime action of Rotate.
        Audit from PowerShell
        Run the following command:
        Get-AzKeyVaultKeyRotationPolicy -VaultName <vaultName> -Name <keyName>
        Ensure that the response contains a lifetime action of Rotate.
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: d8cf8476-a2ec-4916-896e-992351803c44 - Name: 'Keys should have
        a rotation policy ensuring that their rotation is scheduled within the specified
        number of days after creation.'"

  desc 'fix',
       "Note: Azure CLI and Powershell use ISO8601 flags to input timespans. Every timespan
        input will be in the format P<timespanInISO8601Format>(Y,M,D). The leading P is
        required with it denoting period. The (Y,M,D) are for the duration of Year, Month,and
        Day respectively. A time frame of 2 years, 2 months, 2 days would be (P2Y2M2D).
        Remediate from Azure Portal
        1. From Azure Portal select the Portal Menu in the top left.
        2. Select Key Vaults.
        3. Select a Key Vault to audit.
        4. Under Objects select Keys.
        5. Select a key to audit.
        6. In the top row select Rotation policy.
        7. Select an Expiry time.
        8. Set Enable auto rotation to Enabled.
        9. Set an appropriate Rotation option and Rotation time.
        10. Optionally set the Notification time.
        11. Select Save.
        12. Repeat steps 3-11 for each Key Vault and Key.
        Remediate from Azure CLI
        Run the following command for each key to update its policy to be auto-rotated:
        az keyvault key rotation-policy update -n <keyName> --vault-name <vaultName>
        --value <path/to/policy.json>
        Note: It is easiest to supply the policy flags in a .json file. An example
        json file would be:
        {
        'lifetimeActions': [
        {
        'trigger': {
        'timeAfterCreate': '<timespanInISO8601Format>',
        'timeBeforeExpiry' : null
        },
        'action': {
        'type': 'Rotate'
        }
        },
        {
        'trigger': {
        'timeBeforeExpiry' : '<timespanInISO8601Format>'
        },
        'action': {
        'type': 'Notify'
        }
        }
        ],
        'attributes': {
        'expiryTime': '<timespanInISO8601Format>'
        }
        }
        Remediate from PowerShell
        Run the following command for each key to update its policy:
        Set-AzKeyVaultKeyRotationPolicy -VaultName test-kv -Name test-key -PolicyPath
        rotation_policy.json
        Note: It is easiest to supply the policy flags in a .json file. An example json file would be:
        <#
        rotation_policy.json
        {
        'lifetimeActions': [
        {
        'trigger': {
        'timeAfterCreate': 'P<timespanInISO8601Format>M',
        'timeBeforeExpiry': null
        },
        'action': {
        'type': 'Rotate'
        }
        },
        {
        'trigger': {
        'timeBeforeExpiry': 'P<timespanInISO8601Format>D'
        },
        'action': {
        'type': 'Notify'
        }
        }
        ],
        'attributes': {
        'expiryTime': 'P<timespanInISO8601Format>Y'
        }
        }
        #>"

  impact 0.5
  tag nist: ['AU-11', 'CM-12', 'SI-12', 'AC-1', 'AC-2', 'AC-2(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.1', '6.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation'
  ref 'https://docs.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview#update-the-key-version'
  ref 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disks-enable-customer-managed-keys-powershell#set-up-an-azure-key-vault-and-diskencryptionset-optionally-with-automatic-key-rotation'
  ref 'https://azure.microsoft.com/en-us/updates/public-preview-automatic-key-rotation-of-customermanaged-keys-for-encrypting-azure-managed-disks/'
  ref 'https://docs.microsoft.com/en-us/cli/azure/keyvault/key/rotation-policy?view=azure-cli-latest#az-keyvault-key-rotation-policy-update'
  ref 'https://docs.microsoft.com/en-us/powershell/module/az.keyvault/set-azkeyvaultkeyrotationpolicy?view=azps-8.1.0'
  ref 'https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/scalar-data-types/timespan'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-6-use-a-secure-key-management-process'

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

  vault_automatic_key_rotation_script = %(
      $keyVaults = Get-AzKeyVault
      if ($keyVaults -eq $null){
            Write-Output "No Key Vaults Found"
      }
      foreach ($vault in $keyVaults) {
            $vaultName = $vault.VaultName

            $keys = Get-AzKeyVaultKey -VaultName $vaultName

            foreach ($key in $keys) {
                  $keyName = $key.Name
                  $keyAction = (Get-AzKeyVaultKeyRotationPolicy -VaultName $vaultName -Name $keyName).LifetimeActions -join ", "
                  if ($keyAction -notmatch "Rotate") {
                        Write-Host "Key Vault: $vaultName, Key: $keyName"
                  }
            }
      }
  )

  pwsh_output = powershell(vault_automatic_key_rotation_script)

  describe 'Ensure the number of vaults/key pairs with LifetimeActions setting not set to "Rotate"' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following vaults/key pair combinations do not have the LifetimeActions setting set to 'Rotate': \n #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
