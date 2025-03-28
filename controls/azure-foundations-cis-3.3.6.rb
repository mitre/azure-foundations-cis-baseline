control 'azure-foundations-cis-3.3.6' do
  title 'Enable Role Based Access Control for Azure Key Vault'
  desc "The recommended way to access Key Vaults is to use the Azure Role-Based Access
        Control (RBAC) permissions model.
        Azure RBAC is an authorization system built on Azure Resource Manager that provides
        fine-grained access management of Azure resources. It allows users to manage Key,
        Secret, and Certificate permissions. It provides one place to manage all permissions
        across all key vaults."

  desc 'rationale',
       "The new RBAC permissions model for Key Vaults enables a much finer grained access
        control for key vault secrets, keys, certificates, etc., than the vault access policy. This in
        turn will permit the use of privileged identity management over these roles, thus
        securing the key vaults with JIT Access management."

  desc 'impact',
       "Implementation needs to be properly designed from the ground up, as this is a
        fundamental change to the way key vaults are accessed/managed. Changing
        permissions to key vaults will result in loss of service as permissions are re-applied. For
        the least amount of downtime, map your current groups and users to their
        corresponding permission needs."

  desc 'check',
       "Audit from Azure Portal
        1. From Azure Home open the Portal Menu in the top left corner
        2. Select Key Vaults
        3. Select a Key Vault to audit
        4. Select Access configuration
        5. Ensure the Permission Model radio button is set to Azure role-based access
        control
        Audit from Azure CLI
        Run the following command for each Key Vault in each Resource Group:
        az keyvault show --resource-group <resource_group> --name <vault_name>
        Ensure the enableRbacAuthorization setting is set to true within the output of the
        above command.
        Audit from PowerShell
        Run the following PowerShell command:
        Get-AzKeyVault -Vaultname <vault_name> -ResourceGroupName <resource_group>
        Ensure the Enabled For RBAC Authorization setting is set to True
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 12d4fa5e-1f9f-4c21-97a9-b99b3c6611b5 - Name: 'Azure Key Vault
        should use RBAC permission model'"

  desc 'fix',
       "Remediate from Azure Portal
        Key Vaults can be configured to use Azure role-based access control on creation.
        For existing Key Vaults:
        1. From Azure Home open the Portal Menu in the top left corner
        2. Select Key Vaults
        3. Select a Key Vault to audit
        4. Select Access configuration
        5. Set the Permission model radio button to Azure role-based access control,
        taking note of the warning message
        6. Click Save
        7. Select Access Control (IAM)
        8. Select the Role Assignments tab
        9. Reapply permissions as needed to groups or users
        Remediate from Azure CLI
        To enable RBAC Authorization for each Key Vault, run the following Azure CLI
        command:
        az keyvault update --resource-group <resource_group> --name <vault_name> --
        enable-rbac-authorization true
        Remediate from PowerShell
        To enable RBAC authorization on each Key Vault, run the following PowerShell
        command:
        Update-AzKeyVault -ResourceGroupName <resource_group> -VaultName <vault_name>
        -EnableRbacAuthorization $True"

  impact 0.5
  tag nist: ['AC-3', 'AC-5', 'AC-6', 'MP-2', 'AC-2', 'AC-5', 'AC-6', 'AC-6(1)', 'AC-6(7)', 'AU-9(4)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.3', '6.8'] }]

  ref 'https://docs.microsoft.com/en-gb/azure/key-vault/general/rbac-migration#vault-access-policy-to-azure-rbac-migration-steps'
  ref 'https://docs.microsoft.com/en-gb/azure/role-based-access-control/role-assignments-portal?tabs=current'
  ref 'https://docs.microsoft.com/en-gb/azure/role-based-access-control/overview'
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

  check_rbac_vault_script = %(
      $ErrorActionPreference = "Stop"
      $keyVaults = Get-AzKeyVault
      if ($keyVaults -eq $null){
            Write-Output "No Key Vaults Found"
      }
      foreach ($vault in $keyVaults) {
            $vaultName = $vault.VaultName
            $vaultResourceGroup = $vault.ResourceGroupName

            # Get the Key Vault details
            $vaultDetails = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $vaultResourceGroup

            if ($vaultDetails.EnableRbacAuthorization -eq $false) {
                  Write-Host "$vaultName"
            }
      }
  )

  pwsh_output = powershell(check_rbac_vault_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe "Ensure the number of vaults with EnableRbacAuthorization set to 'False" do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following vaults do not have EnableRbacAuthorization set to 'True': #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
