control 'azure-foundations-cis-3.3.7' do
  title 'Ensure that Private Endpoints are Used for Azure Key VaultEnsure that Private Endpoints are Used for Azure Key Vault'
  desc "Ensure that all Keys in Role Based Access Control (RBAC) Azure Key Vaults have an
        expiration date set."

  desc 'rationale',
       "Private endpoints will keep network requests to Azure Key Vault limited to the endpoints
        attached to the resources that are whitelisted to communicate with each other.
        Assigning the Key Vault to a network without an endpoint will allow other resources on
        that network to view all traffic from the Key Vault to its destination. In spite of the
        complexity in configuration, this is recommended for high security secrets."

  desc 'impact',
       "Incorrect or poorly-timed changing of network configuration could result in service
        interruption. There are also additional costs tiers for running a private endpoint per
        petabyte or more of networking traffic."

  desc 'check',
       "Audit from Azure Portal
        1. From Azure Home open the Portal Menu in the top left.
        2. Select Key Vaults.
        3. Select a Key Vault to audit.
        4. Select Networking in the left column.
        5. Select Private endpoint connections from the top row.
        6. View if there is an endpoint attached.
        Audit from Azure CLI
        Run the following command within a subscription for each Key Vault you wish to audit.
        az keyvault show --name <keyVaultName>
        Ensure that privateEndpointConnections is not null.
        Audit from PowerShell
        Run the following command within a subscription for each Key Vault you wish to audit.
        Get-AzPrivateEndpointConnection -PrivateLinkResourceId
        '/subscriptions/<subscriptionNumber>/resourceGroups/<resourceGroup>/providers
        /Microsoft.KeyVault/vaults/<keyVaultName>/'
        Ensure that the response contains details of a private endpoint.
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: a6abeaec-4d90-4a02-805f-6b26c4d3fbe9 - Name: 'Azure Key Vaults
        should use private link"

  desc 'fix',
       "Please see the additional information about the requirements needed before
        starting this remediation procedure.
        Remediate from Azure Portal
        1. From Azure Home open the Portal Menu in the top left.
        2. Select Key Vaults.
        3. Select a Key Vault to audit.
        4. Select Networking in the left column.
        5. Select Private endpoint connections from the top row.
        6. Select + Create.
        7. Select the subscription the Key Vault is within, and other desired configuration.
        8. Select Next.
        9. For resource type select Microsoft.KeyVault/vaults.
        10. Select the Key Vault to associate the Private Endpoint with.
        11. Select Next.
        12. In the Virtual Networking field, select the network to assign the Endpoint.
        13. Select other configuration options as desired, including an existing or new
        application security group.
        14. Select Next.
        15. Select the private DNS the Private Endpoints will use.
        16. Select Next.
        17. Optionally add Tags.
        18. Select Next : Review + Create.
        19. Review the information and select Create. Follow the Audit Procedure to
        determine if it has successfully applied.
        20. Repeat steps 3-19 for each Key Vault.
        Remediate from Azure CLI
        1. To create an endpoint, run the following command:
        az network private-endpoint create --resource-group <resourceGroup --vnet-
        name <vnetName> --subnet <subnetName> --name <PrivateEndpointName> --
        private-connection-resource-id '/subscriptions/<AZURE SUBSCRIPTION
        ID>/resourceGroups/<resourceGroup>/providers/Microsoft.KeyVault/vaults/<keyVa
        ultName>' --group-ids vault --connection-name <privateLinkConnectionName> --
        location <azureRegion> --manual-request
        2. To manually approve the endpoint request, run the following command:
        az keyvault private-endpoint-connection approve --resource-group
        <resourceGroup> --vault-name <keyVaultName> –name <privateLinkName>
        3. Determine the Private Endpoint's IP address to connect the Key Vault to the
        Private DNS you have previously created:
        4. Look for the property networkInterfaces then id; the value must be placed in the
        variable <privateEndpointNIC> within step 7.
        az network private-endpoint show -g <resourceGroupName> -n
        <privateEndpointName>
        5. Look for the property networkInterfaces then id; the value must be placed on
        <privateEndpointNIC> in step 7.
        az network nic show --ids <privateEndpointName>
        6. Create a Private DNS record within the DNS Zone you created for the Private
        Endpoint:
        az network private-dns record-set a add-record -g <resourcecGroupName> -z
        'privatelink.vaultcore.azure.net' -n <keyVaultName> -a <privateEndpointNIC>
        7. nslookup the private endpoint to determine if the DNS record is correct:
        nslookup <keyVaultName>.vault.azure.net
        nslookup <keyVaultName>.privatelink.vaultcore.azure.n"

  impact 0.5
  tag nist: ['PL-8', 'PM-7', 'SA-8', 'CM-7', 'CP-6', 'CP-7', 'SC-7']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['12.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview'
  ref 'https://docs.microsoft.com/en-us/azure/storage/common/storage-private-endpoints'
  ref 'https://azure.microsoft.com/en-us/pricing/details/private-link/'
  ref 'https://docs.microsoft.com/en-us/azure/key-vault/general/private-link-service?tabs=portal'
  ref 'https://docs.microsoft.com/en-us/azure/virtual-network/quick-create-portal'
  ref 'https://docs.microsoft.com/en-us/azure/private-link/tutorial-private-endpoint-storage-portal'
  ref 'https://docs.microsoft.com/en-us/azure/bastion/bastion-overview'
  ref 'https://docs.microsoft.com/azure/dns/private-dns-getstarted-cli#create-an-additional-dns-record'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-8-ensure-security-of-key-and-certificate-repository'

  subscription_id = input('subscription_id')
  check_private_endpoints_non_null_script = %(
      $keyVaults = Get-AzKeyVault
      if ($keyVaults -eq $null){
            Write-Output "No Key Vaults Found"
      }
      foreach ($vault in $keyVaults) {
            $vaultName = $vault.VaultName
            $vaultResourceGroup = $vault.ResourceGroupName

            # Get the Key Vault details
            $privateEndpointDetails = Get-AzPrivateEndpointConnection -PrivateLinkResourceId "/subscriptions/#{subscription_id}/resourceGroups/$vaultResourceGroup/providers/Microsoft.KeyVault/vaults/$vaultName/"

            if ($privateEndpointDetails -eq $null) {
                  Write-Host "$vaultName"
            }
      }
  )
  pwsh_output = powershell(check_private_endpoints_non_null_script)
  describe 'Ensure the number of vaults with PrivateEndpointConnections set to null' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following vaults have PrivateEndpointConnections set to null: #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
