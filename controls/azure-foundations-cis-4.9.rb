control 'azure-foundations-cis-4.9' do
  title 'Ensure Private Endpoints are used to access Storage Accounts'
  desc "Use private endpoints for your Azure Storage accounts to allow clients and services to
        securely access data located over a network via an encrypted Private Link. To do this,
        the private endpoint uses an IP address from the VNet for each service. Network traffic
        between disparate services securely traverses encrypted over the VNet. This VNet can
        also link addressing space, extending your network and accessing resources on it.
        Similarly, it can be a tunnel through public networks to connect remote infrastructures
        together. This creates further security through segmenting network traffic and
        preventing outside sources from accessing it."

  desc 'rationale',
       "Securing traffic between services through encryption protects the data from easy
        interception and reading."

  desc 'impact',
       "A Private Endpoint costs approximately US$7.30 per month. If an Azure Virtual Network
        is not implemented correctly, this may result in the loss of critical network traffic."

  desc 'check',
       "Audit from Azure Portal
        1. Open the Storage Accounts blade.
        2. For each listed Storage Account, perform the following check:
        3. Under the Security + networking heading, click on Networking.
        4. Click on the Private endpoint connections tab at the top of the networking
        window.
        5. Ensure that for each VNet that the Storage Account must be accessed from, a
        unique Private Endpoint is deployed and the Connection state for each Private
        Endpoint is Approved.
        Repeat the procedure for each Storage Account.
        Audit from PowerShell
        $storageAccount = Get-AzStorageAccount -ResourceGroup '<ResourceGroupName>' -
        Name '<storageaccountname>'
        Get-AzPrivateEndpoint -ResourceGroup '<ResourceGroupName>'|Where-Object
        {$_.PrivateLinkServiceConnectionsText -match $storageAccount.id}
        If the results of the second command returns information, the Storage Account is using
        a Private Endpoint and complies with this Benchmark, otherwise if the results of the
        second command are empty, the Storage Account generates a finding.
        Audit from Azure CLI
        az storage account show --name '<storage account name>' --query
        'privateEndpointConnections[0].id'
        If the above command returns data, the Storage Account complies with this Benchmark,
        otherwise if the results are empty, the Storage Account generates a finding.
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 6edd7eda-6dd8-40f7-810d-67160c639cd9 - Name: 'Storage accounts
        should use private link'"

  desc 'fix',
       "From Azure Portal
        1. Open the Storage Accounts blade
        2. For each listed Storage Account, perform the following:
        3. Under the Security + networking heading, click on Networking
        4. Click on the Private Endpoint Connections tab at the top of the networking
        window
        5. Click the +Private endpoint button
        6. In the 1 - Basics tab/step:
        o
        Enter a name that will be easily recognizable as associated with the
        Storage Account (Note: The 'Network Interface Name' will be
        automatically completed, but you can customize it if needed.)
        o Ensure that the Region matches the region of the Storage Account
        o Click Next
        7. In the 2 - Resource tab/step:
        o Select the target sub-resource based on what type of storage resource
        is being made available
        o Click Next
        8. In the 3 - Virtual Network tab/step:
        o Select the Virtual network that your Storage Account will be connecting
        to
        o Select the Subnet that your Storage Account will be connecting to
        o (Optional) Select other network settings as appropriate for your
        environment
        o Click Next
        9. In the 4 - DNS tab/step:
        o (Optional) Select other DNS settings as appropriate for your environment
        o Click Next
        10. In the 5 - Tags tab/step:
        o (Optional) Set any tags that are relevant to your organization
        o Click Next
        11. In the 6 - Review + create tab/step:
        o A validation attempt will be made and after a few moments it should
        indicate Validation Passed - if it does not pass, double-check your
        settings before beginning more in depth troubleshooting.
        o If validation has passed, click Create then wait for a few minutes for the
        scripted deployment to complete.
        Repeat the above procedure for each Private Endpoint required within every Storage
        Account.
        From PowerShell
        $storageAccount = Get-AzStorageAccount -ResourceGroupName
        '<ResourceGroupName>' -Name '<storageaccountname>'
        $privateEndpointConnection = @{
        Name = 'connectionName'
        PrivateLinkServiceId = $storageAccount.Id
        GroupID =
        'blob|blob_secondary|file|file_secondary|table|table_secondary|queue|queue_se
        condary|web|web_secondary|dfs|dfs_secondary'
        }
        $privateLinkServiceConnection = New-AzPrivateLinkServiceConnection
        @privateEndpointConnection
        $virtualNetDetails = Get-AzVirtualNetwork -ResourceGroupName
        '<ResourceGroupName>' -Name '<name>'
        $privateEndpoint = @{
        ResourceGroupName = '<ResourceGroupName>'
        Name = '<PrivateEndpointName>'
        Location = '<location>'
        Subnet = $virtualNetDetails.Subnets[0]
        PrivateLinkServiceConnection =
        $privateLinkServiceConnection
        }
        New-AzPrivateEndpoint @privateEndpoint
        From Azure CLI
        az network private-endpoint create --resource-group <ResourceGroupName --
        location <location> --name <private endpoint name> --vnet-name <VNET Name> --
        subnet <subnet name> --private-connection-resource-id <storage account ID> --
        connection-name <private link service connection name> --group-id
        <blob|blob_secondary|file|file_secondary|table|table_secondary|queue|queue_se
        condary|web|web_secondary|dfs|dfs_secondary>"

  impact 0.5
  tag nist: ['PL-8', 'PM-7', 'SA-8', 'CM-7', 'CP-6', 'CP-7', 'SC-7']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['12.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/storage/common/storage-private-endpoints'
  ref 'https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview'
  ref 'https://docs.microsoft.com/en-us/azure/private-link/create-private-endpoint-portal'
  ref 'https://docs.microsoft.com/en-us/azure/private-link/create-private-endpoint-cli?tabs=dynamic-ip'
  ref 'https://docs.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip'
  ref 'https://docs.microsoft.com/en-us/azure/private-link/tutorial-private-endpoint-storage-portal'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls'

  storage_script = 'Get-AzStorageAccount | ConvertTo-Json -Depth 10'
  storage_output = powershell(storage_script).stdout.strip
  all_storage = json(content: storage_output).params

  only_if('N/A - No Storage Accounts found', impact: 0) do
    case all_storage
    when Array
      !all_storage.empty?
    when Hash
      !all_storage.empty?
    else
      false
    end
  end

  rg_sa_list = input('resource_groups_and_storage_accounts')

  rg_sa_list.each do |pair|
    resource_group, storage_account = pair.split('.')

    describe "Private Endpoint Check for Storage Account '#{storage_account}' in Resource Group '#{resource_group}'" do
      script = <<-EOH
                $storageAccount = Get-AzStorageAccount -ResourceGroupName "#{resource_group}" -Name "#{storage_account}"
                Get-AzPrivateEndpoint -ResourceGroup "#{resource_group}" | Where-Object { $_.PrivateLinkServiceConnectionsText -match $storageAccount.id }
      EOH

      describe powershell(script) do
        its('stdout.strip') { should_not be_empty }
      end
    end
  end
end
