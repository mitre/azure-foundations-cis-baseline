control 'azure-foundations-cis-5.4.1' do
  title "Ensure That 'Firewalls & Networks' Is Limited to Use Selected Networks Instead of All Networks"
  desc 'Limiting your Cosmos DB to only communicate on whitelisted networks lowers its attack footprint.'

  desc 'rationale',
       'Selecting certain networks for your Cosmos DB to communicate restricts the number of networks including the internet that can interact with what is stored within the database.'

  desc 'impact',
       'WARNING: Failure to whitelist the correct networks will result in a connection loss.
        WARNING: Changes to Cosmos DB firewalls may take up to 15 minutes to apply. Ensure that sufficient time is planned for remediation or changes to avoid disruption.'

  desc 'check',
       "Audit from Azure Portal
            1. Open the portal menu.
            2. Select the Azure Cosmos DB blade
            3. Select a Cosmos DB to audit.
            4. Select Networking.
            5. Under Public network access, ensure Selected networks is selected.
            6. Under Virtual networks, ensure appropriate virtual networks are configured.
        Audit from Azure CLI
            Retrieve a list of all CosmosDB database names:
                az cosmosdb list
            For each database listed, run the following command:
                az cosmosdb show <database id>
            For each database, ensure that isVirtualNetworkFilterEnabled is set to true
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 862e97cf-49fc-4a5c-9de4-40d4e2e7c8eb - Name: 'Azure Cosmos DB accounts should have firewall rules'"

  desc 'fix',
       "Remediate from Azure Portal
            1. Open the portal menu.
            2. Select the Azure Cosmos DB blade.
            3. Select a Cosmos DB account to audit.
            4. Select Networking.
            5. Under Public network access, select Selected networks.
            6. Under Virtual networks, select + Add existing virtual network or + Add a new virtual network.
            7. For existing networks, select subscription, virtual network, subnet and click Add. For new networks, provide a name, update the default values if required, and click Create.
            8. Click Save."

  impact 0.5
  tag nist: ['CA-9', 'SC-7', 'SC-7(5)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.4'] }]

  ref 'https://docs.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints'
  ref 'https://docs.microsoft.com/en-us/azure/cosmos-db/how-to-configure-vnet-service-endpoint'
  ref 'https://docs.microsoft.com/en-us/cli/azure/cosmosdb?view=azure-cli-latest#az-cosmosdb-show'
  ref 'https://docs.microsoft.com/en-us/cli/azure/cosmosdb/database?view=azure-cli-latest#az-cosmosdb-database-list'
  ref 'https://docs.microsoft.com/en-us/powershell/module/az.cosmosdb/?view=azps-8.1.0'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls'

  all_cosmosdb_accounts = []

  storage_script = 'Get-AzStorageAccount | ConvertTo-Json'
  storage_output = powershell(storage_script).stdout.strip
  all_storage = json(content: storage_output).params
  exclusions_list = input('excluded_resource_groups_and_storage_accounts')

  if all_storage.is_a?(Array)
    rg_sa_list = all_storage.map { |account| account['ResourceGroupName'] + '.' + account['StorageAccountName'] }
  elsif all_storage.is_a?(Hash)
    rg_sa_list = [ all_storage['ResourceGroupName'] + '.' + all_storage['StorageAccountName'] ]
  else
    rg_sa_list = []
  end

  rg_sa_list.reject! { |sa| exclusions_list.include?(sa) }

  rg_sa_list.each do |pair|
    resource_group, = pair.split('.')

    script = <<-EOH
      $ErrorActionPreference = "Stop"
      Get-AzCosmosDBAccount -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
    EOH

    output_pwsh = powershell(script)
    output = output_pwsh.stdout.strip
    raise Inspec::Error, "The powershell output returned the following error:  #{output_pwsh.stderr}" if output_pwsh.exit_status != 0

    accounts = json(content: output).params

    if accounts.is_a?(Hash)
      accounts = accounts.empty? ? [] : [accounts]
    elsif !accounts.is_a?(Array)
      accounts = [accounts]
    end

    all_cosmosdb_accounts.concat(accounts)

    if accounts.empty?
      describe "Cosmos DB Accounts in Resource Group #{resource_group}" do
        skip "N/A - No Cosmos DB accounts found in Resource Group #{resource_group}"
      end
    else
      accounts.each do |account|
        account_name = account['Name']
        describe "Cosmos DB Account '#{account_name}' in Resource Group '#{resource_group}' Virtual Network Filter configuration" do
          it "should have IsVirtualNetworkFilterEnabled set to 'True'" do
            expect(account['IsVirtualNetworkFilterEnabled']).to cmp true
          end
        end
      end
    end
  end

  impact 0.0 if all_cosmosdb_accounts.empty?
end
