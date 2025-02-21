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

  describe 'benchmark' do
    skip 'The check for this control needs to be done manually'
  end
end
