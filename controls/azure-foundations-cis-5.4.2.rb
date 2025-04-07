control 'azure-foundations-cis-5.4.2' do
  title 'Ensure That Private Endpoints Are Used Where Possible'
  desc 'Private endpoints limit network traffic to approved sources.'

  desc 'rationale',
       'For sensitive data, private endpoints allow granular control of which services can communicate with Cosmos DB and ensure that this network traffic is private. You set this up on a case by case basis for each service you wish to be connected.'

  desc 'impact',
       'Only whitelisted services will have access to communicate with the Cosmos DB.'

  desc 'check',
       "Audit from Azure Portal
            1. Open the portal menu.
            2. Select the Azure Cosmos DB blade.
            3. Select the Azure Cosmos DB account.
            4. Select Networking.
            5. Ensure Public network access is set to Selected networks.
            6. Ensure the listed networks are set appropriately.
            7. Select Private access.
            8. Ensure a private endpoint exists and Connection state is Approved.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 58440f8a-10c5-4151-bdce-dfbaad4a20b7 - Name: 'CosmosDB accounts should use private link'"

  desc 'fix',
       "Remediate from Azure Portal
            1. Open the portal menu.
            2. Select the Azure Cosmos DB blade.
            3. Select the Azure Cosmos DB account.
            4. Select Networking.
            5. Select Private access.
            6. Click + Private Endpoint.
            7. Provide a Name.
            8. Click Next.
            9. From the Resource type drop down, select Microsoft.AzureCosmosDB/databaseAccounts.
            10. From the Resource drop down, select the Cosmos DB account.
            11. Click Next.
            12. Provide appropriate Virtual Network details.
            13. Click Next.
            14. Provide appropriate DNS details.
            15. Click Next.
            16. Optionally provide Tags.
            17. Click Next : Review + create.
            18. Click Create."

  impact 0.5
  tag nist: ['PL-8', 'PM-7', 'SA-8', 'CM-7', 'CP-6', 'CP-7', 'SC-7']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['12.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints'
  ref 'https://docs.microsoft.com/en-us/azure/private-link/tutorial-private-endpoint-cosmosdb-portal'
  ref 'https://docs.microsoft.com/en-us/cli/azure/cosmosdb/private-endpoint-connection?view=azure-cli-latest'
  ref 'https://docs.microsoft.com/en-us/cli/azure/network/private-endpoint?view=azure-cli-latest#az-network-private-endpoint-create'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls'

  all_cosmosdb_accounts = []

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

    cosmosdb_script = <<-EOH
      $ErrorActionPreference = "Stop"
			Get-AzCosmosDBAccount -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
    EOH

    cosmosdb_output_pwsh = powershell(cosmosdb_script)
    cosmosdb_output = cosmosdb_output_pwsh.stdout.strip
    raise Inspec::Error, "The powershell output returned the following error:  #{cosmosdb_output_pwsh.stderr}" if cosmosdb_output_pwsh.exit_status != 0

    accounts = json(content: cosmosdb_output).params

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
