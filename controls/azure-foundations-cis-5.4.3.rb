control 'azure-foundations-cis-5.4.3' do
  title 'Use Entra ID Client Authentication and Azure RBAC where possible'
  desc 'Cosmos DB can use tokens or Entra ID for client authentication which in turn will use Azure RBAC for authorization. Using Entra ID is significantly more secure because Entra ID handles the credentials and allows for MFA and centralized management, and the Azure RBAC is better integrated with the rest of Azure.'

  desc 'rationale',
       'Entra ID client authentication is considerably more secure than token-based authentication because the tokens must be persistent at the client. Entra ID does not require this.'

  desc 'check',
       "%(Audit from PowerShell
            $cosmosdbname = '<your-cosmos-db-account-name>'
            $resourcegroup = '<your-resource-group-name>'
            az cosmosdb show --name $cosmosdbname --resource-group $resourcegroup | ConvertFrom-Json
            In the resulting output, disableLocalAuth should be true
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 5450f5bd-9c72-4390-a9c4-a7aba4edfdd2 - Name: 'Cosmos DB database accounts should have local authentication methods disabled')

    desc 'fix',
       'Map all the resources that currently have access to the Azure Cosmos DB account with keys or access tokens. Create an Entra ID identity for each of these resources:
            • For Azure resources, you can create a managed identity. You may choose between system-assigned and user-assigned managed identities.
            • For non-Azure resources, create an Entra ID identity. Grant each Entra ID identity the minimum permission it requires. When possible, we recommend you
              use one of the 2 built-in role definitions: Cosmos DB Built-in Data Reader or Cosmos DB Built-in Data Contributor. Validate that the new resource is functioning correctly. After new permissions are granted to identities, it may take a few hours until they propagate. When all resources are working correctly with the new identities, continue to the next step.
        Remediate from PowerShell
            $cosmosdbname = '<your-cosmos-db-account-name>'
            $resourcegroup = '<your-resource-group-name>'
            az cosmosdb show --name $cosmosdbname --resource-group $resourcegroup | ConvertFrom-Json az resource update --ids $cosmosdb.id --set properties.disableLocalAuth=true --latest-include-preview'"

  impact 0.5
  tag nist: ['AC-2(1)', 'AC-3']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['6.7'] }]

  ref 'https://learn.microsoft.com/en-us/azure/cosmos-db/role-based-access-control'

  all_cosmos_accounts = []

  rg_sa_list = input('resource_groups_and_storage_accounts')

  rg_sa_list.each do |pair|
    resource_group, = pair.split('.')

    cosmos_accounts_script = <<-EOH
      $ErrorActionPreference = "Stop"
      Get-AzCosmosDBAccount -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
    EOH

    cosmos_accounts_output_pwsh = powershell(cosmos_accounts_script)
    cosmos_accounts_output = cosmos_accounts_output_pwsh.stdout.strip
    raise Inspec::Error, "The powershell output returned the following error:  #{cosmos_accounts_output_pwsh.stderr}" if cosmos_accounts_output_pwsh.exit_status != 0

    cosmos_accounts = json(content: cosmos_accounts_output).params

    if cosmos_accounts.is_a?(Hash)
      cosmos_accounts = cosmos_accounts.empty? ? [] : [cosmos_accounts]
    elsif !cosmos_accounts.is_a?(Array)
      cosmos_accounts = [cosmos_accounts]
    end

    all_cosmos_accounts.concat(cosmos_accounts)

    if cosmos_accounts.empty?
      describe "Cosmos DB Accounts in Resource Group #{resource_group}" do
        skip "N/A - No Cosmos DB accounts found in Resource Group #{resource_group}"
      end
    else
      cosmos_accounts.each do |account|
        cosmosdb_account = account['Name']

        cosmosdb_show_script = <<-EOH
          az cosmosdb show --name "#{cosmosdb_account}" --resource-group "#{resource_group}"
        EOH

        cosmosdb_output = powershell(cosmosdb_show_script).stdout.strip
        cosmosdb_json = json(content: cosmosdb_output).params

        describe "Cosmos DB account '#{cosmosdb_account}' in Resource Group '#{resource_group}'" do
          it "should have disableLocalAuth set to 'True'" do
            expect(cosmosdb_json['disableLocalAuth']).to cmp true
          end
        end
      end
    end
  end

  impact 0.0 if all_cosmos_accounts.empty?
end
