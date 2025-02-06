control 'azure-foundations-cis-5.4.3' do
    title 'Use Entra ID Client Authentication and Azure RBAC where possible'
    desc "Cosmos DB can use tokens or Entra ID for client authentication which in turn will use Azure RBAC for authorization. Using Entra ID is significantly more secure because Entra ID handles the credentials and allows for MFA and centralized management, and the Azure RBAC is better integrated with the rest of Azure."

    desc 'rationale',
        "Entra ID client authentication is considerably more secure than token-based authentication because the tokens must be persistent at the client. Entra ID does not require this."

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

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end