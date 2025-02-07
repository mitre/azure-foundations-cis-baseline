control 'azure-foundations-cis-5.2.5' do
    title "Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled"
    desc "Disable access from Azure services to PostgreSQL flexible server."

    desc 'rationale',
        "If access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually not a desired configuration. Instead, set up firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks."

    desc 'check',
       "%(Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Networking.
            4. Under Firewall rules, ensure Allow public access from any Azure service within Azure to this server is not checked.
        Audit from Azure CLI 
            Ensure the below command does not return a rule with a name beginning AllowAllAzureServicesAndResourcesWithinAzureIps or with 'startIpAddress': '0.0.0.0' or 'endIpAddress': '0.0.0.0': 
                az postgres flexible-server firewall-rule list --resource-group <resourceGroup> --name <serverName>
        Audit from PowerShell 
            Ensure the below command does not return a rule with a name beginning AllowAllAzureServicesAndResourcesWithinAzureIps: 
                Get-AzPostgreSqlFlexibleServerFirewallRule -ResourceGroupName <resourceGroup> -ServerName <serverName>
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 5e1de0e3-42cb-4ebc-a86d-61d0c619ca48 - Name: 'Public network access should be disabled for PostgreSQL flexible servers')"

    desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Networking.
            4. Under Firewall rules, uncheck Allow public access from any Azure service within Azure to this server.
            5. Click Save.
        Remediate from Azure CLI 
            Using the firewall rule name from the Audit from Azure CLI steps, use the below command to delete the AllowAllAzureServicesAndResourcesWithinAzureIps rule for PostgreSQL flexible server: 
                az postgres flexible-server firewall-rule delete --resource-group <resourceGroup> --name <serverName> --rule-name <ruleName>
            Type y and press enter to confirm. 
        Remediate from PowerShell 
            Using the firewall rule name from the Audit from PowerShell steps, use the below command to delete the AllowAllAzureServicesAndResourcesWithinAzureIps rule for PostgreSQL flexible server: 
                Remove-AzPostgreSqlFlexibleServerFirewallRule -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name <ruleName>"

    impact 0.5
    tag nist: ['CA-9', 'SC-7', 'SC-7(5)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['4.4'] }]
   
    ref 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-firewall-rules'
    ref 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-manage-firewall-cli'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-1-establish-network-segmentation-boundaries'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-6-deploy-web-application-firewall'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end