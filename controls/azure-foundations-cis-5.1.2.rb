control 'azure-foundations-cis-5.1.2' do
  title 'Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)'
  desc 'Ensure that no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP).'

  desc 'rationale',
       "Azure SQL Server includes a firewall to block access to unauthorized connections. More granular IP addresses can be defined by referencing the range of addresses available from specific datacenters.
        By default, for a SQL server, a Firewall exists with StartIp of 0.0.0.0 and EndIP of 0.0.0.0 allowing access to all the Azure services.
        Additionally, a custom rule can be set up with StartIp of 0.0.0.0 and EndIP of 255.255.255.255 allowing access from ANY IP over the Internet.
        In order to reduce the potential attack surface for a SQL server, firewall rules should be defined with more granular IP addresses by referencing the range of addresses available from specific datacenters.
        If Allow Azure services and resources to access this server is 'Checked', this will allow resources outside of the subscription/tenant/organization boundary, within any region of Azure, to effectively bypass the defined SQL Server Network ACL on public endpoint. A malicious attacker can successfully launch a SQL server password bruteforce attack by creating a virtual machine in any Azure subscription/region, from outside of the subscription boundary where the SQL Server is residing."

  desc 'impact',
       'Disabling Allow Azure services and resources to access this server will break all connections to SQL server and Hosted Databases unless custom IP specific rules are added in Firewall Policy.'

  desc 'check',
       "Audit from Azure Portal
            1. Go to SQL servers
            2. For each SQL server
            3. Under Security, click Networking
            4. Ensure that Allow Azure services and resources to access this server is unchecked
            5. Ensure that no firewall rule exists with
                • Start IP of 0.0.0.0
                • or other combinations which allows access to wider public IP ranges
        Audit from Azure CLI
            List all SQL servers
                az sql server list
            For each SQL server run the following command
                az sql server firewall-rule list --resource-group <resource group name> --server <sql server name>
            Ensure the output does not contain any firewall allow rules with a source of 0.0.0.0, or any rules named AllowAllWindowsAzureIps
        Audit from PowerShell
            Get the list of all SQL Servers
                Get-AzSqlServer
            For each Server
                Get-AzSqlServerFirewallRule -ResourceGroupName <resource group name> -ServerName <server name>
            Ensure that StartIpAddress is not set to 0.0.0.0, /0 or other combinations which allows access to wider public IP ranges including Windows Azure IP ranges. Also ensure that FirewallRuleName doesn't contain AllowAllWindowsAzureIps which is the rule created when the Allow Azure services and resources to access this server setting is enabled for that SQL Server.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 1b8ca024-1d5c-4dec-8995-b1a932b41780 - Name: 'Public network access on Azure SQL Database should be disabled"

  desc 'fix',
       'Remediate from Azure Portal
            1. Go to SQL servers
            2. For each SQL server
            3. Under Security, click Networking
            4. Uncheck Allow Azure services and resources to access this server
            5. Set firewall rules to limit access to only authorized connections
            6. Click Save
        Remediate from Azure CLI
            Disable default firewall rule Allow access to Azure services:
                az sql server firewall-rule delete --resource-group <resource group> --server <sql server name> --name "AllowAllWindowsAzureIps"
            Remove a custom firewall rule:
                az sql server firewall-rule delete --resource-group <resource group> --server <sql server name> --name <firewall rule name>
            Create a firewall rule:
                az sql server firewall-rule create --resource-group <resource group> --server <sql server name> --name <firewall rule name> --start-ip-address "<IP Address other than 0.0.0.0>" --end-ip-address "<IP Address other than 0.0.0.0 or 255.255.255.255>"
            Update a firewall rule:
                az sql server firewall-rule update --resource-group <resource group> --server <sql server name> --name <firewall rule name> --start-ip-address "<IP Address other than 0.0.0.0>" --end-ip-address "<IP Address other than 0.0.0.0 or 255.255.255.255>"
        Remediate from PowerShell
            Disable Default Firewall Rule Allow access to Azure services:
                Remove-AzSqlServerFirewallRule -FirewallRuleName "AllowAllWindowsAzureIps" -ResourceGroupName <resource group name> -ServerName <server name>
            Remove a custom Firewall rule:
                Remove-AzSqlServerFirewallRule -FirewallRuleName "<firewall rule name>" -ResourceGroupName <resource group name> -ServerName <server name>
            Set the appropriate firewall rules:
                Set-AzSqlServerFirewallRule -ResourceGroupName <resource group name> -ServerName <server name> -FirewallRuleName "<firewall rule name>" -StartIpAddress "<IP Address other than 0.0.0.0>" -EndIpAddress "<IP Address other than 0.0.0.0 or 255.255.255.255>"'

  impact 0.5
  tag nist: ['AC-3', 'AC-5', 'AC-6', 'MP-2']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.3'] }]

  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-windows-firewall-for-database-engine-access?view=sql-server-2017'
  ref 'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/get-azurermsqlserverfirewallrule?view=azurermps-5.2.0'
  ref 'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/set-azurermsqlserverfirewallrule?view=azurermps-5.2.0'
  ref 'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/remove-azurermsqlserverfirewallrule?view=azurermps-5.2.0'
  ref 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-firewall-configure'
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-set-database-firewall-rule-azure-sql-database?view=azuresqldb-current'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls'
  ref 'https://learn.microsoft.com/en-us/azure/azure-sql/database/network-access-controls-overview?view=azuresql#allow-azure-services'

  rg_sa_list = input('resource_groups_and_storage_accounts')

  rg_sa_list.each do |pair|
    resource_group, = pair.split('.')

    # Retrieve all SQL Servers in the resource group using PowerShell.
    sql_servers_script = <<-EOH
      Get-AzSqlServer -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
    EOH

    sql_servers_output = powershell(sql_servers_script).stdout.strip
    sql_servers = json(content: sql_servers_output).params
    sql_servers = [sql_servers] unless sql_servers.is_a?(Array)

    sql_servers.each do |server|
      resource_group_server = server['ResourceGroupName']
      server_name = server['ServerName']

      describe "Firewall rules for SQL Server '#{server_name}' in Resource Group '#{resource_group_server}'" do
        firewall_rules_script = <<-EOH
          Get-AzSqlServerFirewallRule -ResourceGroupName "#{resource_group_server}" -ServerName "#{server_name}" | ConvertTo-Json -Depth 10
        EOH

        firewall_rules_output = powershell(firewall_rules_script).stdout.strip
        firewall_rules = json(content: firewall_rules_output).params
        firewall_rules = [firewall_rules] unless firewall_rules.is_a?(Array)

        firewall_rules.each do |rule|
          describe "Firewall Rule '#{rule['FirewallRuleName']}' on SQL Server '#{server_name}'" do
            it 'should not allow overly permissive access via StartIpAddress' do
              start_ip = rule['StartIpAddress']
              expect(start_ip).not_to match(%r{^0\.0\.0\.0(/0)?$})
            end

            it "should not be named 'AllowAllWindowsAzureIps'" do
              rule_name = rule['FirewallRuleName']
              expect(rule_name).not_to match(/AllowAllWindowsAzureIps/i)
            end
          end
        end
      end
    end
  end
end
