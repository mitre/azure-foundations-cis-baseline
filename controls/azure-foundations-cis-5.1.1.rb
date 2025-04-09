control 'azure-foundations-cis-5.1.1' do
  title "Ensure that 'Auditing' is set to 'On'"
  desc 'Enable auditing on SQL Servers.'

  desc 'rationale',
       "The Azure platform allows a SQL server to be created as a service. Enabling auditing at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing policy applied on the SQL database does not override auditing policy and settings applied on the particular SQL server where the database is hosted.
        Auditing tracks database events and writes them to an audit log in the Azure storage account. It also helps to maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations."

  desc 'check',
       "Audit from Azure Portal
            1. Go to SQL servers
            2. For each server instance
            3. Under Security, click Auditing
            4. Ensure that Enable Azure SQL Auditing is set to On
        Audit from PowerShell
            Get the list of all SQL Servers
                Get-AzSqlServer
        For each Server
            Get-AzSqlServerAudit -ResourceGroupName <ResourceGroupName> -ServerName <SQLServerName>
        Ensure that BlobStorageTargetState, EventHubTargetState, or LogAnalyticsTargetState is set to Enabled.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: a6fb4358-5bf4-4ad7-ba82-2cd2f41ce5e9 - Name: 'Auditing on SQL server should be enabled'"

  desc 'fix',
       'Remediate from Azure Portal
            1. Go to SQL servers
            2. Select the SQL server instance
            3. Under Security, click Auditing
            4. Click the toggle next to Enable Azure SQL Auditing
            5. Select an Audit log destination
            6. Click Save
        Remediate from PowerShell
            Get the list of all SQL Servers
                Get-AzSqlServer
            For each Server, enable auditing and set the retention for at least 90 days.
                Log Analytics Example
                    Set-AzSqlServerAudit -ResourceGroupName <resource group name> -ServerName <SQL Server name> -RetentionInDays <Number of Days to retain the audit logs, should be 90days minimum> -LogAnalyticsTargetState Enabled -WorkspaceResourceId "/subscriptions/<subscription ID>/resourceGroups/insights-integration/providers/Microsoft.OperationalInsights/workspaces/<workspace name>
                Event Hub Example
                    Set-AzSqlServerAudit -ResourceGroupName "<resource group name>" -ServerName "<SQL Server name>" -EventHubTargetState Enabled -EventHubName "<Event Hub name>" -EventHubAuthorizationRuleResourceId "<Event Hub Authorization Rule Resource ID>"
                Blob Storage Example
                    Set-AzSqlServerAudit -ResourceGroupName "<resource group name>" -ServerName "<SQL Server name>" -BlobStorageTargetState Enabled -StorageAccountResourceId "/subscriptions/<subscription_ID>/resourceGroups/<Resource_Group>/providers/Microsoft.Stora ge/storageAccounts/<Storage Account name>"'

  impact 0.5
  tag nist: ['AU-3', 'AU-3(1)', 'AU-7', 'AU-12']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['8.5'] }]

  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-auditing-on-sql-servers'
  ref 'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/get-azurermsqlserverauditing?view=azurermps-5.2.0'
  ref 'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/set-azurermsqlserverauditingpolicy?view=azurermps-5.2.0'
  ref 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-auditing'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'

  servers_script = 'Get-AzSqlServer | ConvertTo-Json'
  servers_output = powershell(servers_script).stdout.strip
  all_servers = json(content: servers_output).params

  only_if('N/A - No Azure SQL Databases found', impact: 0) do
    case all_servers
    when Array
      !all_servers.empty?
    when Hash
      !all_servers.empty?
    else
      false
    end
  end

  storage_script = 'Get-AzStorageAccount | ConvertTo-Json'
  storage_output = powershell(storage_script).stdout.strip
  all_storage = json(content: storage_output).params
  exclusions_list = input('excluded_resource_groups_and_storage_accounts')

  rg_sa_list = case all_storage
               when Array
                 all_storage.map { |account| "#{account['ResourceGroupName']}.#{account['StorageAccountName']}" }
               when Hash
                 ["#{all_storage['ResourceGroupName']}.#{all_storage['StorageAccountName']}"]
               else
                 []
               end

  rg_sa_list.reject! { |sa| exclusions_list.include?(sa) }

  only_if('N/A - No Storage Accounts found (accounts may have been manually excluded)', impact: 0) do
    !rg_sa_list.empty?
  end

  rg_sa_list.each do |pair|
    resource_group, = pair.split('.')

    sql_servers_script = <<-EOH
      $ErrorActionPreference = "Stop"
      Get-AzSqlServer -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
    EOH

    sql_servers_output_pwsh = powershell(sql_servers_script)
    raise Inspec::Error, "The powershell output returned the following error:  #{sql_servers_output_pwsh.stderr}" if sql_servers_output_pwsh.exit_status != 0

    sql_servers_output = sql_servers_output_pwsh.stdout.strip

    sql_servers = json(content: sql_servers_output).params
    sql_servers = [sql_servers] unless sql_servers.is_a?(Array)

    sql_servers.each do |server|
      resource_group_server = server['ResourceGroupName']
      server_name = server['ServerName']

      if resource_group_server.to_s.empty? || server_name.to_s.empty?
        describe "Ensure that 'Auditing' Retention is 'greater than 90 days'" do
          skip 'ResourceGroupName or ServerName is empty, skipping audit test'
        end
      else
        describe "SQL Server Audit Settings for #{server_name} (Resource Group: #{resource_group})" do
          audit_script = <<-EOH
            $ErrorActionPreference = "Stop"
            Get-AzSqlServerAudit -ResourceGroupName "#{resource_group}" -ServerName "#{server_name}" | ConvertTo-Json -Depth 10
          EOH

          audit_output_pwsh = powershell(audit_script)
          audit_output = audit_output_pwsh.stdout.strip
          raise Inspec::Error, "The powershell output returned the following error:  #{audit_output_pwsh.stderr}" if audit_output_pwsh.exit_status != 0

          audit = json(content: audit_output).params

          it 'has at least one audit target enabled' do
            blob_enabled = audit['BlobStorageTargetState'] == 'Enabled'
            eventhub_enabled = audit['EventHubTargetState'] == 'Enabled'
            loganalytics_enabled = audit['LogAnalyticsTargetState'] == 'Enabled'
            expect(blob_enabled || eventhub_enabled || loganalytics_enabled).to cmp true
          end
        end
      end
    end
  end
end
