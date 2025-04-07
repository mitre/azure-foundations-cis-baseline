control 'azure-foundations-cis-5.1.6' do
  title "Ensure that 'Auditing' Retention is 'greater than 90 days'"
  desc 'SQL Server Audit Retention should be configured to be greater than 90 days.'

  desc 'rationale',
       'Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access.'

  desc 'check',
       "Audit from Azure Portal
            1. Go to SQL servers.
            2. For each SQL server, under Security, click Auditing.
            3. If Storage is checked, expand Advanced properties.
            4. Ensure Retention (days) is set to a value greater than 90, or 0 for unlimited retention.
        Audit from PowerShell
            Get the list of all SQL Servers
                Get-AzSqlServer
            For each Server
                Get-AzSqlServerAudit -ResourceGroupName <resource group name> -ServerName <server name>
            Ensure that RetentionInDays is set to more than 90 Note: If the SQL server is set with LogAnalyticsTargetState setting set to Enabled, run the following additional command.
                Get-AzOperationalInsightsWorkspace | Where-Object {$_.ResourceId -eq <SQL Server WorkSpaceResourceId>}
            Ensure that RetentionInDays is set to more than 90
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 89099bee-89e0-4b26-a5f4-165451757743 - Name: 'SQL servers with auditing to storage account destination should be configured with 90 days retention or higher'"

  desc 'fix',
       'Remediate from Azure Portal
            1. Go to SQL servers.
            2. For each SQL server, under Security, click Auditing.
            3. If Storage is checked, expand Advanced properties.
            4. Set Retention (days) to a value greater than 90, or 0 for unlimited retention.
            5. Click Save.
        Remediate from PowerShell
            For each Server, set retention policy to more than 90 days
                Log Analytics Example
                    Set-AzSqlServerAudit -ResourceGroupName <resource group name> -ServerName <SQL Server name> -RetentionInDays <Number of Days to retain the audit logs, should be more than 90 days> -LogAnalyticsTargetState Enabled -WorkspaceResourceId "/subscriptions/<subscription ID>/resourceGroups/insights-integration/providers/Microsoft.OperationalInsights/workspaces/<workspace name>
                Event Hub Example
                    Set-AzSqlServerAudit -ResourceGroupName "<resource group name>" -ServerName "<SQL Server name>" -EventHubTargetState Enabled -EventHubName "<Event Hub name>" -EventHubAuthorizationRuleResourceId "<Event Hub Authorization Rule Resource ID>"
                Blob Storage Example
                    Set-AzSqlServerAudit -ResourceGroupName "<resource group name>" -ServerName "<SQL Server name>" -BlobStorageTargetState Enabled -StorageAccountResourceId "/subscriptions/<subscription_ID>/resourceGroups/<Resource_Group>/providers/Microsoft.Stora ge/storageAccounts/<Storage Account name>"'

  impact 0.5
  tag nist: ['AU-4']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['8.3'] }]

  ref 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-auditing'
  ref 'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/get-azurermsqlserverauditing?view=azurermps-5.2.0'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-6-configure-log-storage-retention'

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

      describe "SQL Server Audit retention for '#{server_name}' (Resource Group: #{resource_group_server})" do
        audit_script = <<-EOH
          $ErrorActionPreference = "Stop"
          Get-AzSqlServerAudit -ResourceGroupName "#{resource_group_server}" -ServerName "#{server_name}" | ConvertTo-Json -Depth 10
        EOH

        audit_output_pwsh = powershell(audit_script)
        audit_output = audit_output_pwsh.stdout.strip
        raise Inspec::Error, "The powershell output returned the following error:  #{audit_output_pwsh.stderr}" if audit_output_pwsh.exit_status != 0

        audit = json(content: audit_output).params

        if audit['LogAnalyticsTargetState'].to_i == 0 && audit['WorkspaceResourceId'] && !audit['WorkspaceResourceId'].empty?
          describe "Operational Insights Workspace retention for SQL Server '#{server_name}'" do
            workspace_script = <<-EOH
              $ErrorActionPreference = "Stop"
              Get-AzOperationalInsightsWorkspace | Where-Object { $_.ResourceId -eq "#{audit['WorkspaceResourceId']}" } | ConvertTo-Json -Depth 10
            EOH

            workspace_output_pwsh = powershell(workspace_script)
            workspace_output = workspace_output_pwsh.stdout.strip
            raise Inspec::Error, "The powershell output returned the following error:  #{workspace_output_pwsh.stderr}" if workspace_output_pwsh.exit_status != 0

            workspace = json(content: workspace_output).params

            it 'should have Workspace RetentionInDays set to more than 90 days' do
              workspace_retention = workspace['retentionInDays'].to_i
              expect(workspace_retention).to be > 90
            end
          end
        else
          it 'should have Audit RetentionInDays set to more than 90 days' do
            retention = audit['RetentionInDays'].to_i
            expect(retention).to be > 90
          end
        end
      end
    end
  end
end
