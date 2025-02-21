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

  describe 'benchmark' do
    skip 'The check for this control needs to be done manually'
  end
end
