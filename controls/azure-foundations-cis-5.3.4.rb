control 'azure-foundations-cis-5.3.4' do
    title "Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL flexible server"
    desc "Set audit_log_events to include CONNECTION on MySQL flexible servers."

    desc 'rationale',
        "Enabling CONNECTION helps MySQL Database to log items such as successful and failed connection attempts to the server. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance."

    desc 'impact',
        "There are further costs incurred for storage of logs. For high traffic databases these logs will be significant. Determine your organization's needs before enabling."

    desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for MySQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type audit_log.
            5. Ensure that the VALUE for audit_log_enabled is ON.
            6. Ensure that the VALUE for audit_log_events includes CONNECTION.
        Audit from Azure CLI 
            Ensure the below command returns a value that includes CONNECTION: 
                az mysql flexible-server parameter show --resource-group <resourceGroup> --server-name <serverName> --name audit_log_events
        Audit from PowerShell 
            Ensure the below command returns a Value that includes CONNECTION: 
                Get-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name audit_log_events"

    desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for MySQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type audit_log.
            5. Set audit_log_enabled to ON.
            6. In the drop-down next to audit_log_events, check CONNECTION.
            7. Click Save.
            8. Under Monitoring, select Diagnostic settings.
            9. Select + Add diagnostic setting.
            10. Provide a diagnostic setting name.
            11. Under Categories, select MySQL Audit Logs.
            12. Specify destination details.
            13. Click Save.
            It may take up to 10 minutes for the logs to appear in the configured destination.
        Remediate from Azure CLI 
            Use the below command to set audit_log_events to CONNECTION: 
                az mysql flexible-server parameter set --resource-group <resourceGroup> --server-name <serverName> --name audit_log_events --value CONNECTION
        Remediate from PowerShell 
            Use the below command to set audit_log_events to CONNECTION: 
                Update-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name audit_log_events -Value CONNECTION"


    impact 0.5
    tag nist: ['AU-2', 'AU-7', 'AU-12']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['8.2'] }]

    ref 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-audit-logs'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'
    ref 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/tutorial-configure-audit'
    ref 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/tutorial-configure-audit#configure-auditing-by-using-the-azure-cli'

    describe 'benchmark' do
        skip 'configure'
    end
end