control 'azure-foundations-cis-5.3.3' do
    title "Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL flexible server"
    desc "Enable audit_log_enabled on MySQL flexible servers."

    desc 'rationale',
        "Enabling audit_log_enabled helps MySQL Database to log items such as connection attempts to the server, DDL/DML access, and more. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance."

    desc 'impact',
        "There are further costs incurred for storage of logs. For high traffic databases these logs will be significant. Determine your organization's needs before enabling."

    desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for MySQL Servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type audit_log_enabled.
            5. Ensure that the VALUE for audit_log_enabled is ON.
        Audit from Azure CLI 
            Ensure the below command returns a value of on: 
                az mysql flexible-server parameter show --resource-group <resourceGroup> --server-name <serverName> --name audit_log_enabled
        Audit from PowerShell 
            Ensure the below command returns a Value of on: 
                Get-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name audit_log_enabled"

    desc 'fix',
       "Remediate from Azure Portal 
            Part 1 - Turn on audit logs
                1. Login to Azure Portal using https://portal.azure.com.
                2. Go to Azure Database for MySQL flexible servers.
                3. For each database, under Settings, click Server parameters.
                4. Set audit_log_enabled to ON.
                5. Click Save.
            Part 2 - Capture audit logs (diagnostic settings is for example only, send these logs to the appropriate data sink for your logging needs)
                1. Under Monitoring, select Diagnostic settings.
                2. Select + Add diagnostic setting.
                3. Provide a diagnostic setting name.
                4. Under Categories, select MySQL Audit Logs.
                5. Specify destination details.
                6. Click Save.
            It may take up to 10 minutes for the logs to appear in the configured destination.
        Remediate from Azure CLI 
            Use the below command to enable audit_log_enabled : 
                az mysql flexible-server parameter set --resource-group <resourceGroup> --server-name <serverName> --name audit_log_enabled --value on
        Remediate from PowerShell 
            Use the below command to enable audit_log_enabled : 
                Update-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name audit_log_enabled -Value on"

    impact 0.5
    tag nist: ['AU-2', 'AU-7', 'AU-12']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['8.2'] }]

    ref 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/tutorial-configure-audit'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'
    ref 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/tutorial-configure-audit#configure-auditing-by-using-the-azure-cli'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end