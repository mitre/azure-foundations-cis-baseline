control 'azure-foundations-cis-5.2.4' do
    title "Ensure server parameter 'logfiles.retention_days' is greater than 3 days for PostgreSQL flexible server"
    desc "Ensure logfiles.retention_days on PostgreSQL flexible servers is set to an appropriate value."

    desc 'rationale',
        "Configuring logfiles.retention_days determines the duration in days that Azure Database for PostgreSQL retains log files. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance."

    desc 'impact',
        'Configuring this setting will result in logs being retained for the specified number of days. If this is configured on a high traffic server, the log may grow quickly to occupy a large amount of disk space. In this case you may want to set this to a lower number.'

    desc 'check',
       "Audit from Azure Portal
            1. From Azure Home select the Portal Menu.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type logfiles.retention_days.
            5. Ensure that the VALUE is between 4 and 7 (inclusive).
        Audit from Azure CLI 
            Ensure logfiles.retention_days value is greater than 3. 
                az postgres flexible-server parameter show --resource-group <resourceGroup> --server-name <serverName> --name logfiles.retention_days
        Audit from Powershell 
            Ensure logfiles.retention_days value is greater than 3: 
                Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name logfiles.retention_days"

    desc 'fix',
       "Remediate from Azure Portal
            1. From Azure Home select the Portal Menu.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type logfiles.retention_days.
            5. Input a value between 4 and 7 (inclusive).
            6. Click Save.
        Remediate from Azure CLI 
            Use the below command to update logfiles.retention_days configuration: 
                az postgres flexible-server parameter set --resource-group <resourceGroup> --server-name <serverName> --name logfiles.retention_days --value <4-7>
        Remediate from Powershell 
            Use the below command to update logfiles.retention_days configuration: 
                Update-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name logfiles.retention_days -Value <4-7>"

    impact 0.5
    tag nist: ['AU-4']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['8.3'] }]

    ref 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-server-parameters-using-portal'
    ref 'https://learn.microsoft.com/en-us/rest/api/postgresql/flexibleserver/configurations/list-by-server'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-6-configure-log-storage-retention'
    ref 'https://learn.microsoft.com/en-us/powershell/module/az.postgresql/get-azpostgresqlflexibleserverconfiguration?view=azps-12.2.0#example-1-get-specified-postgresql-configuration-by-name'
    ref 'https://learn.microsoft.com/en-us/powershell/module/az.postgresql/update-azpostgresqlflexibleserverconfiguration?view=azps-12.2.0#example-1-updatae-specified-postgresql-configuration-by-name'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end