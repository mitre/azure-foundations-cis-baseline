control 'azure-foundations-cis-5.2.2' do
    title "Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL flexible server"
    desc "Enable log_checkpoints on PostgreSQL flexible servers."

    desc 'rationale',
        "Enabling log_checkpoints helps the PostgreSQL Database to Log each checkpoint, which in turn generates query and error logs. However, access to transaction logs is not supported. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance."

    desc 'check',
       "Audit from Azure Portal
            1. From Azure Home select the Portal Menu.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type log_checkpoints.
            5. Ensure that the VALUE for log_checkpoints is set to ON.
        Audit from Azure CLI 
            Ensure the below command returns a value of on: 
                az postgres flexible-server parameter show --resource-group <resourceGroup> --server-name <serverName> --name log_checkpoints
        Audit from PowerShell 
            Ensure the below command returns a Value of on: 
                Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name log_checkpoints
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 70be9e12-c935-49ac-9bd8-fd64b85c1f87 - Name: 'Log checkpoints should be enabled for PostgreSQL flexible servers'"

    desc 'fix',
       "Remediate from Azure Portal
            1. From Azure Home select the Portal Menu.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type log_checkpoints.
            5. Set the VALUE for log_checkpoints to ON.
            6. Click Save.
        Remediate from Azure CLI 
            Use the below command to enable log_checkpoints: 
                az postgres flexible-server parameter set --resource-group <resourceGroup> --server-name <serverName> --name log_checkpoints --value on
        Remediate from PowerShell 
            Update-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name log_checkpoints -Value on"

    impact 0.5
    tag nist: ['AU-2', 'AU-7', 'AU-12']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['8.2'] }]

    ref 'https://learn.microsoft.com/en-us/rest/api/postgresql/flexibleserver/configurations/list-by-server'
    ref 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-server-parameters-using-portal'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'
    ref 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-logging#configure-logging'
    ref 'https://learn.microsoft.com/en-us/powershell/module/az.postgresql/get-azpostgresqlflexibleserverconfiguration?view=azps-12.2.0#example-1-get-specified-postgresql-configuration-by-name'
    ref 'https://learn.microsoft.com/en-us/powershell/module/az.postgresql/update-azpostgresqlflexibleserverconfiguration?view=azps-12.2.0#example-1-updatae-specified-postgresql-configuration-by-name'

    describe 'benchmark' do
        skip 'configure'
    end
end