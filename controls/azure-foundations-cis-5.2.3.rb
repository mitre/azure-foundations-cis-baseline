control 'azure-foundations-cis-5.2.3' do
    title "Ensure server parameter 'connection_throttle.enable' is set to 'ON' for PostgreSQL flexible server"
    desc "Enable connection throttling on PostgreSQL flexible servers."

    desc 'rationale',
        "Enabling connection throttling helps the PostgreSQL Database to Set the verbosity of logged messages. This in turn generates query and error logs with respect to concurrent connections that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance."

    desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type connection_throttle.enable.
            5. Ensure that VALUE for connection_throttle.enable is set to ON.
        Audit from Azure CLI 
            Ensure the below command returns a value of on: 
                az postgres flexible-server parameter show --resource-group <resourceGroup> --server-name <serverName> --name connection_throttle.enable
        Audit from PowerShell 
            Ensure the below command returns a Value of on: 
                Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name connection_throttle.enable
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: dacf07fa-0eea-4486-80bc-b93fae88ac40 - Name: 'Connection throttling should be enabled for PostgreSQL flexible servers'"

    desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type connection_throttle.enable.
            5. Set connection_throttle.enable to ON.
            6. Click Save.
        Remediate from Azure CLI 
            Use the below command to enable connection_throttle.enable: 
                az postgres flexible-server parameter set --resource-group <resourceGroup> --server-name <serverName> --name connection_throttle.enable --value on
        Remediate from PowerShell 
            Use the below command to update connection_throttling configuration. 
                Update-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name connection_throttle.enable -Value on"

    impact 0.5
    tag nist: ['AU-2', 'AU-7', 'AU-12']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['8.2'] }]

    ref 'https://learn.microsoft.com/en-us/rest/api/postgresql/flexibleserver/configurations/list-by-server'
    ref 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-server-parameters-using-portal'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'
    ref 'https://learn.microsoft.com/en-us/powershell/module/az.postgresql/get-azpostgresqlflexibleserverconfiguration?view=azps-12.2.0#example-1-get-specified-postgresql-configuration-by-name'
    ref 'https://learn.microsoft.com/en-us/powershell/module/az.postgresql/update-azpostgresqlflexibleserverconfiguration?view=azps-12.2.0#example-1-updatae-specified-postgresql-configuration-by-name'

    describe 'benchmark' do
        skip 'configure'
    end
end