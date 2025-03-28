control 'azure-foundations-cis-5.2.6' do
  title "[LEGACY] Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL single server"
  desc "Enable log_connections on PostgreSQL single servers.
        NOTE: This recommendation currently only applies to Single Server, not Flexible Server. See additional information below for details about the planned retirement of Azure PostgreSQL Single Server."

  desc 'rationale',
       'Enabling log_connections helps PostgreSQL Database to log attempted connection to the server, as well as successful completion of client authentication. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.'

  desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for PostgreSQL servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type log_connections.
            5. Ensure that log_connections is set to ON.
        Audit from Azure CLI
            Ensure the below command returns a Value of on:
                az postgres server configuration show --resource-group <resourceGroup> --server-name <serverName> --name log_connections
        Audit from PowerShell
            Ensure the below command returns a Value of on:
                Get-AzPostgreSqlConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name log_connections
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: eb6f77b9-bd53-4e35-a23d-7f65d5f0e442 - Name: 'Log connections should be enabled for PostgreSQL database servers'"

  desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for PostgreSQL servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type log_connections.
            5. Set log_connections to ON.
            6. Click Save.
        Remediate from Azure CLI
            Use the below command to update log_connections configuration.
                az postgres server configuration set --resource-group <resourceGroupName> --server-name <serverName> --name log_connections --value on
        Remediate from PowerShell
            Use the below command to update log_connections configuration.
                Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_connections -Value on"

  impact 0.5
  tag nist: ['AU-2', 'AU-7', 'AU-12']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['8.2'] }]

  ref 'https://docs.microsoft.com/en-us/rest/api/postgresql/configurations/listbyserver'
  ref 'https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'
  ref 'https://learn.microsoft.com/en-us/powershell/module/az.postgresql/get-azpostgresqlconfiguration?view=azps-9.2.0#example-2-get-specified-postgresql-configuration-by-name'
  ref 'https://learn.microsoft.com/en-us/powershell/module/az.postgresql/update-azpostgresqlconfiguration?view=azps-9.2.0#example-1-update-postgresql-configuration-by-name'

  servers_script = 'Get-AzPostgreSqlFlexibleServer | ConvertTo-Json'
  servers_output = powershell(servers_script).stdout.strip
  all_servers = json(content: servers_output).params

  only_if('Control applicable only if PostgreSQL Flexible Servers exist and using PostgreSQL single server', impact: 0) do
    servers_exist = case all_servers
                    when Array
                      !all_servers.empty?
                    when Hash
                      !all_servers.empty?
                    else
                      false
                    end

    servers_exist && input('postgresql_single_server')
  end

  rg_sa_list = input('resource_groups_and_storage_accounts')

  rg_sa_list.each do |pair|
    resource_group, = pair.split('.')

    postgres_servers_script = <<-EOH
        $ErrorActionPreference = "Stop"
				Get-AzPostgreSqlFlexibleServer -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
    EOH

    postgres_servers_output_pwsh = powershell(postgres_servers_script)
    postgres_servers_output = postgres_servers_output_pwsh.stdout.strip
    raise Inspec::Error, "The powershell output returned the following error:  #{postgres_servers_output_pwsh.stderr}" if postgres_servers_output_pwsh.exit_status != 0

    postgres_servers = json(content: postgres_servers_output).params
    postgres_servers = [postgres_servers] unless postgres_servers.is_a?(Array)

    postgres_servers.each do |server|
      server_name = server['Name']

      describe "PostgreSQL Flexible Server '#{server_name}' in Resource Group '#{resource_group}' require_secure_transport configuration" do
        config_script = <<-EOH
            $ErrorActionPreference = "Stop"
						Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName "#{resource_group}" -ServerName "#{server_name}" -Name require_secure_transport | ConvertTo-Json -Depth 10
        EOH

        config_output_pwsh = powershell(config_script)
        config_output = config_output_pwsh.stdout.strip
        raise Inspec::Error, "The powershell output returned the following error:  #{config_output_pwsh.stderr}" if config_output_pwsh.exit_status != 0

        configuration = json(content: config_output).params

        it "should have require_secure_transport set to 'ON'" do
          expect(configuration['Value']).to cmp 'on'
        end
      end
    end
  end
end
