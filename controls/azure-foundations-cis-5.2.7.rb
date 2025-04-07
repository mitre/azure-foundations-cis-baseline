control 'azure-foundations-cis-5.2.7' do
  title "[LEGACY] Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL single server"
  desc "Enable log_disconnections on PostgreSQL Servers.
        NOTE: This recommendation currently only applies to Single Server, not Flexible Server. See additional information below for details about the planned retirement of Azure PostgreSQL Single Server."

  desc 'rationale',
       'Enabling log_disconnections helps PostgreSQL Database to Logs end of a session, including duration, which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.'

  desc 'impact',
       'Enabling this setting will enable a log of all disconnections. If this is enabled for a high traffic server, the log may grow exponentially.'

  desc 'check',
       "Audit from Azure Portal
            1. From Azure Home select the Portal Menu.
            2. Go to Azure Database for PostgreSQL servers.
            3. For each database, under Settings, click Server parameters.
            4. Search for log_disconnections.
            5. Ensure that log_disconnections is set to ON.
        Audit from Azure CLI
            Ensure log_disconnections value is set to ON
                az postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name log_disconnections
        Audit from PowerShell
            Ensure log_disconnections value is set to ON
                Get-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_disconnections
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: eb6f77b9-bd53-4e35-a23d-7f65d5f0e446 - Name: 'Disconnections should be logged for PostgreSQL database servers.'"

  desc 'fix',
       "Remediate from Azure Portal
            1. From Azure Home select the Portal Menu.
            2. Go to Azure Database for PostgreSQL servers.
            3. For each database, under Settings, click Server parameters.
            4. Search for log_disconnections.
            5. Set log_disconnections to ON.
            6. Click Save.
        Remediate from Azure CLI
            Use the below command to update log_disconnections configuration.
                az postgres server configuration set --resource-group <resourceGroupName> --server-name <serverName> --name log_disconnections --value on
        Remediate from PowerShell
            Use the below command to update log_disconnections configuration.
                Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_disconnections -Value on"

  impact 0.5
  tag nist: ['AU-2', 'AU-7', 'AU-12']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['8.2'] }]

  ref 'https://docs.microsoft.com/en-us/rest/api/postgresql/singleserver/configurations/list-by-server'
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
