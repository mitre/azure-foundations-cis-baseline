control 'azure-foundations-cis-5.2.4' do
  title "Ensure server parameter 'logfiles.retention_days' is greater than 3 days for PostgreSQL flexible server"
  desc 'Ensure logfiles.retention_days on PostgreSQL flexible servers is set to an appropriate value.'

  desc 'rationale',
       'Configuring logfiles.retention_days determines the duration in days that Azure Database for PostgreSQL retains log files. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.'

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

  servers_script = 'Get-AzPostgreSqlFlexibleServer | ConvertTo-Json'
  servers_output = powershell(servers_script).stdout.strip
  all_servers = json(content: servers_output).params

  only_if('N/A - No PostgreSQL Flexible Servers found', impact: 0) do
    !all_servers.empty?
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

  if rg_sa_list.empty?
    impact 0.0
    describe 'N/A' do
      skip 'N/A - No storage accounts found or accounts have been manually excluded'
    end
  else

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

        if server_name.to_s.empty?
          describe "Ensure server parameter 'logfiles.retention_days' is greater than 3 days for PostgreSQL flexible server" do
            skip 'Name is empty, skipping audit test'
          end
        else
          describe "PostgreSQL Flexible Server '#{server_name}' in Resource Group '#{resource_group}' logfiles.retention_days configuration" do
            config_script = <<-EOH
            $ErrorActionPreference = "Stop"
						Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName "#{resource_group}" -ServerName "#{server_name}" -Name logfiles.retention_days | ConvertTo-Json -Depth 10
            EOH

            config_output_pwsh = powershell(config_script)
            config_output = config_output_pwsh.stdout.strip
            raise Inspec::Error, "The powershell output returned the following error:  #{config_output_pwsh.stderr}" if config_output_pwsh.exit_status != 0

            configuration = json(content: config_output).params

            it 'should have logfiles.retention_days set to a value greater than 3' do
              expect(configuration['Value'].to_i).to be > 3
            end
          end
        end
      end
    end
  end
end
