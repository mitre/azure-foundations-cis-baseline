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

	rg_sa_list = input('resource_groups_and_storage_accounts')

	rg_sa_list.each do |pair|
		resource_group, _ = pair.split('.')

		postgres_servers_script = <<-EOH
				Get-AzPostgreSqlFlexibleServer -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
		EOH

		postgres_servers_output = powershell(postgres_servers_script).stdout.strip
		postgres_servers = json(content: postgres_servers_output).params
		postgres_servers = [postgres_servers] unless postgres_servers.is_a?(Array)

		postgres_servers.each do |server|
			server_name = server['Name']

			describe "PostgreSQL Flexible Server '#{server_name}' in Resource Group '#{resource_group}' require_secure_transport configuration" do
				config_script = <<-EOH
						Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName "#{resource_group}" -ServerName "#{server_name}" -Name require_secure_transport | ConvertTo-Json -Depth 10
				EOH

				config_output = powershell(config_script).stdout.strip
				configuration = json(content: config_output).params

				it "should have require_secure_transport set to on" do
					expect(configuration['Value']).to cmp 'on'
				end
			end
		end
	end
end
