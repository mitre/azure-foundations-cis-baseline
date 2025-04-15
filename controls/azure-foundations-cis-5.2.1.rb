control 'azure-foundations-cis-5.2.1' do
  title "Ensure server parameter 'require_secure_transport' is set to 'ON' for PostgreSQL flexible server"
  desc 'Enable require_secure_transport on PostgreSQL flexible servers.'

  desc 'rationale',
       'SSL connectivity helps to provide a new layer of security by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against "man in the middle" attacks by encrypting the data stream between the server and application'

  desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type require_secure_transport.
            5. Ensure that the VALUE for require_secure_transport is set to ON.
        Audit from Azure CLI
            Ensure the below command returns a value of on:
                az postgres flexible-server parameter show --resource-group <resourceGroup> --server-name <serverName> --name require_secure_transport
        Audit from PowerShell
            Ensure the below command returns a Value of on:
                Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name require_secure_transport
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: c29c38cb-74a7-4505-9a06-e588ab86620a - Name: 'Enforce SSL connection should be enabled for PostgreSQL flexible servers'"

  desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type require_secure_transport.
            5. Set the VALUE for require_secure_transport to ON.
            6. Click Save.
        Remediate from Azure CLI
            Use the below command to enable require_secure_transport:
                az postgres flexible-server parameter set --resource-group <resourceGroup> --server-name <serverName> --name require_secure_transport --value on
        Remediate from PowerShell
            Update-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name require_secure_transport -Value on"

  impact 0.5
  tag nist: ['AC-17(2)', 'IA-5', 'IA-5(1)', 'SC-8', 'CS-8(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.10'] }]

  ref 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-ssl-tls'
  ref 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-connect-tls-ssl'
  ref 'https://learn.microsoft.com/en-us/powershell/module/az.postgresql/get-azpostgresqlflexibleserverconfiguration?view=azps-12.2.0#example-1-get-specified-postgresql-configuration-by-name'
  ref 'https://learn.microsoft.com/en-us/powershell/module/az.postgresql/update-azpostgresqlflexibleserverconfiguration?view=azps-12.2.0#example-1-updatae-specified-postgresql-configuration-by-name'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-3-encrypt-sensitive-data-in-transit'

  servers_script = 'Get-AzPostgreSqlFlexibleServer | ConvertTo-Json'
  servers_output = powershell(servers_script).stdout.strip
  all_servers = json(content: servers_output).params

  only_if('N/A - No PostgreSQL Flexible Servers found', impact: 0) do
    case all_servers
    when Array
      !all_servers.empty?
    when Hash
      !all_servers.empty?
    else
      false
    end
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
      skip 'N/A - No Storage Accounts found or accounts have been manually excluded'
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
          describe "Ensure server parameter 'require_secure_transport' is set to 'ON' for PostgreSQL flexible server" do
            skip 'Name is empty, skipping audit test'
          end
        else
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
  end
end
