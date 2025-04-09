control 'azure-foundations-cis-5.3.2' do
  title "Ensure server parameter 'tls_version' is set to 'TLSv1.2' (or higher) for MySQL flexible server"
  desc 'Ensure tls_version on MySQL flexible servers is set to use TLS version 1.2 or higher.'

  desc 'rationale',
       'TLS connectivity helps to provide a new layer of security by connecting database server to client applications using Transport Layer Security (TLS). Enforcing TLS connections between database server and client applications helps protect against "man in the middle" attacks by encrypting the data stream between the server and application.'

  desc 'check',
       'Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for MySQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type tls_version.
            5. Ensure tls_version is set to TLSv1.2 (or higher).
        Audit from PowerShell
            Ensure the Value of the below command contains TLSv1.2 or higher, and does not contain anything lower than TLSv1.2:
                Get-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <ServerName> -Name tls_version
        Audit from Azure CLI
            Ensure the value of the below command contains TLSv1.2 or higher, and does not contain anything lower than TLSv1.2:
                az mysql flexible-server parameter show --resource-group <resourceGroup> --server-name <serverName> --name tls_version
            Example output – next page
                {
                    "allowedValues": "TLSv1,TLSv1.1,TLSv1.2",
                    "dataType": "Set",
                    "defaultValue": "TLSv1.2",
                    "description": "Which protocols the server permits for encrypted connections. By default, TLS 1.2 is enforced",
                    "id": "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.DBforMySQL/flexibleServers/<serverName>/configurations/tls_version",
                    "isConfigPendingRestart": "False",
                    "isDynamicConfig": "False",
                    "isReadOnly": "False",
                    "name": "tls_version",
                    "resourceGroup": "<resourceGroupName>",
                    "source": "system-default",
                    "systemData": null,
                    "type": "Microsoft.DBforMySQL/flexibleServers/configurations",
                    "value": "TLSv1.2"
                }'

  desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for MySQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type tls_version.
            5. Click on the VALUE dropdown next to tls_version, and check TLSv1.2 (or higher).
            6. Uncheck anything lower than TLSv1.2.
            7. Click Save.
        Remediate from Azure CLI
            Use the below command to update MySQL flexible servers to use TLS version 1.2:
                az mysql flexible-server parameter set --resource-group <resourceGroup> --server-name <serverName> --name tls_version --value TLSv1.2
        Remediate from PowerShell
            Use the below command to update MySQL flexible servers to use TLS version 1.2:
                Update-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name tls_version -Value TLSv1.2"

  impact 0.5
  tag nist: ['AC-17(2)', 'IA-5', 'IA-5(1)', 'SC-8', 'SC-8(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.10'] }]

  ref 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking#tls-and-ssl'
  ref 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-connect-tls-ssl'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-3-encrypt-sensitive-data-in-transit'

  servers_script = 'Get-AzMysqlFlexibleServer | ConvertTo-Json'
  servers_output = powershell(servers_script).stdout.strip
  all_servers = json(content: servers_output).params

  only_if('N/A - No MySQL Flexible Servers found', impact: 0) do
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

  only_if('N/A - No Storage Accounts found (accounts may have been manually excluded)', impact: 0) do
    !rg_sa_list.empty?
  end

  rg_sa_list.each do |pair|
    resource_group, = pair.split('.')

    script = <<-EOH
      $ErrorActionPreference = "Stop"
			Get-AzMysqlFlexibleServer -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
    EOH

    server_output_pwsh = powershell(script)
    server_output = server_output_pwsh.stdout.strip
    raise Inspec::Error, "The powershell output returned the following error:  #{server_output_pwsh.stderr}" if server_output_pwsh.exit_status != 0

    servers = json(content: server_output).params
    servers = [servers] unless servers.is_a?(Array)

    servers.each do |server|
      server_name = server['Name']

      if server_name.to_s.empty?
        describe "Ensure server parameter 'tls_version' is set to 'TLSv1.2' (or higher) for MySQL flexible server" do
          skip 'Name is empty, skipping audit test'
        end
      else
        describe "MySQL Flexible Server '#{server_name}' tls_version configuration" do
          config_script = <<-EOH
          $ErrorActionPreference = "Stop"
					Get-AzMysqlFlexibleServerConfiguration -ResourceGroupName "#{resource_group}" -ServerName "#{server_name}" -Name tls_version | ConvertTo-Json -Depth 10
          EOH

          config_output_pwsh = powershell(config_script)
          config_output = config_output_pwsh.stdout.strip
          raise Inspec::Error, "The powershell output returned the following error:  #{config_output_pwsh.stderr}" if config_output_pwsh.exit_status != 0

          configuration = json(content: config_output).params

          it 'should include TLSv1.2' do
            expect(configuration['Value']).to match(/TLSv1\.2/)
          end
        end
      end
    end
  end
end
