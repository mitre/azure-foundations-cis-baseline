control 'azure-foundations-cis-5.3.1' do
  title "Ensure server parameter 'require_secure_transport' is set to 'ON' for MySQL flexible server"
  desc 'Enable require_secure_transport on MySQL flexible servers.'

  desc 'rationale',
       'SSL connectivity helps to provide a new layer of security by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against "man in the middle" attacks by encrypting the data stream between the server and application.'

  desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for MySQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type require_secure_transport.
            5. Ensure that the VALUE for require_secure_transport is ON.
        Audit from Azure CLI
            Ensure the below command returns a value of on:
                az mysql flexible-server parameter show --resource-group <resourceGroup> --server-name <serverName> --name require_secure_transport
        Audit from PowerShell
            Ensure the below command returns a Value of on:
                Get-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name require_secure_transport"

  desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for MySQL flexible servers.
            3. For each database, under Settings, click Server parameters.
            4. In the filter bar, type require_secure_transport.
            5. Set the VALUE for require_secure_transport to ON.
            6. Click Save.
        Remediate from Azure CLI
            Use the below command to enable require_secure_transport:
                az mysql flexible-server parameter set --resource-group <resourceGroup> --server-name <serverName> --name require_secure_transport --value on
        Remediate from PowerShell
            Use the below command to enable require_secure_transport:
                Update-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name require_secure_transport -Value on"

  impact 0.5
  tag nist: ['AC-17(2)', 'IA-5', 'IA-5(1)', 'SC-8', 'SC-8(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.10'] }]

  ref 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking#tls-and-ssl'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-3-encrypt-sensitive-data-in-transit'

  servers_script = 'Get-AzMysqlFlexibleServer | ConvertTo-Json'
  servers_output = powershell(servers_script).stdout.strip
  all_servers = json(content: servers_output).params

  only_if('N/A - No MySQL Flexible Servers found', impact: 0) do
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
    failures = []
    resource_groups = rg_sa_list.map { |pair| pair.split('.').first }.uniq
    resource_groups.each do |resource_group|
      servers_script = <<-EOH
        $ErrorActionPreference = "Stop"
        Get-AzMysqlFlexibleServer -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
      EOH

      servers_output_pwsh = powershell(servers_script)
      raise Inspec::Error, "The powershell output returned the following error:  #{servers_output_pwsh.stderr}" if servers_output_pwsh.exit_status != 0

      servers = json(content: servers_output_pwsh.stdout.strip).params
      servers = [servers] unless servers.is_a?(Array)

      servers.each do |server|
        server_name = server['Name']
        next if server_name.to_s.empty?

        config_script = <<-EOH
          $ErrorActionPreference = "Stop"
          Get-AzMysqlFlexibleServerConfiguration -ResourceGroupName "#{resource_group}" -ServerName "#{server_name}" -Name require_secure_transport | ConvertTo-Json -Depth 10
        EOH

        config_output_pwsh = powershell(config_script)
        raise Inspec::Error, "The powershell output returned the following error:  #{config_output_pwsh.stderr}" if config_output_pwsh.exit_status != 0

        configuration = json(content: config_output_pwsh.stdout.strip).params

        failures << "#{resource_group}/#{server_name}" unless configuration['Value'].casecmp('on').zero?
      end
    end

    describe 'MySQL Flexible servers with require_secure_transport not set to ON' do
      subject { failures }
      it { should be_empty }
    end
  end
end
