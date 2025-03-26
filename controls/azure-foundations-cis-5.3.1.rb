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
    case all_servers
    when Array
      !all_servers.empty?
    when Hash
      !all_servers.empty?
    else
      false
    end
  end

  rg_sa_list = input('resource_groups_and_storage_accounts')

  rg_sa_list.each do |pair|
    resource_group, = pair.split('.')

    script = <<-EOH
			Get-AzMysqlFlexibleServer -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
    EOH

    server_output = powershell(script).stdout.strip
    servers = json(content: server_output).params
    servers = [servers] unless servers.is_a?(Array)

    servers.each do |server|
      server_name = server['Name']

      describe "MySQL Flexible Server '#{server_name}' in Resource Group '#{resource_group}' require_secure_transport configuration" do
        config_script = <<-EOH
						Get-AzMysqlFlexibleServerConfiguration -ResourceGroupName "#{resource_group}" -ServerName "#{server_name}" -Name require_secure_transport | ConvertTo-Json -Depth 10
        EOH

        config_output = powershell(config_script).stdout.strip
        configuration = json(content: config_output).params

        it "should have require_secure_transport set to 'ON'" do
          expect(configuration['Value']).to cmp 'on'
        end
      end
    end
  end
end
