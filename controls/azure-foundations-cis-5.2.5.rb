control 'azure-foundations-cis-5.2.5' do
  title "Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled"
  desc 'Disable access from Azure services to PostgreSQL flexible server.'

  desc 'rationale',
       "If access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually not a desired configuration. Instead, set up firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks."

  desc 'check',
       "%(Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Networking.
            4. Under Firewall rules, ensure Allow public access from any Azure service within Azure to this server is not checked.
        Audit from Azure CLI
            Ensure the below command does not return a rule with a name beginning AllowAllAzureServicesAndResourcesWithinAzureIps or with 'startIpAddress': '0.0.0.0' or 'endIpAddress': '0.0.0.0':
                az postgres flexible-server firewall-rule list --resource-group <resourceGroup> --name <serverName>
        Audit from PowerShell
            Ensure the below command does not return a rule with a name beginning AllowAllAzureServicesAndResourcesWithinAzureIps:
                Get-AzPostgreSqlFlexibleServerFirewallRule -ResourceGroupName <resourceGroup> -ServerName <serverName>
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 5e1de0e3-42cb-4ebc-a86d-61d0c619ca48 - Name: 'Public network access should be disabled for PostgreSQL flexible servers')"

  desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com.
            2. Go to Azure Database for PostgreSQL flexible servers.
            3. For each database, under Settings, click Networking.
            4. Under Firewall rules, uncheck Allow public access from any Azure service within Azure to this server.
            5. Click Save.
        Remediate from Azure CLI
            Using the firewall rule name from the Audit from Azure CLI steps, use the below command to delete the AllowAllAzureServicesAndResourcesWithinAzureIps rule for PostgreSQL flexible server:
                az postgres flexible-server firewall-rule delete --resource-group <resourceGroup> --name <serverName> --rule-name <ruleName>
            Type y and press enter to confirm.
        Remediate from PowerShell
            Using the firewall rule name from the Audit from PowerShell steps, use the below command to delete the AllowAllAzureServicesAndResourcesWithinAzureIps rule for PostgreSQL flexible server:
                Remove-AzPostgreSqlFlexibleServerFirewallRule -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name <ruleName>"

  impact 0.5
  tag nist: ['CA-9', 'SC-7', 'SC-7(5)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.4'] }]

  ref 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-firewall-rules'
  ref 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-manage-firewall-cli'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-1-establish-network-segmentation-boundaries'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-6-deploy-web-application-firewall'

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
    failures = []
    resource_groups = rg_sa_list.map { |pair| pair.split('.').first }.uniq
    resource_groups.each do |resource_group|
      servers_script = <<-EOH
        $ErrorActionPreference = "Stop"
        Get-AzPostgreSqlFlexibleServer -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
      EOH

      servers_output_pwsh = powershell(servers_script)
      raise Inspec::Error, "The powershell output returned the following error:  #{servers_output_pwsh.stderr}" if servers_output_pwsh.exit_status != 0

      servers = json(content: servers_output_pwsh.stdout.strip).params
      servers = [servers] unless servers.is_a?(Array)

      servers.each do |server|
        server_name = server['Name']
        next if server_name.to_s.empty?

        firewall_script = <<-EOH
          $ErrorActionPreference = "Stop"
          Get-AzPostgreSqlFlexibleServerFirewallRule -ResourceGroupName "#{resource_group}" -ServerName "#{server_name}" | ConvertTo-Json -Depth 10
        EOH

        fw_pwsh = powershell(firewall_script)
        raise Inspec::Error, "The powershell output returned the following error:  #{fw_pwsh.stderr}" if fw_pwsh.exit_status != 0

        rules = json(content: fw_pwsh.stdout.strip).params
        rules = [rules] unless rules.is_a?(Array)

        rules.each do |rule|
          name = rule['Name'].to_s
          start_ip = rule['StartIpAddress'].to_s
          end_ip   = rule['EndIpAddress'].to_s

          failures << "#{resource_group}/#{server_name}/#{name}" if name.match(/^AllowAllAzureServicesAndResourcesWithinAzureIps/) || start_ip == '0.0.0.0' || end_ip == '0.0.0.0'
        end
      end
    end

    describe 'PostgreSQL Flexible servers with overly permissive firewall rules' do
      subject { failures }
      it { should be_empty }
    end
  end
end
