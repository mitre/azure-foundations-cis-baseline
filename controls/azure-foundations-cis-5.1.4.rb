control 'azure-foundations-cis-5.1.4' do
  title 'Ensure that Microsoft Entra authentication is Configured for SQL Servers'
  desc 'Use Microsoft Entra authentication for authentication with SQL Database to manage credentials in a single place.'

  desc 'rationale',
       "Microsoft Entra authentication is a mechanism to connect to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in the Microsoft Entra ID directory. With Entra ID authentication, identities of database users and other Microsoft services can be managed in one central location. Central ID management provides a single place to manage database users and simplifies permission management.
            • It provides an alternative to SQL Server authentication.
            • Helps stop the proliferation of user identities across database servers.
            • Allows password rotation in a single place.
            • Customers can manage database permissions using external (Entra ID) groups.
            • It can eliminate storing passwords by enabling integrated Windows authentication and other forms of authentication supported by Microsoft Entra.
            • Entra ID authentication uses contained database users to authenticate identities at the database level.
            • Entra ID supports token-based authentication for applications connecting to SQL Database.
            • Entra ID authentication supports ADFS (domain federation) or native user/password authentication for a local Active Directory without domain synchronization.
            • Entra ID supports connections from SQL Server Management Studio that use Active Directory Universal Authentication, which includes Multi-Factor Authentication (MFA). MFA includes strong authentication with a range of easy verification options — phone call, text message, smart cards with pin, or mobile app notification."

  desc 'impact',
       'This will create administrative overhead with user account and permission management. For further security on these administrative accounts, you may want to consider licensing which supports features like Multi Factor Authentication.'

  desc 'check',
       "Audit from Azure Portal
            1. Go to SQL servers
            2. For each SQL server, under Settings, click Microsoft Entra ID
            3. Under Microsoft Entra admin, ensure a value has been set for Admin Name
        Audit from Azure CLI
            To list SQL Server Admins on a specific server:
                az sql server ad-admin list --resource-group <resource-group> --server <server>
        Audit from PowerShell
            Print a list of all SQL Servers to find which one you want to audit
                Get-AzSqlServer
            Audit a list of Administrators on a Specific Server
                Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName <resource group name> -ServerName <server name>
            Ensure Output shows DisplayName set to AD account.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 1f314764-cb73-4fc9-b863-8eca98ac36e9 - Name: 'An Azure Active Directory administrator should be provisioned for SQL servers'"

  desc 'fix',
       'Remediate from Azure Portal
            1. Go to SQL servers
            2. For each SQL server, under Settings, click Microsoft Entra ID
            3. Click Set admin
            4. Select an admin
            5. Click Select
            6. Click Save
        Remediate from Azure CLI
                az ad user show --id
            For each Server, set AD Admin
                az sql server ad-admin create --resource-group <resource group name> --server <server name> --display-name <display name> --object-id <object id of user>
        Remediate from PowerShell
            For each Server, set Entra ID Admin
                Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName <resource group name> -ServerName <server name> -DisplayName "<Display name of AD account to set as DB administrator>"'

  impact 0.5
  tag nist: ['AC-2(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['5.6'] }]

  ref 'https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure'
  ref 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication'
  ref 'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/get-azurermsqlserveractivedirectoryadministrator?view=azurermps-5.2.0'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-1-use-centralized-identity-and-authentication-system'
  ref 'https://docs.microsoft.com/en-us/cli/azure/sql/server/ad-admin?view=azure-cli-latest#az_sql_server_ad_admin_list'

  servers_script = 'Get-AzSqlServer | ConvertTo-Json'
  servers_output = powershell(servers_script).stdout.strip
  all_servers = json(content: servers_output).params

  only_if('N/A - No Azure SQL Databases found', impact: 0) do
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

    sql_servers_script = <<-EOH
      $ErrorActionPreference = "Stop"
      Get-AzSqlServer -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
    EOH

    sql_servers_output_pwsh = powershell(sql_servers_script)
    raise Inspec::Error, "The powershell output returned the following error:  #{sql_servers_output_pwsh.stderr}" if sql_servers_output_pwsh.exit_status != 0

    sql_servers_output = sql_servers_output_pwsh.stdout.strip
    sql_servers = json(content: sql_servers_output).params
    sql_servers = [sql_servers] unless sql_servers.is_a?(Array)

    sql_servers.each do |server|
      server_name = server['ServerName']
      resource_group_server = server['ResourceGroupName']

      if resource_group_server.to_s.empty? || server_name.to_s.empty?
        describe 'Ensure that Microsoft Entra authentication is Configured for SQL Servers' do
          skip 'ResourceGroupName or ServerName is empty, skipping audit test'
        end
      else
        script = <<-EOH
        $ErrorActionPreference = "Stop"
        Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName "#{resource_group_server}" -ServerName "#{server_name}" | ConvertTo-Json -Depth 10
        EOH

        output_pwsh = powershell(script)
        output = output_pwsh.stdout.strip
        raise Inspec::Error, "The powershell output returned the following error:  #{output_pwsh.stderr}" if output_pwsh.exit_status != 0

        ad_admin = json(content: output).params

        describe "Microsoft Entra authentication for SQL Server '#{server_name}' (Resource Group: #{resource_group_server})" do
          it 'has a non-empty Admin Name' do
            expect(ad_admin['DisplayName'].to_s.strip).not_to be_empty
          end
        end
      end
    end
  end
end
