control 'azure-foundations-cis-5.1.5' do
  title "Ensure that 'Data encryption' is set to 'On' on a SQL Database"
  desc 'Enable Transparent Data Encryption on every SQL server.'

  desc 'rationale',
       'Azure SQL Database transparent data encryption helps protect against the threat of malicious activity by performing real-time encryption and decryption of the database, associated backups, and transaction log files at rest without requiring changes to the application.'

  desc 'check',
       "Audit from Azure Portal
            1. Go to SQL databases
            2. For each DB instance, under Security, click Data Encryption
            3. Under Transparent data encryption, ensure that Data encryption is set to On
        Audit from Azure CLI
            Ensure the output of the below command is Enabled
                az sql db tde show --resource-group <resourceGroup> --server <dbServerName> --database <dbName> --query status
        Audit from PowerShell
            Get a list of SQL Servers.
                Get-AzSqlServer
            For each server, list the databases.
                Get-AzSqlDatabase -ServerName <SQL Server Name> -ResourceGroupName <Resource Group Name>
            For each database not listed as a Master database, check for Transparent Data Encryption.
                Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName <Resource Group Name> -ServerName <SQL Server Name> -DatabaseName <Database Name>
            Make sure DataEncryption is Enabled for each database except the Master database.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 17k78e20-9358-41c9-923c-fb736d382a12 - Name: 'Transparent Data Encryption on SQL databases should be enabled'"

  desc 'fix',
       "Remediate from Azure Portal
            1. Go to SQL databases
            2. For each DB instance, under Security, click Data Encryption
            3. Under Transparent data encryption, set Data encryption to On
            4. Click Save
        Remediate from Azure CLI
            Use the below command to enable Transparent data encryption for SQL DB instance.
                az sql db tde set --resource-group <resourceGroup> --server <dbServerName> --database <dbName> --status Enabled
        Remediate from PowerShell Use the below command to enable Transparent data encryption for SQL DB instance.
            Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName <Resource Group Name> -ServerName <SQL Server Name> -DatabaseName <Database Name> -State 'Enabled'

            Note:
            • TDE cannot be used to encrypt the logical master database in SQL Database. The master database contains objects that are needed to perform the TDE operations on the user databases.
            • Azure Portal does not show master databases per SQL server. However, CLI/API responses will show master databases."

  impact 0.5
  tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.11'] }]

  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption-with-azure-sql-database'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default'
  ref 'https://learn.microsoft.com/en-us/powershell/module/az.sql/set-azsqldatabasetransparentdataencryption?view=azps-9.2.0'

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

  rg_sa_list = input('resource_groups_and_storage_accounts')

  rg_sa_list.each do |pair|
    resource_group, = pair.split('.')

    sql_servers_script = <<-EOH
      Get-AzSqlServer -ResourceGroupName "#{resource_group}" | ConvertTo-Json -Depth 10
    EOH

    sql_servers_output = powershell(sql_servers_script).stdout.strip
    sql_servers = json(content: sql_servers_output).params
    sql_servers = [sql_servers] unless sql_servers.is_a?(Array)

    sql_servers.each do |server|
      resource_group_server = server['ResourceGroupName']
      server_name = server['ServerName']

      databases_script = <<-EOH
        Get-AzSqlDatabase -ServerName "#{server_name}" -ResourceGroupName "#{resource_group_server}" | ConvertTo-Json -Depth 10
      EOH

      databases_output = powershell(databases_script).stdout.strip
      databases = json(content: databases_output).params
      databases = [databases] unless databases.is_a?(Array)

      databases.each do |db|
        db_name = db['DatabaseName']

        next if db_name.downcase == 'master'

        describe "Transparent Data Encryption for database '#{db_name}' on SQL Server '#{server_name}' (Resource Group: #{resource_group_server})" do
          tde_script = <<-EOH
            Get-AzSqlDatabaseTransparentDataEncryption -ServerName "#{server_name}" -ResourceGroupName "#{resource_group_server}" -DatabaseName "#{db_name}" | ConvertTo-Json -Depth 10
          EOH

          tde_output = powershell(tde_script).stdout.strip
          tde = json(content: tde_output).params

          it 'should have DataEncryption (TDE) enabled' do
            expect(tde['State']).to cmp 0
          end
        end
      end
    end
  end
end
