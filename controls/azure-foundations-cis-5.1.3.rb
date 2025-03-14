control 'azure-foundations-cis-5.1.3' do
  title "Ensure SQL server's Transparent Data Encryption (TDE) protector is encrypted with Customer-managed key"
  desc "Transparent Data Encryption (TDE) with Customer-managed key support provides increased transparency and control over the TDE Protector, increased security with an HSM-backed external service, and promotion of separation of duties.
        With TDE, data is encrypted at rest with a symmetric key (called the database encryption key) stored in the database or data warehouse distribution. To protect this data encryption key (DEK) in the past, only a certificate that the Azure SQL Service managed could be used. Now, with Customer-managed key support for TDE, the DEK can be protected with an asymmetric key that is stored in the Azure Key Vault. The Azure Key Vault is a highly available and scalable cloud-based key store which offers central key management, leverages FIPS 140-2 Level 2 validated hardware security modules (HSMs), and allows separation of management of keys and data for additional security.
        Based on business needs or criticality of data/databases hosted on a SQL server, it is recommended that the TDE protector is encrypted by a key that is managed by the data owner (Customer-managed key)."

  desc 'rationale',
       'Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure’s cloud-based external key management system, is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.'

  desc 'impact',
       'Once TDE protector is encrypted with a Customer-managed key, it transfers entire responsibility of respective key management on to you, and hence you should be more careful about doing any operations on the particular key in order to keep data from corresponding SQL server and Databases hosted accessible.
        When deploying Customer Managed Keys, it is prudent to ensure that you also deploy an automated toolset for managing these keys (this should include discovery and key rotation), and Keys should be stored in an HSM or hardware backed keystore, such as Azure Key Vault.
        As far as toolsets go, check with your cryptographic key provider, as they may well provide one as an add-on to their service.'

  desc 'check',
       "%(Audit from Azure Portal
            1. Go to SQL servers
            2. For each SQL server, under Security, click Transparent data encryption
            3. Ensure that Customer-managed key is selected
            4. Ensure Make this key the default TDE protector is checked
        Audit from Azure CLI
            az account get-access-token --query '{subscripton:subscription,accessToken:accessToken}' --out tsv | xargs -L1 bash -c 'curl -X GET -H 'Authorization: Bearer $1' -H 'Content-Type: application/json' https://management.azure.com/subscriptions/$0/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/encryptionProtector?api-version=2015-05-01-preview'
            Ensure the output of the command contains properties kind set to azurekeyvault serverKeyType set to AzureKeyVault uri is not null
        Audit from PowerShell
            Get-AzSqlServerTransparentDataEncryptionProtector -ServerName <ServerName> -ResourceGroupName <ResourceGroupName>
            Ensure the output of the command contains properties Type set to AzureKeyVault ServerKeyVaultKeyName set to KeyVaultName_KeyName_KeyIdentifierVersion KeyId set to KeyIdentifier
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 0a370ff3-6cab-4e85-8995-295fd854c5b8 - Name: 'SQL servers should use customer-managed keys to encrypt data at rest'
                • Policy ID: ac01ad65-10e5-46df-bdd9-6b0cad13e1d2 - Name: 'SQL managed instances should use customer-managed keys to encrypt data at rest')"

  desc 'fix',
       "Remediate from Azure Portal
            1. Go to SQL servers
            2. For each SQL server, under Security, click Transparent data encryption
            3. Set Transparent data encryption to Customer-managed key
            4. Select a key or enter a key identifier
            5. Check Make this key the default TDE protector
            6. Click Save
        Remediate from Azure CLI
            Use the below command to encrypt SQL server's TDE protector with a Customer-managed key
                az sql server tde-key set --resource-group <resourceName> --server <dbServerName> --server-key-type {AzureKeyVault} --kid <keyIdentifier>
        Remediate from PowerShell
            Use the below command to encrypt SQL server's TDE protector with a Customer-managed Key Vault key
                Set-AzSqlServerTransparentDataEncryptionProtector -Type AzureKeyVault -KeyId <KeyIdentifier> -ServerName <ServerName> -ResourceGroupName <ResourceGroupName>
            Select Y when prompted"

  impact 0.5
  tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.11'] }]

  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption-byok-azure-sql'
  ref 'https://azure.microsoft.com/en-in/blog/preview-sql-transparent-data-encryption-tde-with-bring-your-own-key-support/'
  ref 'https://winterdom.com/2017/09/07/azure-sql-tde-protector-keyvault'
  ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required'
  ref 'https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts'
  ref 'https://docs.microsoft.com/en-us/cli/azure/sql/server/tde-key?view=azure-cli-latest'
  ref 'https://learn.microsoft.com/en-us/powershell/module/az.sql/get-azsqlservertransparentdataencryptionprotector?view=azps-9.2.0'
  ref 'https://learn.microsoft.com/en-us/powershell/module/az.sql/set-azsqlservertransparentdataencryptionprotector?view=azps-9.2.0'

  expected_full_keys = input('key_vault_full_key_uri')

  expected_values = expected_full_keys.map do |full_uri|
    match = full_uri.match(%r{https://(.*)\.vault\.azure\.net/keys/([^/]+)/([^/]+)})
    next unless match

    key_vault_name = match[1]
    key_name = match[2]
    key_version = match[3]
    {
      'ServerKeyVaultKeyName' => "#{key_vault_name}_#{key_name}_#{key_version}",
      'KeyId' => full_uri
    }
  end.compact

  sql_servers_script = <<-EOH
    Get-AzSqlServer | ConvertTo-Json -Depth 10
  EOH

  sql_servers_output = powershell(sql_servers_script).stdout.strip
  sql_servers = json(content: sql_servers_output).params
  sql_servers = [sql_servers] unless sql_servers.is_a?(Array)

  sql_servers.each do |server|
    resource_group = server['ResourceGroupName']
    server_name = server['ServerName']

    describe "Transparent Data Encryption Protector for SQL Server #{server_name} (Resource Group: #{resource_group})" do
      tde_script = <<-EOH
        Get-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName "#{resource_group}" -ServerName "#{server_name}" | ConvertTo-Json -Depth 10
      EOH

      tde_output = powershell(tde_script).stdout.strip
      tde = json(content: tde_output).params

      it "should have Type set to 'AzureKeyVault'" do
        expect(tde['Type']).to cmp 0
      end

      it 'should have ServerKeyVaultKeyName in one of the allowed formats' do
        allowed_names = expected_values.map { |v| v['ServerKeyVaultKeyName'] }
        expect(allowed_names).to include(tde['ServerKeyVaultKeyName'])
      end

      it 'should have KeyId in one of the allowed formats' do
        allowed_ids = expected_values.map { |v| v['KeyId'] }
        expect(allowed_ids).to include(tde['KeyId'])
      end
    end
  end
end
