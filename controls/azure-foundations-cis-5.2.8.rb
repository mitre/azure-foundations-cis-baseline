control 'azure-foundations-cis-5.2.8' do
  title "[LEGACY] Ensure 'Infrastructure double encryption' for PostgreSQL single server is 'Enabled'"
  desc "Azure Database for PostgreSQL servers should be created with 'infrastructure double encryption' enabled.
        NOTE: This recommendation currently only applies to Single Server, not Flexible Server. See additional information below for details about the planned retirement of Azure PostgreSQL Single Server."

  desc 'rationale',
       'If Double Encryption is enabled, another layer of encryption is implemented at the hardware level before the storage or network level. Information will be encrypted before it is even accessed, preventing both interception of data in motion if the network layer encryption is broken and data at rest in system resources such as memory or processor cache. Encryption will also be in place for any backups taken of the database, so the key will secure access the data in all forms. For the most secure implementation of key based encryption, it is recommended to use a Customer Managed asymmetric RSA 2048 Key in Azure Key Vault.'

  desc 'impact',
       'The read and write speeds to the database will be impacted if both default encryption and Infrastructure Encryption are checked, as a secondary form of encryption requires more resource overhead for the cryptography of information. This cost is justified for information security. Customer managed keys are recommended for the most secure implementation, leading to overhead of key management. The key will also need to be backed up in a secure location, as loss of the key will mean loss of the information in the database.'

  desc 'check',
       "Audit from Azure Portal
            1. From Azure Home, click on more services.
            2. Click on Databases.
            3. Click on Azure Database for PostgreSQL servers.
            4. Select the database by clicking on its name.
            5. Under Security, click Data encryption.
            6. Ensure that Infrastructure encryption enabled is displayed and is checked.
        Audit from Azure CLI
            1. Enter the command
                az postgres server configuration show --name <servername> --resource-group <resourcegroup> --query 'properties.infrastructureEncryption' -o tsv
            2. Verify that Infrastructure encryption is enabled.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 24fba194-95d6-48c0-aea7-f65bf859c598 - Name: 'Infrastructure encryption should be enabled for Azure Database for PostgreSQL servers'"

  desc 'fix',
       "It is not possible to enable 'infrastructure double encryption' on an existing Azure Database for PostgreSQL server. The remediation steps detail the creation of a new Azure Database for PostgreSQL server with 'infrastructure double encryption' enabled.
       Remediate from Azure Portal
            1. Go through the normal process of database creation.
            2. On step 2 titled Additional settings ensure that Infrastructure double encryption enabled is checked.
            3. Acknowledge that you understand this will impact database performance.
            4. Finish database creation as normal.
        Remediate from Azure CLI
            az postgres server create --resource-group <resourcegroup> --name <servername> --location <location> --admin-user <adminusername> --admin-password <server_admin_password> --sku-name GP_Gen4_2 --version 11 --infrastructure-encryption Enabled"

  impact 0.5
  tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.11'] }]

  ref 'https://docs.microsoft.com/en-us/azure/postgresql/howto-double-encryption'
  ref 'https://docs.microsoft.com/en-us/azure/postgresql/concepts-infrastructure-double-encryption'
  ref 'https://docs.microsoft.com/en-us/azure/postgresql/concepts-data-encryption-postgresql'
  ref 'https://docs.microsoft.com/en-us/azure/key-vault/keys/byok-specification'
  ref 'https://docs.microsoft.com/en-us/azure/postgresql/howto-double-encryption'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default'

  only_if('N/A - Control applicable only if using PostgreSQL single server', impact: 0) do
    input('postgresql_single_server')
  end

  describe "[LEGACY] Ensure 'Infrastructure double encryption' for PostgreSQL single server is 'Enabled'" do
    skip 'The check for this control needs to be done manually'
  end
end
