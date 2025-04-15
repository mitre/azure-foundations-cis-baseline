control 'azure-foundations-cis-4.2' do
  title 'Ensure that ‘Enable Infrastructure Encryption’ for Each Storage Account in Azure Storage is Set to ‘enabled'
  desc "Enabling encryption at the hardware level on top of the default software encryption for
        Storage Accounts accessing Azure storage solutions."

  desc 'rationale',
       "Azure Storage automatically encrypts all data in a storage account at the network level
        using 256-bit AES encryption, which is one of the strongest, FIPS 140-2-compliant block
        ciphers available. Customers who require higher levels of assurance that their data is
        secure can also enable 256-bit AES encryption at the Azure Storage infrastructure level
        for double encryption. Double encryption of Azure Storage data protects against a
        scenario where one of the encryption algorithms or keys may be compromised.
        Similarly, data is encrypted even before network transmission and in all backups. In this
        scenario, the additional layer of encryption continues to protect your data. For the most
        secure implementation of key based encryption, it is recommended to use a Customer
        Managed asymmetric RSA 2048 Key in Azure Key Vault."

  desc 'impact',
       "The read and write speeds to the storage will be impacted if both default encryption and
        Infrastructure Encryption are checked, as a secondary form of encryption requires more
        resource overhead for the cryptography of information. This performance impact should
        be considered in an analysis for justifying use of the feature in your environment.
        Customer-managed keys are recommended for the most secure implementation,
        leading to overhead of key management. The key will also need to be backed up in a
        secure location, as loss of the key will mean loss of the information in the storage."

  desc 'check',
       "From Azure Portal
        1. From Azure Portal select the portal menu in the top left.
        2. Select Storage Accounts.
        3. Click on each storage account within each resource group you wish to audit.
        4. In the overview, under Security, ensure Infrastructure encryption is set to
        Enabled.
        From Azure CLI
        az storage blob show \
        --account-name <storage-account> \
        --container-name <container> \
        --name <blob> \
        --query 'properties.serverEncrypted'
        From PowerShell
        $account = Get-AzStorageAccount -ResourceGroupName <resource-group> `
        -Name <storage-account>
        $blob = Get-AzStorageBlob -Context $account.Context `
        -Container <container> `
        -Blob <blob>
        $blob.ICloudBlob.Properties.IsServerEncrypted
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 4733ea7b-a883-42fe-8cac-97454c2a9e4a - Name: 'Storage accounts
        should have infrastructure encryption'"

  desc 'fix',
       "From Azure Portal
        1. During Storage Account creation, in the Encryption tab, check the box next to
        Enable infrastructure encryption.
        From Azure CLI
        Replace the information within <> with appropriate values:
        az storage account create \
        --name <storage-account> \
        --resource-group <resource-group> \
        --location <location> \
        --sku Standard_RAGRS \
        --kind StorageV2 \
        --require-infrastructure-encryption
        From PowerShell
        Replace the information within <> with appropriate values:
        New-AzStorageAccount -ResourceGroupName <resource_group> `
        -AccountName <storage-account> `
        -Location <location> `
        -SkuName 'Standard_RAGRS' `
        -Kind StorageV2 `
        -RequireInfrastructureEncryption
        Enabling Infrastructure Encryption after Storage Account Creation
        If infrastructure encryption was not enabled on blob storage creation, there is no official
        way to enable it. Please see the additional information section."

  impact 0.5
  tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.11'] }]

  ref 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-encryption-status'
  ref 'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption'
  ref 'https://docs.microsoft.com/en-us/azure/storage/common/infrastructure-encryption-enable'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default'

  storage_script = 'Get-AzStorageAccount | ConvertTo-Json'
  storage_output = powershell(storage_script).stdout.strip
  all_storage = json(content: storage_output).params

  only_if('N/A - No Storage Accounts found', impact: 0) do
    case all_storage
    when Array
      !all_storage.empty?
    when Hash
      !all_storage.empty?
    else
      false
    end
  end

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

    query = command('az storage account list --query "[?encryption.requireInfrastructureEncryption==\`false\`].{Name:name}" --output tsv').stdout

    describe "Ensure that the number of storage accounts with InfrastructureEncryption setting set to 'False" do
      subject { query }
      it 'is 0' do
        failure_message = "The following storage accounts have InfrastructureEncryption set to 'False':\n#{query}"
        expect(subject).to be_empty, failure_message
      end
    end
  end
end
