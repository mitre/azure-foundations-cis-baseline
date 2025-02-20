control 'azure-foundations-cis-6.1.3' do
    title 'Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key (CMK)'
    desc "Storage accounts with the activity log exports can be configured to use Customer Managed Keys (CMK)."

    desc 'rationale',
        "Configuring the storage account with the activity log export container to use CMKs provides additional confidentiality controls on log data, as a given user must have read permission on the corresponding storage account and must be granted decrypt permission by the CMK."

    desc 'impact',
        'NOTE: You must have your key vault setup to utilize this. All Audit Logs will be encrypted with a key you provide. You will need to set up customer managed keys separately, and you will select which key to use via the instructions here. You will be responsible for the lifecycle of the keys, and will need to manually replace them at your own determined intervals to keep the data secure.'

    desc 'check',
       "%(Audit from Azure Portal
            1. Go to Monitor.
            2. Select Activity log.
            3. Select Export Activity Logs.
            4. Select a Subscription.
            5. Note the name of the Storage Account for the diagnostic setting.
            6. Navigate to Storage accounts.
            7. Click on the storage account name noted in Step 5.
            8. Under Security + networking, click Encryption.
            9. Ensure Customer-managed keys is selected and a key is set.
        Audit from Azure CLI
            1. Get storage account id configured with log profile: 
                az monitor diagnostic-settings subscription list --subscription <subscription id> --query 'value[*].storageAccountId'
            2. Ensure the storage account is encrypted with CMK: 
                az storage account list --query '[?name=='<Storage Account Name>']'
            In command output ensure keySource is set to Microsoft.Keyvault and keyVaultProperties is not set to null
        Audit from PowerShell 
            Get-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name>|select-object -ExpandProperty encryption|format-list
            Ensure the value of KeyVaultProperties is not null or empty, and ensure KeySource is not set to Microsoft.Storage.
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: fbb99e8e-e444-4da0-9ff1-75c92f5a85b2 - Name: 'Storage account containing the container with activity logs must be encrypted with BYOK')"

    desc 'fix',
       "Remediate from Azure Portal
            1. Go to Monitor.
            2. Select Activity log.
            3. Select Export Activity Logs.
            4. Select a Subscription.
            5. Note the name of the Storage Account for the diagnostic setting.
            6. Navigate to Storage accounts.
            7. Click on the storage account.
            8. Under Security + networking, click Encryption.
            9. Next to Encryption type, select Customer-managed keys.
            10. Complete the steps to configure a customer-managed key for encryption of the storage account.
        Remediate from Azure CLI 
            az storage account update --name <name of the storage account> --resource-group <resource group for a storage account> --encryption-key-source=Microsoft.Keyvault --encryption-key-vault <Key Vault URI> --encryption-key-name <KeyName> --encryption-key-version <Key Version>
        Remediate from PowerShell
            Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -KeyvaultEncryption -KeyVaultUri <key vault URI> -KeyName <key name>"

    impact 0.5
    tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['3.11'] }]

    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required'
    ref 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=cli#managing-legacy-log-profiles'

    rg_sa_list = input('resource_groups_and_storage_accounts')

    rg_sa_list.each do |pair|
        resource_group, storage_account = pair.split('.')

        describe "Encryption settings for Storage Account '#{storage_account}' in Resource Group '#{resource_group}'" do
            storage_accounts = json(command: "az storage account list --resource-group #{resource_group} --query \"[?name=='#{storage_account}']\" -o json").params

            encryption = storage_accounts.first['encryption']

            describe "KeySource for '#{storage_account}'" do
                it "should be set to 'Microsoft.Keyvault'" do
                    expect(encryption['keySource']).to cmp 'Microsoft.Keyvault'
                end
            end

            describe "KeyVaultProperties for '#{storage_account}'" do
                it 'should not be null' do
                    expect(encryption['keyVaultProperties']).not_to be_nil
            end

            it 'should not be empty' do
                    expect(encryption['keyVaultProperties'].to_s.strip).not_to eq ''
                end
            end
        end
    end
end