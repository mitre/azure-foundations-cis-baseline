control 'azure-foundations-cis-4.10' do
    title "Ensure Soft Delete is Enabled for Azure Containers and Blob Storage"
    desc "The Azure Storage blobs contain data like ePHI or Financial, which can be secret or
        personal. Data that is erroneously modified or deleted by an application or other storage
        account user will cause data loss or unavailability.
        It is recommended that both Azure Containers with attached Blob Storage and
        standalone containers with Blob Storage be made recoverable by enabling the soft
        delete configuration. This is to save and recover data when blobs or blob snapshots are
        deleted."

    desc 'rationale',
        "Containers and Blob Storage data can be incorrectly deleted. An attacker/malicious
        user may do this deliberately in order to cause disruption. Deleting an Azure Storage
        blob causes immediate data loss. Enabling this configuration for Azure storage ensures
        that even if blobs/data were deleted from the storage account, Blobs/data objects are
        recoverable for a particular time which is set in the 'Retention policies,' ranging from 7
        days to 365 days."

    desc 'impact',
        "Additional storage costs may be incurred as snapshots are retained."

    desc 'check',
       "Audit from Azure Portal
        1. Go to Storage Accounts.
        2. For each Storage Account, under Data management, go to Data protection.
        3. Ensure that Enable soft delete for blobs is checked.
        4. Ensure that Enable soft delete for containers is checked.
        5. Ensure that the retention period for both is a sufficient length for your
        organization.
        Audit from Azure CLI
        Blob Storage: Ensure that the output of the below command contains enabled status as
        true and days is not empty or null
        az storage blob service-properties delete-policy show
        --account-name <storageAccount>
        --account-key <accountkey>
        Azure Containers: Ensure that within containerDeleteRetentionPolicy, the
        enabled property is set to true.
        az storage account blob-service-properties show
        --account-name <storageAccount>
        --resource-group <resourceGroup>"

    desc 'fix',
       "Remediate from Azure Portal
        1. Go to Storage Accounts.
        2. For each Storage Account, under Data management, go to Data protection.
        3. Check the box next to Enable soft delete for blobs.
        4. Check the box next to Enable soft delete for containers.
        5. Set the retention period for both to a sufficient length for your organization.
        6. Click Save.
        Remediate from Azure CLI
        Update blob storage retention days in below command
        az storage blob service-properties delete-policy update --days-retained
        <RetentionDaysValue> --account-name <StorageAccountName> --account-key
        <AccountKey> --enable true
        Update container retention with the below command
        az storage account blob-service-properties update
        --enable-container-delete-retention true
        --container-delete-retention-days <days>
        --account-name <storageAccount>
        --resource-group <resourceGroup>"

    impact 0.5
    tag nist: ['CP-2','CP-10']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['11.1'] }]

    ref 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-soft-delete'
    ref 'https://docs.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-overview'
    ref 'https://docs.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-enable?tabs=azure-portal'

    subscription_id = input('subscription_id')
    rg_sa_list = input('resource_groups_and_storage_accounts')

    rg_sa_list.each do |pair|
        resource_group, storage_account = pair.split('.')

        describe "Encryption configuration for Storage Account '#{storage_account}' in Resource Group '#{resource_group}'" do
            script = <<-EOH
                Set-AzContext -Subscription #{subscription_id} | Out-Null
                (Get-AzStorageAccount -ResourceGroupName "#{resource_group}" -Name "#{storage_account}").Encryption.KeySource
            EOH

            describe powershell(script) do
                its('stdout.strip') { should cmp 'Microsoft.Keyvault' }
            end
        end
    end
end