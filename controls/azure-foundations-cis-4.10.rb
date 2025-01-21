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
        recoverable for a particular time which is set in the 'Retention policies,'' ranging from 7
        days to 365 days."

    check 'impact',
        "Additional storage costs may be incurred as snapshots are retained."

    desc 'check',
       "From Azure Portal:
        1. From the Azure home page, open the hamburger menu in the top left or click on
        the arrow pointing right with 'More services' underneath.
        2. Select Storage.
        3. Select Storage Accounts.
        4. For each Storage Account, navigate to Data protection in the left scroll column.
        5. Ensure that soft delete is checked for both blobs and containers. Also check if
        the retention period is a sufficient length for your organization.
        From Azure CLI
        Blob Storage: Ensure that the output of the below command contains enabled status as
        true and days is not empty or null
        az storage blob service-properties delete-policy show --account-name
        <StorageAccountName> --account-key <accountkey>
        Page 214
        Azure Containers: Make certain that the --enable-container-delete-retention is 'true'.
        az storage account blob-service-properties show
        --account-name <StorageAccountName>
        --account-key <accountkey>
        --resource-group <resource_group>
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: ea39f60f-9f00-473c-8604-be5eac4bb088 - Name: 'Configure blob soft
        delete on a storage account'"

    desc 'fix',
       "From Azure Portal
        1. From the Azure home page, open the hamburger menu in the top left or click on
        the arrow pointing right with 'More services' underneath.
        2. Select Storage.
        3. Select Storage Accounts.
        4. For each Storage Account, navigate to Data protection in the left scroll column.
        5. Check soft delete for both blobs and containers. Set the retention period to a
        sufficient length for your organization.
        From Azure CLI
        Update blob storage retention days in below command
        az storage blob service-properties delete-policy update --days-retained
        <RetentionDaysValue> --account-name <StorageAccountName> --account-key
        <AccountKey> --enable true
        Update container retention with the below command
        az storage account blob-service-properties update
        --enable-container-delete-retention true
        --container-delete-retention-days <days>
        --account-name <storage-account>
        --resource-group <resource_group>
        --account-key <AccountKey>"

    impact 0.5
    tag nist: ['CP-2','CP-10']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['11.1'] }]

    ref 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-soft-delete'
    ref 'https://docs.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-overview'
    ref 'https://docs.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-enable?tabs=azure-portal'

    describe 'benchmark' do
        skip 'configure'
    end
end