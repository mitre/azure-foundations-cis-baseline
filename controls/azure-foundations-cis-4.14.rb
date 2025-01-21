control 'azure-foundations-cis-4.14' do
    title "Ensure Storage Logging is Enabled for Table Service for 'Read', 'Write', and 'Delete' Requests"
    desc "Azure Table storage is a service that stores structured NoSQL data in the cloud,
        providing a key/attribute store with a schema-less design. Storage Logging happens
        server-side and allows details for both successful and failed requests to be recorded in
        the storage account. These logs allow users to see the details of read, write, and delete
        operations against the tables. Storage Logging log entries contain the following
        information about individual requests: timing information such as start time, end-to-end
        latency, and server latency; authentication details; concurrency information; and the
        sizes of the request and response messages."

    desc 'rationale',
        "Storage Analytics logs contain detailed information about successful and failed requests
        to a storage service. This information can be used to monitor each individual request to
        a storage service for increased security or diagnostics. Requests are logged on a best-
        effort basis.
        Storage Analytics logging is not enabled by default for your storage account."

    desc 'impact',
        "Being a level 2, enabling this setting can have a high impact on the cost of data storage
        used for logging more data per each request. Do not enable this without determining
        your need for this level of logging or forget to check in on data usage and projected
        cost."

    desc 'check',
       "From Azure Portal
        1. From the default portal page select Storage Accounts.
        2. Select the specific Storage Account.
        3. Click the Diagnostics settings under the Monitoring section in the left column.
        4. Select the 'table' tab indented below the storage account. Then select the
        diagnostic setting listed.
        5. Ensure StorageRead, StorageWrite, and StorageDelete options are selected
        under the Logging section and that they are sent to the correct destination.
        Page 223
        From Azure CLI
        Ensure the below command's output contains properties delete, read and write set to
        true.
        az storage logging show --services t --account-name <storageAccountName>
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 2fb86bf3-d221-43d1-96d1-2434af34eaa0 - Name: 'Configure
        diagnostic settings for Table Services to Log Analytics workspace'"

    desc 'fix',
       "From Azure Portal
        1. From the default portal page select Storage Accounts.
        2. Select the specific Storage Account.
        3. Click the Diagnostics settings under the Monitoring section in the left column.
        4. Select the 'table' tab indented below the storage account.
        5. Click '+ Add diagnostic setting'.
        6. Select StorageRead, StorageWrite and StorageDelete options under the Logging
        section to enable Storage Logging for Table service.
        7. Select a destination for your logs to be sent to.
        From Azure CLI
        Use the below command to enable the Storage Logging for Table service.
        az storage logging update --account-name <storageAccountName> --account-key
        <storageAccountKey> --services t --log rwd --retention 90"    

    impact 0.5
    tag nist: ['AU-3','AU-3(1)','AU-7','AU-12']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['8.5'] }]

    ref 'https://docs.microsoft.com/en-us/rest/api/storageservices/about-storage-analytics-logging'
    ref 'https://docs.microsoft.com/en-us/cli/azure/storage/logging?view=azure-cli-latest'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'

    describe 'benchmark' do
        skip 'configure'
    end
end