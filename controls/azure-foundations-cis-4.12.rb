control 'azure-foundations-cis-4.12' do
  title "Ensure Storage Logging is Enabled for Queue Service for 'Read', 'Write', and 'Delete' requests"
  desc "The Storage Queue service stores messages that may be read by any client who has
        access to the storage account. A queue can contain an unlimited number of messages,
        each of which can be up to 64KB in size using version 2011-08-18 or newer. Storage
        Logging happens server-side and allows details for both successful and failed requests
        to be recorded in the storage account. These logs allow users to see the details of read,
        write, and delete operations against the queues. Storage Logging log entries contain the
        following information about individual requests: Timing information such as start time,
        end-to-end latency, and server latency, authentication details, concurrency information,
        and the sizes of the request and response messages."

  desc 'rationale',
       "Storage Analytics logs contain detailed information about successful and failed requests
        to a storage service. This information can be used to monitor individual requests and to
        diagnose issues with a storage service. Requests are logged on a best-effort basis.
        Storage Analytics logging is not enabled by default for your storage account."

  desc 'impact',
       "Enabling this setting can have a high impact on the cost of the log analytics service and
        data storage used by logging more data per each request. Do not enable this without
        determining your need for this level of logging, and do not forget to check in on data
        usage and projected cost. Some users have seen their logging costs increase from $10
        per month to $10,000 per month."

  desc 'check',
       "Audit from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Monitoring, click Diagnostics settings.
        3. Select the queue tab indented below the storage account.
        4. Ensure that at least one diagnostic setting is listed.
        5. Click Edit setting on a diagnostic setting.
        6. Ensure that at least one diagnostic setting has StorageRead, StorageWrite,
        and StorageDelete options selected under the Logs section and that they are
        sent to an appropriate destination.
        Audit from Azure CLI
        Ensure the below command's output contains properties delete, read and write set to
        true.
        az storage logging show --services q --account-name <storageAccountName>
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 7bd000e3-37c7-4928-9f31-86c4b77c5c45 - Name: 'Configure
        diagnostic settings for Queue Services to Log Analytics workspace'"

  desc 'fix',
       "Remediate from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Monitoring, click Diagnostics settings.
        3. Select the queue tab indented below the storage account.
        4. To create a new diagnostic setting, click + Add diagnostic setting. To
        update an existing diagnostic setting, click Edit setting on the diagnostic
        setting.
        5. Check the boxes next to StorageRead, StorageWrite, and StorageDelete.
        6. Select an appropriate destination.
        7. Click Save.
        Remediate from Azure CLI
        Use the below command to enable the Storage Logging for Queue service.
        az storage logging update --account-name <storageAccountName> --account-key
        <storageAccountKey> --services q --log rwd --retention 90"

  impact 0.5
  tag nist: ['AU-3', 'AU-3(1)', 'AU-7', 'AU-12']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['8.5'] }]

  ref 'https://docs.microsoft.com/en-us/rest/api/storageservices/about-storage-analytics-logging'
  ref 'https://docs.microsoft.com/en-us/rest/api/storageservices/about-storage-analytics-logging'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-4-enable-network-logging-for-security-investigation'
  ref 'https://docs.microsoft.com/en-us/azure/storage/queues/monitor-queue-storage?tabs=azure-portal'

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

    rg_sa_list.each do |pair|
      resource_group, storage_account = pair.split('.')

      output = json(command: "az storage logging show --services q --account-name #{storage_account}").params

      describe 'Storage Queue Logging Settings' do
        subject { output['queue'] }
        it 'has delete logging enabled' do
          expect(subject['delete']).to cmp true
        end
        it 'has read logging enabled' do
          expect(subject['read']).to cmp true
        end
        it 'has write logging enabled' do
          expect(subject['write']).to cmp true
        end
      end
    end
  end
end
