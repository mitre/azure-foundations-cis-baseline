control 'azure-foundations-cis-4.5' do
  title 'Ensure that Shared Access Signature Tokens Expire Within an Hour'
  desc 'Expire shared access signature tokens within an hour.'

  desc 'rationale',
       "A shared access signature (SAS) is a URI that grants restricted access rights to Azure
        Storage resources. A shared access signature can be provided to clients who should
        not be trusted with the storage account key but for whom it may be necessary to
        delegate access to certain storage account resources. Providing a shared access
        signature URI to these clients allows them access to a resource for a specified period of
        time. This time should be set as low as possible and preferably no longer than an hour."

  desc 'check',
       "Currently, SAS token expiration times cannot be audited. Until Microsoft makes token
        expiration time a setting rather than a token creation parameter, this recommendation
        would require a manual verification."

  desc 'fix',
       "When generating shared access signature tokens, use start and end time such that it
        falls within an hour.
        Remediate from Azure Portal
        1. Go to Storage Accounts
        2. For each storage account where a shared access signature is required, under
        Security + networking, go to Shared access signature
        3. Select the appropriate Allowed resource types
        4. Set the Start and expiry date/time to be within one hour
        5. Click Generate SAS and connection string"

  impact 0.5
  tag nist: ['AC-1', 'AC-2', 'AC-2(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['6.2'] }]

  ref 'https://docs.microsoft.com/en-us/rest/api/storageservices/delegating-access-with-a-shared-access-signature'
  ref 'https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview'

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

  only_if('N/A - No Storage Accounts found (accounts may have been manually excluded)', impact: 0) do
    !rg_sa_list.empty?
  end

  describe 'Ensure that Shared Access Signature Tokens Expire Within an Hour' do
    skip 'The check for this control needs to be done manually'
  end
end
