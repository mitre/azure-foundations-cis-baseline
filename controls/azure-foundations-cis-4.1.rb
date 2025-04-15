control 'azure-foundations-cis-4.1' do
  title "Ensure that 'Secure transfer required' is set to 'Enabled'"
  desc 'Enable data encryption in transit.'

  desc 'rationale',
       "The secure transfer option enhances the security of a storage account by only allowing
        requests to the storage account by a secure connection. For example, when calling
        REST APIs to access storage accounts, the connection must use HTTPS. Any requests
        using HTTP will be rejected when 'secure transfer required' is enabled. When using the
        Azure files service, connection without encryption will fail, including scenarios using
        SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client.
        Because Azure storage doesn’t support HTTPS for custom domain names, this option is
        not applied when using a custom domain name."

  desc 'check',
       "From Azure Portal
        1. Go to Storage Accounts
        2. For each storage account, go to Configuration
        3. Ensure that Secure transfer required is set to Enabled
        From Azure CLI
        Use the below command to ensure the Secure transfer required is enabled for all the
        Storage Accounts by ensuring the output contains true for each of the Storage
        Accounts.
        az storage account list --query '[*].[name,enableHttpsTrafficOnly]'
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 404c3081-a854-4457-ae30-26a93ef643f9 - Name: 'Secure transfer to
        storage accounts should be enabled'"

  desc 'fix',
       "Remediate from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Settings, click Configuration.
        3. Set Secure transfer required to Enabled.
        4. Click Save.
        Remediate from Azure CLI
        Use the below command to enable Secure transfer required for a Storage
        Account
        az storage account update --name <storageAccountName> --resource-group
        <resourceGroupName> --https-only true"

  impact 0.5
  tag nist: ['AC-17(2)', 'IA-5', 'IA-5(1)', 'SC-8', 'SC-8(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.10'] }]

  ref 'https://docs.microsoft.com/en-us/azure/storage/blobs/security-recommendations#encryption-in-transit'
  ref 'https://docs.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest#az_storage_account_list'
  ref 'https://docs.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest#az_storage_account_update'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-3-encrypt-sensitive-data-in-transit'

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

    script = <<-EOH
      az storage account list --query "[*].[name,enableHttpsTrafficOnly]"
    EOH

    output = powershell(script).stdout.strip
    accounts = json(content: output).params

    failed_accounts = accounts.reject do |account|
      account[1] == true
    end.map { |account| account[0] }

    describe 'Storage Accounts secure transfer enforcement' do
      it 'ensures that all storage accounts have secure transfer enabled' do
        expect(failed_accounts).to be_empty, "The following storage accounts do not have secure transfer enabled: #{failed_accounts.join(', ')}"
      end
    end
  end
end
