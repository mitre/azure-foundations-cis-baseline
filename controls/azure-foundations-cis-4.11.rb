control 'azure-foundations-cis-4.11' do
  title 'Ensure Storage for Critical Data are Encrypted with Customer Managed Keys (CMK)'
  desc "Enable sensitive data encryption at rest using Customer Managed Keys (CMK) rather
        than Microsoft Managed keys."

  desc 'rationale',
       "By default, data in the storage account is encrypted using Microsoft Managed Keys at
        rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues,
        and tables. All object metadata is also encrypted. If you want to control and manage this
        encryption key yourself, however, you can specify a customer-managed key. That key is
        used to protect and control access to the key that encrypts your data. You can also
        choose to automatically update the key version used for Azure Storage encryption
        whenever a new version is available in the associated Key Vault.
        While it is possible to automate the assessment of this recommendation, the
        assessment status for this recommendation remains 'Manual.' This is because the
        recommendation pertains to storage accounts that store critical data and is therefore not
        applicable to all storage accounts."

  desc 'impact',
       "If the key expires by setting the 'activation date' and 'expiration date', the user must
        rotate the key manually.
        Using Customer Managed Keys may also incur additional man-hour requirements to
        create, store, manage, and protect the keys as needed."

  desc 'check',
       "From Azure Console:
        1. Go to Storage Accounts
        2. For each storage account, go to Encryption
        3. Ensure that Encryption type is set to Customer Managed Keys
        From PowerShell
        Connect-AzAccount
        Set-AzContext -Subscription <subscription id>
        Get-AzStorageAccount |Select-Object -ExpandProperty Encryption
        PowerShell Results - Non-Compliant
        ...
        KeySource : Microsoft.Storage
        ...
        PowerShell Results - Compliant
        ...
        KeySource : Microsoft.Keyvault
        ...
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 6fac406b-40ca-413b-bf8e-0bf964659c25 - Name: 'Storage accounts
        should use customer-managed key for encryption'"

  desc 'fix',
       "Remediate from Azure Portal
        1. Go to Storage Accounts
        2. For each storage account, under Security + networking, go to Encryption
        3. Set Encryption type to Customer-managed keys
        4. Select an encryption key or enter a key URI
        5. Click Save"

  impact 0.5
  tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.11'] }]

  ref 'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption'
  ref 'https://docs.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices#protect-data-at-rest'
  ref 'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption#azure-storage-encryption-versus-disk-encryption'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required'

  storage_script = 'Get-AzStorageAccount | ConvertTo-Json'
  storage_output = powershell(storage_script).stdout.strip
  all_storage = json(content: storage_output).params

  only_if('N/A - No Storage Accounts found', impact: 0) do
    !all_storage.empty?
  end

  subscription_id = input('subscription_id')
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
      skip 'N/A - No storage accounts found or accounts have been manually excluded'
    end
  else

    rg_sa_list.each do |pair|
      resource_group, storage_account = pair.split('.')

      describe "Encryption configuration for Storage Account '#{storage_account}' in Resource Group '#{resource_group}'" do
        script = <<-EOH
                $ErrorActionPreference = "Stop"
                (Get-AzStorageAccount -ResourceGroupName "#{resource_group}" -Name "#{storage_account}").Encryption.KeySource
        EOH

        pwsh_output = powershell(script)
        raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

        describe pwsh_output do
          its('stdout.strip') { should cmp 'Microsoft.Keyvault' }
        end
      end
    end
  end
end
