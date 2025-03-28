control 'azure-foundations-cis-4.15' do
  title "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'"
  desc "In some cases, Azure Storage sets the minimum TLS version to be version 1.0 by
        default. TLS 1.0 is a legacy version and has known vulnerabilities. This minimum TLS
        version can be configured to be later protocols such as TLS 1.2."

  desc 'rationale',
       "TLS 1.0 has known vulnerabilities and has been replaced by later versions of the TLS
        protocol. Continued use of this legacy protocol affects the security of data in transit."

  desc 'impact',
       "When set to TLS 1.2 all requests must leverage this version of the protocol. Applications
        leveraging legacy versions of the protocol will fail."

  desc 'check',
       "Audit from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Settings, click Configuration.
        3. Ensure that the Minimum TLS version is set to Version 1.2.
        Audit from Azure CLI
        Get a list of all storage accounts and their resource groups
        az storage account list | jq '.[] | {name, resourceGroup}'
        Then query the minimumTLSVersion field
        az storage account show \
        --name <storage-account> \
        --resource-group <resource-group> \
        --query minimumTlsVersion \
        --output tsv
        Audit from PowerShell
        To get the minimum TLS version, run the following command:
        (Get-AzStorageAccount -Name <STORAGEACCOUNTNAME> -ResourceGroupName
        <RESOURCEGROUPNAME>).MinimumTlsVersion
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: fe83a0eb-a853-422d-aac2-1bffd182c5d0 - Name: 'Storage accounts
        should have the specified minimum TLS version'"

  desc 'fix',
       "Remediate from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Settings, click Configuration.
        3. Set the Minimum TLS version to Version 1.2.
        4. Click Save.
        Remediate from Azure CLI
        az storage account update \
        --name <storage-account> \
        --resource-group <resource-group> \
        --min-tls-version TLS1_2
        Remediate from PowerShell
        To set the minimum TLS version, run the following command:
        Set-AzStorageAccount -AccountName <STORAGEACCOUNTNAME> `
        -ResourceGroupName <RESOURCEGROUPNAME> `
        -MinimumTlsVersion TLS1_2"

  impact 0.5
  tag nist: ['AC-17(2)', 'IA-5', 'IA-5(1)', 'SC-8', 'SC-8(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.10'] }]

  ref 'https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version?tabs=portal'
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

  subscription_id = input('subscription_id')
  rg_sa_list = input('resource_groups_and_storage_accounts')

  rg_sa_list.each do |pair|
    resource_group, storage_account = pair.split('.')

    describe "Minimum TLS version for Storage Account '#{storage_account}' in Resource Group '#{resource_group}'" do
      script = <<-EOH
                $ErrorActionPreference = "Stop"
                Set-AzContext -Subscription #{subscription_id} | Out-Null
                (Get-AzStorageAccount -ResourceGroupName "#{resource_group}" -Name "#{storage_account}").MinimumTlsVersion
      EOH

      pwsh_output = powershell(script)
      raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

      describe pwsh_output do
        its('stdout.strip') { should cmp 'TLS1_2' }
      end
    end
  end
end
