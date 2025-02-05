control 'azure-foundations-cis-4.6' do
    title "Ensure that 'Public Network Access' is `Disabled' for storage accounts"
    desc "Disallowing public network access for a storage account overrides the public access
        settings for individual containers in that storage account for Azure Resource Manager
        Deployment Model storage accounts. Azure Storage accounts that use the classic
        deployment model will be retired on August 31, 2024."

    desc 'rationale',
        "The default network configuration for a storage account permits a user with appropriate
        permissions to configure public network access to containers and blobs in a storage
        account. Keep in mind that public access to a container is always turned off by default
        and must be explicitly configured to permit anonymous requests. It grants read-only
        access to these resources without sharing the account key, and without requiring a
        shared access signature. It is recommended not to provide public network access to
        storage accounts until, and unless, it is strongly desired. A shared access signature
        token or Azure AD RBAC should be used for providing controlled and timed access to
        blob containers."

    desc 'impact',
        "Access will have to be managed using shared access signatures or via Azure AD RBAC."

    desc 'check',
       "From Azure Portal
        1. Go to Storage Accounts
        2. For each storage account, under the Security + networking section, click
        Networking
        3. Ensure the Public Network Access setting is set to Disabled.
        From Azure CLI
        Ensure publicNetworkAccess is Disabled
        az storage account show --name <storage-account> --resource-group <resource-
        group> --query '{publicNetworkAccess:publicNetworkAccess}'
        From PowerShell
        For each Storage Account, ensure PublicNetworkAccess is Disabled
        Get-AzStorageAccount -Name <storage account name> -ResourceGroupName
        <resource group name> |select PublicNetworkAccess
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: b2982f36-99f2-4db5-8eff-283140c09693 - Name: 'Storage accounts
        should disable public network access'"

    desc 'fix',
       "Remediate from Azure Portal
        First, follow Microsoft documentation and create shared access signature tokens for
        your blob containers. Then,
        1. Go to Storage Accounts.
        2. For each storage account, under the Security + networking section, click
        Networking.
        3. Set Public network access to Disabled.
        4. Click Save.
        Remediate from Azure CLI
        Set 'Public Network Access' to Disabled on the storage account
        az storage account update --name <storage-account> --resource-group
        <resource-group> --public-network-access Disabled
        Remediate from PowerShell
        For each Storage Account, run the following to set the PublicNetworkAccess setting to
        Disabled
        Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage
        account name> -PublicNetworkAccess Disabled"

    impact 0.5
    tag nist: ['AC-3','AC-5','AC-6','MP-2']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['3.3'] }]

    ref 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-manage-access-to-resources'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls'
    ref 'https://docs.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access'
    ref 'https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-portal'

    rg_sa_list = input('resource_groups_and_storage_accounts')

    rg_sa_list.each do |pair|
        resource_group, storage_account = pair.split('.')

        describe "Storage Account '#{storage_account}' in Resource Group '#{resource_group}'" do
            script = <<-EOH
                (Get-AzStorageAccount -ResourceGroupName "#{resource_group}" -Name "#{storage_account}").PublicNetworkAccess
            EOH

            describe powershell(script) do
                its('stdout.strip') { should cmp 'Disabled' }
            end
        end
    end
end