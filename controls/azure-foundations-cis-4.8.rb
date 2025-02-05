control 'azure-foundations-cis-4.8' do
    title "Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access"
    desc "NOTE: This recommendation assumes that the Public network access parameter is
        set to Enabled from selected virtual networks and IP addresses. Please
        ensure the prerequisite recommendation has been implemented before proceeding:
        • Ensure Default Network Access Rule for Storage Accounts is Set to Deny
        Some Azure services that interact with storage accounts operate from networks that
        can't be granted access through network rules. To help this type of service work as
        intended, allow the set of trusted Azure services to bypass the network rules. These
        services will then use strong authentication to access the storage account. If the Allow
        Azure services on the trusted services list to access this storage
        account exception is enabled, the following services are granted access to the storage
        account: Azure Backup, Azure Data Box, Azure DevTest Labs, Azure Event Grid, Azure
        Event Hubs, Azure File Sync, Azure HDInsight, Azure Import/Export, Azure Monitor,
        Azure Networking Services, and Azure Site Recovery (when registered in the
        subscription)."

    desc 'rationale',
        "Turning on firewall rules for storage account will block access to incoming requests for
        data, including from other Azure services. We can re-enable this functionality by
        enabling 'Trusted Azure Services' through networking exceptions."

    desc 'impact',
       "This creates authentication credentials for services that need access to storage
        resources so that services will no longer need to communicate via network request.
        There may be a temporary loss of communication as you set each Storage Account. It
        is recommended to not do this on mission-critical resources during business hours."

    desc 'check',
        "Audit from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Security + networking, click Networking.
        3. Click on the Firewalls and virtual networks heading.
        4. Under Exceptions, ensure that Allow Azure services on the trusted
        services list to access this storage account is checked.
        Audit from Azure CLI
        Ensure bypass contains AzureServices
        az storage account list --query '[*].networkRuleSet'
        Audit from PowerShell
        Connect-AzAccount
        Set-AzContext -Subscription <subscription ID>
        Get-AzStorageAccountNetworkRuleset -ResourceGroupName <resource group> -Name
        <storage account name> |Select-Object Bypass
        If the response from the above command is None, the storage account configuration is
        out of compliance with this check. If the response is AzureServices, the storage
        account configuration is in compliance with this check.
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: c9d007d0-c057-4772-b18c-01e546713bcd - Name: 'Storage accounts
        should allow access from trusted Microsoft services"

    desc 'fix',
       "Remediate from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Security + networking, click Networking.
        3. Click on the Firewalls and virtual networks heading.
        4. Under Exceptions, check the box next to Allow Azure services on the
        trusted services list to access this storage account.
        5. Click Save.
        Remediate from Azure CLI
        Use the below command to update bypass to Azure services.
        az storage account update --name <StorageAccountName> --resource-group
        <resourceGroupName> --bypass AzureServices"

    impact 0.5
    tag nist: ['AC-3','AC-5','AC-6','MP-2','AC-17','AC-17(1)','SI-4']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['3.3','13.5'] }]

    ref 'https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls'

    subscription_id = input('subscription_id')
    rg_sa_list = input('resource_groups_and_storage_accounts')

    rg_sa_list.each do |pair|
        resource_group, storage_account = pair.split('.')

        describe "Storage Account Network Ruleset Bypass for '#{storage_account}' in Resource Group '#{resource_group}'" do
            script = <<-EOH
                Set-AzContext -Subscription #{subscription_id} | Out-Null
                (Get-AzStorageAccountNetworkRuleset -ResourceGroupName "#{resource_group}" -Name "#{storage_account}").Bypass
            EOH

            describe powershell(script) do
                its('stdout.strip') { should cmp 'AzureServices' }
            end
        end
    end
end