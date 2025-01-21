control 'azure-foundations-cis-4.8' do
    title "Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access"
    desc "Some Azure services that interact with storage accounts operate from networks that
        can't be granted access through network rules. To help this type of service work as
        intended, allow the set of trusted Azure services to bypass the network rules. These
        services will then use strong authentication to access the storage account. If the Allow
        trusted Azure services exception is enabled, the following services are granted access
        to the storage account: Azure Backup, Azure Site Recovery, Azure DevTest Labs,
        Azure Event Grid, Azure Event Hubs, Azure Networking, Azure Monitor, and Azure SQL
        Data Warehouse (when registered in the subscription)."

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
        "From Azure Portal
        1. Go to Storage Accounts
        2. For each storage account, Click on the Networking blade
        3. Click on the Firewalls and virtual networks heading.
        4. Ensure that Enabled from selected virtual networks and IP addresses is
        selected.
        5. Ensure that Allow Azure services on the trusted services list to access
        this storage account is checked in Exceptions.
        From Azure CLI
        Ensure bypass contains AzureServices
        az storage account list --query '[*].networkRuleSet'
        From PowerShell
        Connect-AzAccount
        Set-AzContext -Subscription <subscription ID>
        Get-AzStorageAccountNetworkRuleset -ResourceGroupName <resource group> -Name
        <storage account name> |Select-Object Bypass
        If the resultant output from the above command shows 'NULL', that storage account
        configuration is out of compliance with this check. If the result of the above command
        shows 'AzureServices', that storage account configuration is in compliance with this
        check.
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: c9d007d0-c057-4772-b18c-01e546713bcd - Name: 'Storage accounts
        should allow access from trusted Microsoft services'"

    desc 'fix',
       "From Azure Portal
        1. Go to Storage Accounts
        2. For each storage account, Click on the Networking blade
        3. Click on the Firewalls and virtual networks heading.
        4. Ensure that Enabled from selected virtual networks and IP addresses is
        selected.
        5. Under the 'Exceptions' label, enable check box for Allow Azure services on the
        trusted services list to access this storage account.
        6. Click Save to apply your changes.
        From Azure CLI
        Use the below command to update Azure services.
        az storage account update --name <StorageAccountName> --resource-group
        <resourceGroupName> --bypass AzureServices"

    impact 0.5
    tag nist: ['AC-3','AC-5','AC-6','MP-2','AC-17','AC-17(1)','SI-4']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['3.3','13.5'] }]

    ref 'https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls'

    describe 'benchmark' do
        skip 'configure'
    end
end