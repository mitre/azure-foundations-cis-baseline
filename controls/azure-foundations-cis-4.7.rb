control 'azure-foundations-cis-4.7' do
    title "Ensure Default Network Access Rule for Storage Accounts is Set to Deny"
    desc "Restricting default network access helps to provide a new layer of security, since
        storage accounts accept connections from clients on any network. To limit access to
        selected networks, the default action must be changed."

    desc 'rationale',
        "Storage accounts should be configured to deny access to traffic from all networks
        (including internet traffic). Access can be granted to traffic from specific Azure Virtual
        networks, allowing a secure network boundary for specific applications to be built.
        Access can also be granted to public internet IP address ranges to enable connections
        from specific internet or on-premises clients. When network rules are configured, only
        applications from allowed networks can access a storage account. When calling from an
        allowed network, applications continue to require proper authorization (a valid access
        key or SAS token) to access the storage account."

    desc 'impact',
        "All allowed networks will need to be whitelisted on each specific network, creating
        administrative overhead. This may result in loss of network connectivity, so do not turn
        on for critical resources during business hours."

    desc 'check',
       "From Azure Console
        1. Go to Storage Accounts
        2. For each storage account, Click on the Networking blade.
        3. Click the Firewalls and virtual networks heading.
        4. Ensure that Allow access from All networks is not selected.
        From Azure CLI
        Ensure defaultAction is not set to Allow.
        az storage account list --query '[*].networkRuleSet'
        From PowerShell
        Connect-AzAccount
        Set-AzContext -Subscription <subscription ID>
        Get-AzStorageAccountNetworkRuleset -ResourceGroupName <resource group> -Name
        <storage account name> |Select-Object DefaultAction
        PowerShell Result - Non-Compliant
        DefaultAction : Allow
        PowerShell Result - Compliant
        DefaultAction : Deny
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 34c877ad-507e-4c82-993e-3452a6e0ad3c - Name: 'Storage accounts
        should restrict network access'
        • Policy ID: 2a1a9cdf-e04d-429a-8416-3bfb72a1b26f - Name: 'Storage accounts
        should restrict network access using virtual network rules'"

    desc 'fix',
       "From Azure Console
        1. Go to Storage Accounts
        2. For each storage account, Click on the Networking blade
        3. Click the Firewalls and virtual networks heading.
        4. Ensure that you have elected to allow access from Selected networks
        5. Add rules to allow traffic from specific network.
        6. Click Save to apply your changes.
        From Azure CLI
        Use the below command to update default-action to Deny.
        az storage account update --name <StorageAccountName> --resource-group
        <resourceGroupName> --default-action Deny"

    impact 0.5
    tag nist: ['PL-8','PM-7','SA-8','CM-7','CP-6','CP-7','SC-7']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['12.2'] }]

    ref 'https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end