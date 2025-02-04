control 'azure-foundations-cis-7.6' do
    title "Ensure that Network Watcher is 'Enabled' for Azure Regions that are in use"
    desc "Enable Network Watcher for physical regions in Azure subscriptions."

    desc 'rationale',
        "Network diagnostic and visualization tools available with Network Watcher help users understand, diagnose, and gain insights to the network in Azure."

    desc 'impact',
        'There are additional costs per transaction to run and store network data. For high-volume networks these charges will add up quickly.'

    desc 'check',
       %(Audit from Azure Portal
            1. Go to Network Watcher
            2. Ensure that a network watcher is listed for each region.
        Audit from Azure CLI 
            az network watcher list --query "[].{Location:location,State:provisioningState}" -o table
                This will list all network watchers and their provisioning state. Ensure provisioningState is Succeeded for each network watcher. 
            az account list-locations --query "[?metadata.regionType=='Physical'].{Name:name,DisplayName:regionalDisplayName}" -o table
                This will list all physical regions that exist in the subscription. Compare this list to the previous one to ensure that for each region, a network watcher exists with provisioningState set to Succeeded. 
        Audit From Powershell 
            Get a list of Network Watchers 
                Get-AzNetworkWatcher
            Make sure each watcher is set with the ProvisioningState setting set to Succeeded and all Locations are set with a watcher.
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: b6e2945c-0b7b-40f5-9233-7a5323b5cdc6 - Name: 'Network Watcher should be enabled')

    desc 'fix',
       "Opting out of Network Watcher automatic enablement is a permanent change. Once you opt-out you cannot opt-in without contacting support. To manually enable Network Watcher in each region where you want to use Network Watcher capabilities, follow the steps below.
        Remediate from Azure Portal
            1. Go to Network Watcher.
            2. Click Create.
            3. Select a Region from the drop-down menu.
            4. Click Add.
        Remediate from Azure CLI 
            az network watcher configure --locations <region> --enabled true --resource-group <resource_group>"

    impact 0.5
    tag nist: ['PL-8', 'PM-7', 'SA-8', 'CM-7', 'CP-6', 'CP-7', 'SC-7', 'PM-5']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['12.2', '12.4'] }]

    ref 'https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview'
    ref 'https://learn.microsoft.com/en-us/cli/azure/network/watcher?view=azure-cli-latest'
    ref 'https://docs.azure.cn/zh-cn/cli/network/watcher?view=azure-cli-latest#az_network_watcher_configure'
    ref 'https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-create'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-4-enable-network-logging-for-security-investigation'
    ref 'https://azure.microsoft.com/en-ca/pricing/details/network-watcher/'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end