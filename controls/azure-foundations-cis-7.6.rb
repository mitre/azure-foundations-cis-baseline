control 'azure-foundations-cis-7.6' do
  title "Ensure that Network Watcher is 'Enabled' for Azure Regions that are in use"
  desc 'Enable Network Watcher for physical regions in Azure subscriptions.'

  desc 'rationale',
       'Network diagnostic and visualization tools available with Network Watcher help users understand, diagnose, and gain insights to the network in Azure.'

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

  nsg_script = 'az network nsg list'
  nsg_output = powershell(nsg_script).stdout.strip
  all_nsgs = json(content: nsg_output).params

  only_if('N/A - No Network Security Groups found', impact: 0) do
    case all_nsgs
    when Array
      !all_nsgs.empty?
    when Hash
      !all_nsgs.empty?
    else
      false
    end
  end

  ensure_provision_state_succeeds_script = %(
    $networkWatchersNotSucceeded = Get-AzNetworkWatcher | Where-Object { $_.ProvisioningState -ne 'Succeeded' }

    if ($networkWatchersNotSucceeded) {
        $names = $networkWatchersNotSucceeded | Select-Object -ExpandProperty Name -Unique
        $output = $names -join ', '
        Write-Output $output
    }
  )
  pwsh_output_provision_state = powershell(ensure_provision_state_succeeds_script)
  describe 'Ensure the number of network watchers with ProvisioningState not set to Succeeded' do
    subject { pwsh_output_provision_state.stdout.strip }
    it 'is 0' do
      failure_message = "The following network watchers do not have ProvisioningState set to Succeeded: #{pwsh_output_provision_state.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end

  ensure_locations_using_watcher_script = %(
    $locationsInUse = Get-AzResource | Select-Object -ExpandProperty Location | Sort-Object -Unique
    $networkWatcherLocations = Get-AzNetworkWatcher | Select-Object -ExpandProperty Location | Sort-Object -Unique
    $difference = Compare-Object -ReferenceObject $locationsInUse -DifferenceObject $networkWatcherLocations -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
    if ($difference.Count -eq 0) { $null } else { $difference -join ', ' }

  )
  pwsh_output_location_watcher = powershell(ensure_locations_using_watcher_script)
  describe 'Ensure the number of locations without a Network Watcher' do
    subject { pwsh_output_location_watcher.stdout.strip }
    it 'is 0' do
      failure_message = "The following locations do not have Network Watchers: #{pwsh_output_location_watcher.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
