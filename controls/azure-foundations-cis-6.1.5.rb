control 'azure-foundations-cis-6.1.5' do
  title "Ensure that Network Security Group Flow logs are captured and sent to Log Analytics"
  desc "Ensure that network flow logs are captured and fed into a central log analytics workspace."

  desc 'rationale',
      "Network Flow Logs provide valuable insight into the flow of traffic around your network and feed into both Azure Monitor and Azure Sentinel (if in use), permitting the generation of visual flow diagrams to aid with analyzing for lateral movement, etc."

  desc 'impact'
    'The impact of configuring NSG Flow logs is primarily one of cost and configuration. If deployed, it will create storage accounts that hold minimal amounts of data on a 5-day lifecycle before feeding to Log Analytics Workspace. This will increase the amount of data stored and used by Azure Monitor.'

  desc 'check',
     "Audit from Azure Portal
        1. Navigate to Network Watcher.
        2. Under Logs, select Flow logs.
        3. Click Add filter.
        4. From the Filter drop-down, select Flow log type.
        5. From the Value drop-down, check Network security group only.
        6. Click Apply.
        7. Ensure that at least one network security group flow log is listed and is configured to send logs to a Log Analytics Workspace.
    Audit from Azure Policy 
      If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 27960feb-a23c-4577-8d36-ef8b5f35e0be - Name: 'All flow log resources should be in enabled state'
        • Policy ID: c251913d-7d24-4958-af87-478ed3b9ba41 - Name: 'Flow logs should be configured for every network security group'
        • Policy ID: 4c3c6c5f-0d47-4402-99b8-aa543dd8bcee - Name: 'Flow logs should be configured for every virtual network'"

  desc 'fix',
     'Remediate from Azure Portal
        1. Navigate to Network Watcher.
        2. Under Logs, select Flow logs.
        3. Select + Create.
        4. Select the desired Subscription.
        5. For Flow log type, select Network security group.
        6. Select + Select target resource.
        7. Select Network security group.
        8. Select a network security group.
        9. Click Confirm selection.
        10. Select or create a new Storage Account.
        11. If using a v2 storage account, input the retention in days to retain the log.
        12. Click Next.
        13. Under Analytics, for Flow log version, select Version 2.
        14. Check the box next to Enable traffic analytics.
        15. Select a processing interval.
        16. Select a Log Analytics Workspace.
        17. Select Next.
        18. Optionally add Tags.
        19. Select Review + create.
        20. Select Create.
      Warning The remediation policy creates remediation deployment and names them by concatenating the subscription name and the resource group name. The MAXIMUM permitted length of a deployment name is 64 characters. Exceeding this will cause the remediation task to fail.'

  impact 0.5
  tag nist: ['SI-4', 'SI-4(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['13.6'] }]

  ref 'https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-portal'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-4-enable-network-logging-for-security-investigation'

  describe 'benchmark' do
      skip 'The check for this control needs to be done manually'
  end
end