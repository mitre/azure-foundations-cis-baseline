control 'azure-foundations-cis-7.5' do
    title "Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'"
    desc "Network Security Group Flow Logs should be enabled and the retention period set to greater than or equal to 90 days."

    desc 'rationale',
        "Flow logs enable capturing information about IP traffic flowing in and out of network security groups. Logs can be used to check for anomalies and give insight into suspected breaches."

    desc 'impact',
        'This will keep IP traffic logs for longer than 90 days. As a level 2, first determine your need to retain data, then apply your selection here. As this is data stored for longer, your monthly storage costs will increase depending on your data use.'

    desc 'check',
       "Audit from Azure Portal
            1. Go to Network Watcher
            2. Select NSG flow logs blade in the Logs section
            3. Select each Network Security Group from the list
            4. Ensure Status is set to On
            5. Ensure Retention (days) setting greater than 90 days
        Audit from Azure CLI 
            az network watcher flow-log show --resource-group <resourceGroup> --nsg <NameorID of the NetworkSecurityGroup> --query 'retentionPolicy'
            Ensure that enabled is set to true and days is set to greater then or equal to 90.
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 5e1cd26a-5090-4fdb-9d6a-84a90335e22d - Name: 'Configure network security groups to use specific workspace, storage account and flowlog retention policy for traffic analytics'"

    desc 'fix',
       "Remediate from Azure Portal
            1. Go to Network Watcher
            2. Select NSG flow logs blade in the Logs section
            3. Select each Network Security Group from the list
            4. Ensure Status is set to On
            5. Ensure Retention (days) setting greater than 90 days
            6. Select your storage account in the Storage account field
            7. Select Save 
        Remediate from Azure CLI 
            Enable the NSG flow logs and set the Retention (days) to greater than or equal to 90 days. 
                az network watcher flow-log configure --nsg <NameorID of the Network Security Group> --enabled true --resource-group <resourceGroupName> --retention 91 --storage-account <NameorID of the storage account to save flow logs>"

    impact 0.5
    tag nist: ['AU-4', 'AU-11']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['8.3', '8.10'] }]

    ref 'https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview'
    ref 'https://docs.microsoft.com/en-us/cli/azure/network/watcher/flow-log?view=azure-cli-latest'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-6-configure-log-storage-retention'

    describe 'benchmark' do
        skip 'configure'
    end
end