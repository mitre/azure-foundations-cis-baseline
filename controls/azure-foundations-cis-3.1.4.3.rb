control 'azure-foundations-cis-3.1.4.3' do
    title "Ensure that 'Agentless container vulnerability assessment' component status is 'On'"
    desc "Enable automatic vulnerability management for images stored in ACR or running in AKS clusters."

    desc 'rationale',
        "Agentless vulnerability scanning will examine container images - whether running or in
        storage - for vulnerable configurations."
    
    desc 'impact',
        "Agentless container vulnerability assessment requires licensing and is included in:
        • Defender CSPM
        • Defender for Containers plans"

    desc 'check',
       "Audit from Azure Portal
        1. From the Azure Portal Home page, select Microsoft Defender for Cloud
        2. Under Management select Environment Settings
        3. Select a subscription
        4. Under Settings > Defender Plans, click Settings & monitoring
        5. Locate the row for Agentless container vulnerability assessment
        6. Ensure that On is selected
        Repeat the above for any additional subscriptions.
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 1c988dd6-ade4-430f-a608-2a3e5b0a6d38 - Name: 'Microsoft
        Defender for Containers should be enabled'"

    desc 'fix',
       "Audit from Azure Portal
        1. From the Azure Portal Home page, select Microsoft Defender for Cloud
        2. Under Management select Environment Settings
        3. Select a subscription
        4. Under Settings > Defender Plans, click Settings & monitoring
        5. Locate the row for Agentless container vulnerability assessment
        6. Select On
        7. Click Continue in the top left
        Repeat the above for any additional subscriptions"

    impact 0.5
    tag nist: ['RA-5']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['7.5','7.6'] }]

    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction'
    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/enable-data-collection?tabs=autoprovision-containers'
    ref 'https://msdn.microsoft.com/en-us/library/mt704062.aspx'
    ref 'https://msdn.microsoft.com/en-us/library/mt704063.aspx'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/autoprovisioningsettings/list'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/autoprovisioningsettings/create'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification'

    describe "Ensure that 'Agentless container vulnerability assessment' component status is 'On'" do
        skip 'The check for this control needs to be done manually'
    end
end