control 'azure-foundations-cis-2.1.16' do
    title "Ensure that Auto provisioning of 'Microsoft Defender for Containers components' is Set to 'On'"
    desc "Enable automatic provisioning of the Microsoft Defender for Containers components."

    desc 'rationale',
        "As with any compute resource, Container environments require hardening and run-time
        protection to ensure safe operations and detection of threats and vulnerabilities."
    
    desc 'impact',
        "Microsoft Defender for Containers will require additional licensing."

    desc 'check',
       "From Azure Portal
        1. From the Azure Portal Home page, select Microsoft Defender for Cloud
        2. Under Management select Environment Settings
        3. Select a subscription
        4. Ensure that Containers is set to On
        Repeat the above for any additional subscriptions.
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 1c988dd6-ade4-430f-a608-2a3e5b0a6d38 - Name: 'Microsoft
        Defender for Containers should be enabled"

    desc 'fix',
       "From Azure Portal
        1. From the Azure Portal Home page, select Microsoft Defender for Cloud
        2. Under Management, select Environment Settings
        3. Select a subscription
        4. Set Containers to On"

    impact 0.5
    tag nist: ['RA-5']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['7.5','7.6'] }]

    describe 'benchmark' do
        skip 'configure'
    end
end