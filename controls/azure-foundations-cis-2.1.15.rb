control 'azure-foundations-cis-2.1.15' do
    title "Ensure that Auto provisioning of 'Vulnerability assessment for machines' is Set to 'On'"
    desc "Enable automatic provisioning of vulnerability assessment for machines on both Azure
        and hybrid (Arc enabled) machines."

    desc 'rationale',
        "Vulnerability assessment for machines scans for various security-related configurations
        and events such as system updates, OS vulnerabilities, and endpoint protection, then
        produces alerts on threat and vulnerability findings."

    desc 'impact',
        "Additional licensing is required and configuration of Azure Arc introduces complexity
        beyond this recommendation"

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Then Environment Settings
        4. Select a subscription
        5. Click on Settings & Monitoring
        6. Ensure that Vulnerability assessment for machines is set to On
        Repeat the above for any additional subscriptions."

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Then Environment Settings
        4. Select a subscription
        5. Click on Settings & Monitoring
        6. Ensure that Vulnerability assessment for machines is set to On
        Repeat the above for any additional subscriptions."

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/enable-data-collection?tabs=autoprovision-va'
    ref 'https://msdn.microsoft.com/en-us/library/mt704062.aspx'
    ref 'https://msdn.microsoft.com/en-us/library/mt704063.aspx'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/autoprovisioningsettings/list'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/autoprovisioningsettings/create'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-vulnerability-management#pv-5-perform-vulnerability-assessments'

    describe 'benchmark' do
        skip 'configure'
    end
end