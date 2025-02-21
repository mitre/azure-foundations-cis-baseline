control 'azure-foundations-cis-3.1.3.2' do
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
       "Audit from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Under Management, select Environment Settings
        4. Select a subscription
        5. Click on Settings & monitoring
        6. Ensure that Vulnerability assessment for machines is set to On
        Repeat the above for any additional subscriptions."

  desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Under Management, select Environment Settings
        4. Select a subscription
        5. Click on Settings & Monitoring
        6. Set the Status of Vulnerability assessment for machines to On
        7. Click Continue
        Repeat the above for any additional subscriptions."

  impact 0.5
  tag nist: ['RA-5']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['7.5', '7.6'] }]

  ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/enable-data-collection?tabs=autoprovision-va'
  ref 'https://msdn.microsoft.com/en-us/library/mt704062.aspx'
  ref 'https://msdn.microsoft.com/en-us/library/mt704063.aspx'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/autoprovisioningsettings/list'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/autoprovisioningsettings/create'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-vulnerability-management#pv-5-perform-vulnerability-assessments'

  describe "Ensure that Auto provisioning of 'Vulnerability assessment for machines' is Set to 'On'" do
    skip 'The check for this control needs to be done manually'
  end
end
