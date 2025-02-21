control 'azure-foundations-cis-3.1.3.4' do
  title "Ensure that 'Agentless scanning for machines' component status is set to 'On'"
  desc "Using disk snapshots, the agentless scanner scans for installed software,
        vulnerabilities, and plain text secrets."

  desc 'rationale',
       "The Microsoft Defender for Cloud agentless machine scanner provides threat detection,
        vulnerability detection, and discovery of sensitive information."

  desc 'impact',
       "Agentless scanning for machines requires licensing and is included in these plans:
        • Defender CSPM
        • Defender for Servers plan 2"

  desc 'check',
       "Audit from Azure Portal
        1. From the Azure Portal Home page, select Microsoft Defender for Cloud
        2. Under Management select Environment Settings
        3. Select a subscription
        4. Under Settings > Defender Plans, click Settings & monitoring
        5. Under the Component column, locate the row for Agentless scanning for
        machines
        6. Ensure that On is selected
        Repeat the above for any additional subscriptions."

  desc 'fix',
       "Audit from Azure Portal
        1. From the Azure Portal Home page, select Microsoft Defender for Cloud
        2. Under Management select Environment Settings
        3. Select a subscription
        4. Under Settings > Defender Plans, click Settings & monitoring
        5. Under the Component column, locate the row for Agentless scanning for
        machines
        6. Select On
        7. Click Continue in the top left
        Repeat the above for any additional subscriptions."

  impact 0.5
  tag nist: ['RA-5']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['7.5', '7.6'] }]

  ref 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-data-collection'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification'
  ref 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-agentless-scanning-vms'

  describe "Ensure that 'Agentless scanning for machines' component status is set to 'On'" do
    skip 'The check for this control needs to be done manually'
  end
end
