control 'azure-foundations-cis-3.1.3.5' do
  title "Ensure that 'File Integrity Monitoring' component status is set to 'On'"
  desc "File Integrity Monitoring (FIM) is a feature that monitors critical system files in Windows
        or Linux for potential signs of attack or compromise."

  desc 'rationale',
       "FIM provides a detection mechanism for compromised files. When FIM is enabled,
        critical system files are monitored for changes that might indicate a threat actor is
        attempting to modify system files for lateral compromise within a host operating system."

  desc 'impact',
       "File Integrity Monitoring requires licensing and is included in these plans:
        • Defender for Servers plan 2"

  desc 'check',
       "Audit from Azure Portal
        1. From the Azure Portal Home page, select Microsoft Defender for Cloud
        2. Under Management select Environment Settings
        3. Select a subscription
        4. Under Settings > Defender Plans, click Settings & monitoring
        5. Under the Component column, locate the row for File Integrity Monitoring
        6. Ensure that On is selected
        Repeat the above for any additional subscriptions."

  desc 'fix',
       "Audit from Azure Portal
        1. From the Azure Portal Home page, select Microsoft Defender for Cloud
        2. Under Management select Environment Settings
        3. Select a subscription
        4. Under Settings > Defender Plans, click Settings & monitoring
        5. Under the Component column, locate the row for File Integrity Monitoring
        6. Select On
        7. Click Continue in the top left
        Repeat the above for any additional subscriptions"

  impact 0.5
  tag nist: ['RA-5']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['7.5', '7.6'] }]

  ref 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-overview'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification'
  ref 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-enable-defender-endpoint'

  describe "Ensure that 'File Integrity Monitoring' component status is set to 'On'" do
    skip 'The check for this control needs to be done manually'
  end
end
