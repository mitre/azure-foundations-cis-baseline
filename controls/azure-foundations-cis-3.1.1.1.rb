control 'azure-foundations-cis-3.1.1.1' do
  title "Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'"
  desc "Enable automatic provisioning of the monitoring agent to collect security data.
		DEPRECATION PLANNED: The Log Analytics Agent is slated for deprecation in
		August 2024. The Microsoft Defender for Endpoint agent, in tandem with new agentless
		capabilities will be providing replacement functionality. More detail is available here:
		https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/microsoft-
		defender-for-cloud-strategy-and-plan-towards-log/ba-p/3883341."

  desc 'rationale',
       "When Log Analytics agent for Azure VMs is turned on, Microsoft Defender for Cloud
		provisions the Microsoft Monitoring Agent on all existing supported Azure virtual
		machines and any new ones that are created. The Microsoft Monitoring Agent scans for
		various security-related configurations and events such as system updates, OS
		vulnerabilities, endpoint protection, and provides alerts."

  desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Then Environment Settings
        4. Select a subscription
        5. Click on Settings & Monitoring
        6. Ensure that Log Analytics agent/Azure Monitor agent is set to On
        Repeat the above for any additional subscriptions.
        From Azure CLI
        Ensure the output of the below command is On
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X GET -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/<subscriptionID>/providers/Microso
        ft.Security/autoProvisioningSettings?api-version=2017-08-01-preview' | jq
        '.|.value[] | select(.name=='default')'|jq '.properties.autoProvision'
        Using PowerShell
        Connect-AzAccount
        Get-AzSecurityAutoProvisioningSetting | Select-Object Name, AutoProvision
        Ensure output for Id Name AutoProvision is
        /subscriptions//providers/Microsoft.Security/autoProvisioningSettings/default
        default
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 475aae12-b88a-4572-8b36-9b712b2b3a17 - Name: 'Auto
        provisioning of the Log Analytics agent should be enabled on your subscription'"

  desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Under Management, select Environment Settings
        4. Select a subscription
        5. Click on Settings & monitoring
        6. Set the Status of Log Analytics agent to On
        7. Select a Workspace
        8. Click Apply
        9. Click Continue
        Repeat the above for any additional subscriptions.
        Remediate from Azure CLI
        Use the below command to set Automatic provisioning of monitoring agent to
        On.
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X PUT -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/subscriptionID/providers/Microsoft
        .Security/autoProvisioningSettings/default?api-version=2017-08-01-preview -
        d@'input.json''
        Where input.json contains the Request body json data as mentioned below.
        {
        'id':
        '/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/autoProvi
        sioningSettings/default',
        'name': 'default',
        'type': 'Microsoft.Security/autoProvisioningSettings',
        'properties': {
        'autoProvision': 'On'
        }
        }"

  impact 0.5
  tag nist: ['RA-5']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['7.5', '7.6'] }]

  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-data-security'
  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-data-collection'
  ref 'https://msdn.microsoft.com/en-us/library/mt704062.aspx'
  ref 'https://msdn.microsoft.com/en-us/library/mt704063.aspx'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/autoprovisioningsettings/list'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/autoprovisioningsettings/create'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-5-centralize-security-log-management-and-analysis'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification'

  script = <<-EOH
		(Get-AzSecurityAutoProvisioningSetting -Name 'default').AutoProvision
  EOH

  pwsh_output = powershell(script)

  describe "Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs'" do
    subject { pwsh_output.stdout.strip }
    it "is set to 'On'" do
      expect(subject).to eq('On')
    end
  end
end
