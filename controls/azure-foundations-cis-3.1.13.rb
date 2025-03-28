control 'azure-foundations-cis-3.1.13' do
  title "Ensure 'Additional email addresses' is Configured with a Security Contact Email"
  desc "Microsoft Defender for Cloud emails the subscription owners whenever a high-severity
            alert is triggered for their subscription. You should provide a security contact email
            address as an additional email address."

  desc 'rationale',
       "Microsoft Defender for Cloud emails the Subscription Owner to notify them about
        security alerts. Adding your Security Contact's email address to the 'Additional email
        addresses' field ensures that your organization's Security Team is included in these
        alerts. This ensures that the proper people are aware of any potential compromise in
        order to mitigate the risk in a timely fashion."

  desc 'check',
       "Audit from Azure Portal
        1. From Azure Home select the Portal Menu.
        2. Select Microsoft Defender for Cloud.
        3. Under Management, select Environment Settings.
        4. Click on the appropriate Management Group, Subscription, or Workspace.
        5. Click on Email notifications.
        6. Ensure that a valid security contact email address is listed in the Additional
        email addresses field.
        Audit from Azure CLI
        Ensure the output of the below command is not empty and is set with appropriate email
        ids:
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X GET -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se
        curityContacts?api-version=2020-01-01-preview' | jq '.|.[] |
        select(.name=='default')'|jq '.properties.emails'
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 4f4f78b8-e367-4b10-a341-d9a4ad5cf1c7 - Name: 'Subscriptions
        should have a contact email address for security issues'"

  desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Click on Environment Settings
        4. Click on the appropriate Management Group, Subscription, or Workspace
        5. Click on Email notifications
        6. Enter a valid security contact email address (or multiple addresses separated by
        commas) in the Additional email addresses field
        7. Click Save
        From Azure CLI
        Use the below command to set Security contact emails to On.
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X PUT -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se
        curityContacts/default?api-version=2020-01-01-preview -d@'input.json''
        Where input.json contains the data below, replacing validEmailAddress with a single
        email address or multiple comma-separated email addresses:
        {
        'id':
        '/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/securityC
        ontacts/default',
        'name': 'default',
        'type': 'Microsoft.Security/securityContacts',
        'properties': {
        'email': '<validEmailAddress>',
        'alertNotifications': 'On',
        'alertsToAdmins': 'On'
        }
        }"

  impact 0.5
  tag nist: ['IR-6', 'IR-6(3)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['17.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-provide-security-contact-details'
  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-provide-security-contact-details'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/security-contacts'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification'

  subscription_id = input('subscription_id')

  script = <<-EOH
    $ErrorActionPreference = "Stop"
    $tokenInfo = az account get-access-token --query "{accessToken:accessToken}" --out tsv
    $accessToken = $tokenInfo.Trim()
    $subscription = "#{subscription_id}"
    $url = "https://management.azure.com/subscriptions/$subscription/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview"
    $response = Invoke-RestMethod -Method Get -Uri $url -Headers @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }
    # Select the default security contact and extract its 'emails' property
    $result = $response | Where-Object { $_.name -eq "default" } | ForEach-Object { $_.properties.emails } | ConvertTo-Json -Depth 10
    Write-Output $result
  EOH

  pwsh_output = powershell(script)
  result = pwsh_output.stdout.strip
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  emails = json(content: result).params

  describe 'Security Contacts Emails configuration' do
    it 'should not be empty' do
      expect(emails).not_to be_nil
      expect(emails.to_s.strip).not_to eq('')
    end
  end
end
