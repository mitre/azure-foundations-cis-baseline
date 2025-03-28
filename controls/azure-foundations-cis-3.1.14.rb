control 'azure-foundations-cis-3.1.14' do
  title "Ensure That 'Notify about alerts with the following severity' is Set to 'High'"
  desc 'Enables emailing security alerts to the subscription owner or other designated security contact.'

  desc 'rationale',
       "Enabling security alert emails ensures that security alert emails are received from
        Microsoft. This ensures that the right people are aware of any potential security issues
        and are able to mitigate the risk."

  desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Click on Environment Settings
        4. Click on the appropriate Management Group, Subscription, or Workspace
        5. Click on Email notifications
        6. Ensure that the Notify about alerts with the following severity (or
        higher): setting is checked and set to High
        From Azure CLI
        Ensure the output of below command is set to true, enter your Subscription ID at the $0
        between /subscriptions/<$0>/providers.
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X GET -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se
        curityContacts?api-version=2020-01-01-preview' | jq '.|.[] |
        select(.name=='default')'|jq '.properties.alertNotifications'
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 6e2593d9-add6-4083-9c9b-4b7d2188c899 - Name: 'Email notification
        for high severity alerts should be enabled'"

  desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Click on Environment Settings
        4. Click on the appropriate Management Group, Subscription, or Workspace
        5. Click on Email notifications
        6. Under Notification types, check the check box next to Notify about alerts
        with the following severity (or higher): and select High from the drop
        down menu
        7. Click Save
        From Azure CLI
        Use the below command to set Send email notification for high severity alerts
        to On.
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X PUT -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/<$0>/providers/Microsoft.Security/
        securityContacts/default1?api-version=2017-08-01-preview -d@'input.json''
        Where input.json contains the data below, replacing validEmailAddress with a single
        email address or multiple comma-separated email addresses:
        {
        'id':
        '/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/securityC
        ontacts/default1',
        'name': 'default1',
        'type': 'Microsoft.Security/securityContacts',
        'properties': {
        'email': '<validEmailAddress>',
        'alertNotifications': 'On',
        'alertsToAdmins': 'On'
        }"

  impact 0.5
  tag nist: ['SI-4']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['13.11'] }]

  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-provide-security-contact-details'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/securitycontacts/list'
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
    $result = $response | Where-Object { $_.name -eq "default" } | ForEach-Object { $_.properties.alertNotifications } | ConvertTo-Json -Depth 10
    Write-Output $result
  EOH

  pwsh_output = powershell(script)
  result = pwsh_output.stdout.strip
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  alert_notifications = json(content: result).params

  describe 'Security Alert Notifications configuration' do
    it "should have state set to 'On'" do
      expect(alert_notifications['state']).to cmp 'On'
    end

    it "should have minimalSeverity set to 'High'" do
      expect(alert_notifications['minimalSeverity']).to cmp 'High'
    end
  end
end
