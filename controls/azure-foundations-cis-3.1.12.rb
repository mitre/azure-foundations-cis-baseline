control 'azure-foundations-cis-3.1.12' do
    title "Ensure That 'All users with the following roles' is set to 'Owner'"
    desc "Enable security alert emails to subscription owners."

    desc 'rationale',
        "Enabling security alert emails to subscription owners ensures that they receive security
        alert emails from Microsoft. This ensures that they are aware of any potential security
        issues and can mitigate the risk in a timely fashion."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Then Environment Settings
        4. Click on the appropriate Management Group, Subscription, or Workspace
        5. Click on Email notifications
        6. Ensure that All users with the following roles is set to Owner
        From Azure CLI
        Ensure the command below returns state of On and that Owner appears in roles.
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X GET -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se
        curityContacts?api-version=2020-01-01-preview'| jq '.[] |
        select(.name=='default').properties.notificationsByRole'"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Click on Environment Settings
        4. Click on the appropriate Management Group, Subscription, or Workspace
        5. Click on Email notifications
        6. In the drop down of the All users with the following roles field select Owner
        7. Click Save
        From Azure CLI
        Use the below command to set Send email also to subscription owners to On.
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X PUT -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se
        curityContacts/default1?api-version=2017-08-01-preview -d@'input.json''
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
        'alertsToAdmins': 'On',
        'notificationsByRole': 'Owner'
        }
        }"

    impact 0.5
    tag nist: ['IR-6','IR-6(3)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['17.2'] }]

    ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-provide-security-contact-details'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/securitycontacts/list'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/security-contacts'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end