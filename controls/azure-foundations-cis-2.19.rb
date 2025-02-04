control 'azure-foundations-cis-2.19' do
    title "Ensure that 'Users can create security groups in Azure portals, API or PowerShell' is set to 'No'"
    desc "Restrict security group creation to administrators only."

    desc 'rationale',
        "When creating security groups is enabled, all users in the directory are allowed to
        create new security groups and add members to those groups. Unless a business
        requires this day-to-day delegation, security group creation should be restricted to
        administrators only."

    desc 'impact',
        "Enabling this setting could create a number of requests that would need to be managed
        by an administrator."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Groups
        4. Select General under Settings
        5. Ensure that Users can create security groups in Azure portals, API or
        PowerShell is set to No"

    desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Groups
        4. Under Settings, select General
        5. Under Security Groups, set Users can create security groups in Azure
        portals, API or PowerShell to No
        6. Click Save"

    impact 0.5
    tag nist: ['AC-2','AC-2(1)','AC-2','AC-5','AC-6','AC-6(1)','AC-6(7)','AU-9(4)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['6.8'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-accessmanagement-self-service-group-management#making-a-group-available-for-end-user-self-service'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
    ref 'https://learn.microsoft.cm/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'

    describe "Ensure that 'Restrict user ability to access groups features in the Access Pane' is Set to 'Yes'" do
        skip 'The check for this control needs to be done manually'
    end
end