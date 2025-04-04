control 'azure-foundations-cis-2.18' do
  title "Ensure that 'Restrict user ability to access groups features in the Access Pane' is Set to 'Yes'"
  desc 'Restrict access to group web interface in the Access Panel portal.'

  desc 'rationale',
       "Self-service group management enables users to create and manage security groups or
        Office 365 groups in Microsoft Entra ID. Unless a business requires this day-to-day
        delegation for some users, self-service group management should be disabled. Any
        user can access the Access Panel, where they can reset their passwords, view their
        information, etc. By default, users are also allowed to access the Group feature, which
        shows groups, members, related resources (SharePoint URL, Group email address,
        Yammer URL, and Teams URL). By setting this feature to 'Yes', users will no longer
        have access to the web interface, but still have access to the data using the API. This is
        useful to prevent non-technical users from enumerating groups-related information, but
        technical users will still be able to access this information using APIs"

  desc 'impact',
       "Setting to Yes could create administrative overhead by customers seeking certain group
        memberships that will have to be manually managed by administrators with appropriate
        permissions."

  desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Groups
        4. Select General under Settings
        5. Ensure that Restrict user ability to access groups features in My Groups
        is set to Yes"

  desc 'fix',
       "FRemediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Groups
        4. Under Settings, select General
        5. Under Self Service Group Management, set Restrict user ability to
        access groups features in My Groups to Yes
        6. Click Save"

  impact 0.5
  tag nist: ['AC-2', 'AC-2(1)', 'AC-2', 'AC-5', 'AC-6', 'AC-6(1)', 'AC-6(7)', 'AU-9(4)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['6.8'] }]

  ref 'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-accessmanagement-self-service-group-management'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'

  describe "Ensure that 'Restrict user ability to access groups features in the Access Pane' is Set to 'Yes'" do
    skip 'The check for this control needs to be done manually'
  end
end
