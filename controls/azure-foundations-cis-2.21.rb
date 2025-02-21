control 'azure-foundations-cis-2.21' do
  title "Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'"
  desc 'Restrict Microsoft 365 group creation to administrators only.'

  desc 'rationale',
       "Restricting Microsoft 365 group creation to administrators only ensures that creation of
        Microsoft 365 groups is controlled by the administrator. Appropriate groups should be
        created and managed by the administrator and group creation rights should not be
        delegated to any other user."

  desc 'impact',
       'Enabling this setting could create a number of requests that would need to be managed by an administrator.'

  desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then Groups
        4. Select General in setting
        5. Ensure that Users can create Microsoft 365 groups in Azure portals, API
        or PowerShell is set to No"

  desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Groups
        4. Under Settings, select General
        5. Under Microsoft 365 Groups, set Users can create Microsoft 365
        groups in Azure portals, API or PowerShell to No
        6. Click Save"

  impact 0.5
  tag nist: ['AC-2', 'AC-2(1)', 'AC-2', 'AC-5', 'AC-6', 'AC-6(1)', 'AC-6(7)', 'AU-9(4)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['6.8'] }]

  ref 'https://whitepages.unlimitedviz.com/2017/01/disable-office-365-groups-2/'
  ref 'https://support.office.com/en-us/article/Control-who-can-create-Office-365-Groups-4c46c8cb-17d0-44b5-9776-005fced8e618'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'

  describe "Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'" do
    skip 'The check for this control needs to be done manually'
  end
end
